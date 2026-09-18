use std::{
    collections::BTreeSet,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_client_kernel::authorization_contract_ref;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    harness::v1::{ApprovalRequestLifecycleKind, ApprovalRequestObservation, harness_observation},
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        HarnessApprovalRequestBinding, IssueHarnessApprovalDecisionCommand, PolicyAuthorityProof,
    },
};
use egopulse_harness_adapter::{AdapterEdge, AdapterEdgeError, RetainedApprovalAuthorization};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyReferenceRejection, PolicyReferenceResolver,
    ResolvedApprovalAuthorization,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The reviewed local-user policy used by the first single-Harness vertical.
/// Approval routing is resolved from the Adapter's durable request projection;
/// the client never supplies adapter, fencing, routing, or observation facts.
pub struct LocalUserPolicyResolver {
    adapters: Vec<LocalUserPolicyAdapterEdge>,
    authorization_policy_ref: ContractReference,
    authentication_context_ref: String,
    allowed_scope_refs: BTreeSet<String>,
    decision_ttl: Duration,
}

impl LocalUserPolicyResolver {
    pub fn new(
        config: LocalUserPolicyResolverConfig,
    ) -> Result<Self, LocalUserPolicyConfigurationError> {
        Self::new_multi(LocalUserPolicyResolverMultiConfig {
            adapters: vec![LocalUserPolicyAdapterConfig {
                edge: config.edge,
                adapter_id: config.adapter_id,
            }],
            authorization_policy_ref: config.authorization_policy_ref,
            authentication_context_ref: config.authentication_context_ref,
            allowed_scope_refs: config.allowed_scope_refs,
            decision_ttl: config.decision_ttl,
        })
    }

    /// Builds one policy resolver over independently owned provider Adapter
    /// stores. Approval request ids must resolve to exactly one provider; a
    /// cross-provider collision is treated as an integrity failure rather
    /// than being resolved by registration order.
    pub fn new_multi(
        config: LocalUserPolicyResolverMultiConfig,
    ) -> Result<Self, LocalUserPolicyConfigurationError> {
        if config.adapters.is_empty()
            || config.authentication_context_ref.trim().is_empty()
            || config.allowed_scope_refs.is_empty()
            || config.decision_ttl.is_zero()
            || config.decision_ttl > Duration::from_secs(24 * 60 * 60)
            || config.authorization_policy_ref != authorization_contract_ref()
        {
            return Err(LocalUserPolicyConfigurationError::InvalidConfiguration);
        }
        if config.adapters.iter().any(|adapter| {
            adapter.adapter_id.trim().is_empty() || adapter.edge.adapter_id() != adapter.adapter_id
        }) {
            return Err(LocalUserPolicyConfigurationError::InvalidConfiguration);
        }
        if config
            .allowed_scope_refs
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(LocalUserPolicyConfigurationError::InvalidConfiguration);
        }
        Ok(Self {
            adapters: config
                .adapters
                .into_iter()
                .map(|adapter| LocalUserPolicyAdapterEdge {
                    edge: Mutex::new(adapter.edge),
                    adapter_id: adapter.adapter_id,
                })
                .collect(),
            authorization_policy_ref: config.authorization_policy_ref,
            authentication_context_ref: config.authentication_context_ref,
            allowed_scope_refs: config.allowed_scope_refs,
            decision_ttl: config.decision_ttl,
        })
    }
}

pub struct LocalUserPolicyResolverConfig {
    pub edge: AdapterEdge,
    pub adapter_id: String,
    pub authorization_policy_ref: ContractReference,
    pub authentication_context_ref: String,
    pub allowed_scope_refs: BTreeSet<String>,
    pub decision_ttl: Duration,
}

pub struct LocalUserPolicyAdapterConfig {
    pub edge: AdapterEdge,
    pub adapter_id: String,
}

pub struct LocalUserPolicyResolverMultiConfig {
    pub adapters: Vec<LocalUserPolicyAdapterConfig>,
    pub authorization_policy_ref: ContractReference,
    pub authentication_context_ref: String,
    pub allowed_scope_refs: BTreeSet<String>,
    pub decision_ttl: Duration,
}

struct LocalUserPolicyAdapterEdge {
    edge: Mutex<AdapterEdge>,
    adapter_id: String,
}

impl PolicyReferenceResolver for LocalUserPolicyResolver {
    fn resolve_issue(
        &self,
        command: &IssueHarnessApprovalDecisionCommand,
        principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<ResolvedApprovalAuthorization, PolicyReferenceRejection> {
        if !principal.authenticated || principal.principal_id.trim().is_empty() {
            return Err(PolicyReferenceRejection::Unauthenticated);
        }
        let now = current_timestamp()?;
        let expires_at = timestamp_after(&now, self.decision_ttl)?;
        let mut matched = None;
        for adapter in &self.adapters {
            let snapshot = adapter
                .edge
                .lock()
                .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?
                .approval_authorization_snapshot()
                .map_err(map_edge_error)?;
            let mut adapter_match: Option<RetainedApprovalAuthorization> = None;
            for entry in snapshot.entries.into_iter().filter(|value| {
                value
                    .projection
                    .observation
                    .payload
                    .as_ref()
                    .is_some_and(|payload| {
                        matches!(
                            payload,
                            harness_observation::Payload::ApprovalRequest(request)
                                if request.approval_request_id == command.approval_request_id
                        )
                    })
            }) {
                let projection = &entry.projection;
                let request_revision = match projection.observation.payload.as_ref() {
                    Some(harness_observation::Payload::ApprovalRequest(request)) => {
                        request.request_revision
                    }
                    _ => return Err(PolicyReferenceRejection::IntegrityFailure),
                };
                if request_revision == 0
                    || adapter_match.as_ref().is_some_and(|current| {
                        let current_revision = match current.projection.observation.payload.as_ref()
                        {
                            Some(harness_observation::Payload::ApprovalRequest(request)) => {
                                request.request_revision
                            }
                            _ => 0,
                        };
                        request_revision <= current_revision
                            || projection.source_revision <= current.projection.source_revision
                    })
                {
                    return Err(PolicyReferenceRejection::IntegrityFailure);
                }
                adapter_match = Some(entry);
            }
            if let Some(projection) = adapter_match {
                if matched.is_some() {
                    return Err(PolicyReferenceRejection::IntegrityFailure);
                }
                matched = Some((adapter, projection));
            }
        }
        let (adapter, entry) = matched.ok_or(PolicyReferenceRejection::NotFound)?;
        let projection = &entry.projection;
        let request = match projection.observation.payload.as_ref() {
            Some(harness_observation::Payload::ApprovalRequest(request)) => request,
            _ => return Err(PolicyReferenceRejection::IntegrityFailure),
        };
        if request.lifecycle != ApprovalRequestLifecycleKind::Open as i32
            || request.request_revision == 0
            || request.request_revision != command.expected_request_revision
            || request.action_digest_sha256 != command.expected_action_digest_sha256
            || request.requested_scope_ref.is_empty()
            || !self
                .allowed_scope_refs
                .contains(&request.requested_scope_ref)
            || projection.observation.observation_id != command.expected_request_observation_id
            || projection.source_revision != command.expected_request_observation_sequence
        {
            return Err(PolicyReferenceRejection::RequestMismatch);
        }
        let request = private_approval_request(&entry)?;
        let projection = entry.projection;
        let binding = HarnessApprovalRequestBinding {
            adapter_id: adapter.adapter_id.clone(),
            attempt_id: projection.attempt_id,
            dispatch_id: projection.dispatch_id,
            fencing_token: projection.fencing_token,
            approval_request_id: request.approval_request_id,
            kind: request.kind,
            action_digest_sha256: request.action_digest_sha256,
            requested_scope_ref: request.requested_scope_ref,
            native_routing_ref: request.native_routing_ref,
            request_observation_id: projection.source_observation_id,
            request_observation_sequence: projection.source_revision,
            request_lifecycle: request.lifecycle,
            request_revision: request.request_revision,
        };
        let evidence_ref = format!(
            "adapter-approval-request:{}@durable",
            binding.request_observation_id
        );
        Ok(ResolvedApprovalAuthorization {
            request: binding,
            authority_proof: PolicyAuthorityProof {
                authenticated_principal_id: principal.principal_id.clone(),
                authentication_context_ref: self.authentication_context_ref.clone(),
                authorization_policy_ref: Some(self.authorization_policy_ref.clone()),
                authorization_decision_id: format!(
                    "local-policy:{}:{}:{}",
                    principal.principal_id,
                    command.approval_request_id,
                    command.expected_request_revision
                ),
                verified_at: Some(now),
            },
            evidence_refs: vec![evidence_ref],
            expires_at,
        })
    }

    fn validate_adapter_receipt(
        &self,
        command: &ConsumeHarnessApprovalDecisionCommand,
        record: &HarnessApprovalDecisionRecord,
        _principal: &AuthenticatedPolicyPrincipal,
    ) -> Result<Vec<String>, PolicyReferenceRejection> {
        let request = record
            .request
            .as_ref()
            .ok_or(PolicyReferenceRejection::IntegrityFailure)?;
        let receipt = command
            .adapter_receipt
            .as_ref()
            .ok_or(PolicyReferenceRejection::DeliveryReceiptInvalid)?;
        let mut matched = None;
        for adapter in &self.adapters {
            let edge = adapter
                .edge
                .lock()
                .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?;
            let snapshot = edge
                .approval_authorization_snapshot()
                .map_err(map_edge_error)?;
            let mut exact_binding = false;
            let mut request_present = false;
            for entry in &snapshot.entries {
                let Some(harness_observation::Payload::ApprovalRequest(observed)) =
                    entry.projection.observation.payload.as_ref()
                else {
                    continue;
                };
                if observed.approval_request_id != request.approval_request_id {
                    continue;
                }
                request_present = true;
                let private = private_approval_request(entry)?;
                let projection = &entry.projection;
                let binding = HarnessApprovalRequestBinding {
                    adapter_id: adapter.adapter_id.clone(),
                    attempt_id: projection.attempt_id.clone(),
                    dispatch_id: projection.dispatch_id.clone(),
                    fencing_token: projection.fencing_token,
                    approval_request_id: private.approval_request_id,
                    kind: private.kind,
                    action_digest_sha256: private.action_digest_sha256,
                    requested_scope_ref: private.requested_scope_ref,
                    native_routing_ref: private.native_routing_ref,
                    request_observation_id: projection.source_observation_id.clone(),
                    request_observation_sequence: projection.source_revision,
                    request_lifecycle: private.lifecycle,
                    request_revision: private.request_revision,
                };
                if binding == *request {
                    if exact_binding {
                        return Err(PolicyReferenceRejection::IntegrityFailure);
                    }
                    exact_binding = true;
                }
            }
            // Request identity is globally unambiguous, even when two stores
            // use the same native adapter ID. Never choose a store by order.
            if request_present {
                if matched.is_some() {
                    return Err(PolicyReferenceRejection::IntegrityFailure);
                }
                matched = Some((
                    exact_binding,
                    edge.approval_receipt(&request.approval_request_id)
                        .map_err(map_edge_error)?,
                ));
            }
        }
        let (exact_binding, stored) = matched.ok_or(PolicyReferenceRejection::NotFound)?;
        if !exact_binding {
            return Err(PolicyReferenceRejection::RequestMismatch);
        }
        let stored = stored.ok_or(PolicyReferenceRejection::NotFound)?;
        if stored != *receipt
            || receipt.approval_request_id != request.approval_request_id
            || receipt.decision != record.decision
        {
            return Err(PolicyReferenceRejection::DeliveryReceiptInvalid);
        }
        Ok(vec![format!(
            "adapter-approval-receipt:{}@durable",
            receipt.receipt_id
        )])
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LocalUserPolicyConfigurationError {
    #[error("local-user policy resolver configuration is invalid")]
    InvalidConfiguration,
}

fn current_timestamp() -> Result<prost_types::Timestamp, PolicyReferenceRejection> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?;
    Ok(prost_types::Timestamp {
        seconds: i64::try_from(duration.as_secs())
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?,
        nanos: i32::try_from(duration.subsec_nanos())
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?,
    })
}

fn timestamp_after(
    now: &prost_types::Timestamp,
    ttl: Duration,
) -> Result<prost_types::Timestamp, PolicyReferenceRejection> {
    let seconds =
        i64::try_from(ttl.as_secs()).map_err(|_| PolicyReferenceRejection::IntegrityFailure)?;
    let result = now
        .seconds
        .checked_add(seconds)
        .ok_or(PolicyReferenceRejection::IntegrityFailure)?;
    Ok(prost_types::Timestamp {
        seconds: result,
        nanos: now.nanos,
    })
}

/// Public projections deliberately omit native routing. Recover it only from
/// the exact retained private observation, after validating the public/private
/// join and the owning dispatch. Raw bytes never leave this resolver.
fn private_approval_request(
    entry: &RetainedApprovalAuthorization,
) -> Result<ApprovalRequestObservation, PolicyReferenceRejection> {
    let projection = &entry.projection;
    let evidence = &entry.evidence;
    let envelope = &entry.envelope;
    if entry.lineage.as_ref().is_none_or(|lineage| {
        lineage.task_id.trim().is_empty()
            || lineage.task_revision == 0
            || lineage.work_revision == 0
    }) || evidence.observation.observation_id != projection.source_observation_id
        || evidence.observation.observation_sequence != projection.source_revision
        || evidence.observation.native_event_digest_sha256
            != format!("{:x}", Sha256::digest(&evidence.raw_event))
        || projection.payload_digest_sha256
            != format!(
                "{:x}",
                Sha256::digest(projection.observation.encode_to_vec())
            )
        || envelope.run_id != projection.run_id
        || envelope.step_id != projection.step_id
        || envelope.attempt_id != projection.attempt_id
        || envelope.dispatch_id != projection.dispatch_id
        || envelope.fencing_token != projection.fencing_token
        || evidence.observation.capability_profile_id.trim().is_empty()
        || envelope
            .capability_profile_ref
            .as_ref()
            .map(|profile| profile.contract_id.as_str())
            != Some(evidence.observation.capability_profile_id.as_str())
        || envelope
            .route_binding
            .as_ref()
            .map(|route| route.capability_profile_id.as_str())
            != Some(evidence.observation.capability_profile_id.as_str())
    {
        return Err(PolicyReferenceRejection::IntegrityFailure);
    }
    let mut sanitized = evidence.observation.clone();
    let request = match sanitized.payload.as_mut() {
        Some(harness_observation::Payload::ApprovalRequest(request)) => request,
        _ => return Err(PolicyReferenceRejection::IntegrityFailure),
    };
    if request.native_routing_ref.trim().is_empty() {
        return Err(PolicyReferenceRejection::IntegrityFailure);
    }
    let private_request = request.clone();
    request.native_routing_ref.clear();
    if sanitized != projection.observation {
        return Err(PolicyReferenceRejection::IntegrityFailure);
    }
    Ok(private_request)
}

fn map_edge_error(error: AdapterEdgeError) -> PolicyReferenceRejection {
    match error {
        AdapterEdgeError::Sql(_)
        | AdapterEdgeError::Migration(_)
        | AdapterEdgeError::Directory(_)
        | AdapterEdgeError::CipherUnavailable
        | AdapterEdgeError::StoreGenerationMismatch
        | AdapterEdgeError::IntegrityFailure
        | AdapterEdgeError::DispatchConflict
        | AdapterEdgeError::DispatchStateConflict
        | AdapterEdgeError::DispatchNotFound(_)
        | AdapterEdgeError::SequenceConflict
        | AdapterEdgeError::Decode(_) => PolicyReferenceRejection::IntegrityFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egopulse_client_kernel::authorization_contract_ref;
    use egopulse_domain_contracts::v01::egopulse::{
        harness::v1::{
            ApprovalDecision, ApprovalDecisionReceipt, ApprovalKind, ApprovalRequestObservation,
            DeliveryDisposition, DispatchEnvelope, DispatchRouteBinding, HarnessObservation,
            harness_observation,
        },
        policy::v1::{
            ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
            IssueHarnessApprovalDecisionCommand,
        },
    };
    use egopulse_harness_adapter::{AdapterEdgeConfig, AdapterEdgeKey};
    use prost::Message;
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    use uuid::Uuid;

    fn edge_root() -> PathBuf {
        std::env::temp_dir().join(format!("egopulse-agentosd-policy-{}", Uuid::now_v7()))
    }

    fn resolver(root: &Path) -> LocalUserPolicyResolver {
        let edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join("adapter.db"),
            adapter_id: "codex".to_owned(),
            store_epoch: "policy-test-epoch".to_owned(),
            key: AdapterEdgeKey::new([0x41; 32]),
        })
        .expect("open adapter edge");
        LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge,
            adapter_id: "codex".to_owned(),
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .expect("valid local user policy")
    }

    fn edge_with_pending_approval(
        root: &Path,
        file_name: &str,
        adapter_id: &str,
        approval_request_id: &str,
        key_byte: u8,
    ) -> AdapterEdge {
        let mut edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join(file_name),
            adapter_id: adapter_id.to_owned(),
            store_epoch: format!("{adapter_id}-policy-test-epoch"),
            key: AdapterEdgeKey::new([key_byte; 32]),
        })
        .expect("open adapter edge");
        edge.prepare_dispatch(
            &DispatchEnvelope {
                run_id: format!("run-{adapter_id}"),
                run_revision: 1,
                step_id: format!("step-{adapter_id}"),
                step_revision: 1,
                attempt_id: format!("attempt-{adapter_id}"),
                attempt_revision: 1,
                dispatch_id: format!("dispatch-{adapter_id}"),
                dispatch_fingerprint: "f".repeat(64),
                fencing_token: 7,
                capability_profile_ref: Some(ContractReference {
                    contract_id: "profile:policy-test".to_owned(),
                    ..Default::default()
                }),
                route_binding: Some(DispatchRouteBinding {
                    capability_profile_id: "profile:policy-test".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            1,
        )
        .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage(&format!("dispatch-{adapter_id}"), "task-policy", 1, 1, 1)
            .expect("bind task lineage");
        edge.append_observation(
            &format!("dispatch-{adapter_id}"),
            &format!("native-{approval_request_id}"),
            b"approval-request-raw",
            HarnessObservation {
                attempt_id: format!("attempt-{adapter_id}"),
                dispatch_id: format!("dispatch-{adapter_id}"),
                fencing_token: 7,
                capability_profile_id: "profile:policy-test".to_owned(),
                payload: Some(harness_observation::Payload::ApprovalRequest(
                    ApprovalRequestObservation {
                        approval_request_id: approval_request_id.to_owned(),
                        kind: ApprovalKind::Command as i32,
                        action_digest_sha256: "a".repeat(64),
                        requested_scope_ref: "scope://safe".to_owned(),
                        display_summary_ref: format!("summary://{approval_request_id}"),
                        display_summary: None,
                        native_routing_ref: format!("native://{approval_request_id}"),
                        lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                        request_revision: 1,
                    },
                )),
                ..Default::default()
            },
            2,
        )
        .expect("append approval observation");
        edge
    }

    fn acknowledge_pending_approval_projections(edge: &mut AdapterEdge) {
        let pending = edge
            .pending_approval_projection_messages()
            .expect("read pending approval projections");
        for projection in pending {
            assert!(
                edge.acknowledge_approval_projection_message(
                    &projection.message_id,
                    &projection.payload_digest_sha256,
                )
                .expect("acknowledge approval projection")
            );
        }
    }

    #[test]
    fn policy_resolver_requires_the_embedded_authorization_contract() {
        let root = edge_root();
        let edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join("adapter.db"),
            adapter_id: "codex".to_owned(),
            store_epoch: "policy-test-epoch".to_owned(),
            key: AdapterEdgeKey::new([0x42; 32]),
        })
        .expect("open adapter edge");
        let result = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge,
            adapter_id: "codex".to_owned(),
            authorization_policy_ref: ContractReference {
                contract_id: "wrong".to_owned(),
                version: "v0".to_owned(),
                sha256: "0".repeat(64),
            },
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        });
        let error = match result {
            Ok(_) => panic!("wrong policy must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            LocalUserPolicyConfigurationError::InvalidConfiguration
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn policy_resolver_does_not_authorize_a_missing_adapter_request() {
        let root = edge_root();
        let resolver = resolver(&root);
        let principal = AuthenticatedPolicyPrincipal {
            kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
            principal_id: "os-user:test".to_owned(),
            authenticated: true,
        };
        let error = resolver
            .resolve_issue(
                &IssueHarnessApprovalDecisionCommand {
                    approval_request_id: "missing".to_owned(),
                    expected_action_digest_sha256: "a".repeat(64),
                    expected_request_observation_id: "observation".to_owned(),
                    expected_request_observation_sequence: 1,
                    expected_request_revision: 1,
                    reason_code: "test".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .expect_err("missing durable request must be rejected");
        assert_eq!(error, PolicyReferenceRejection::NotFound);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn acknowledged_request_with_later_withdrawal_rejects_the_old_open_command() {
        let root = edge_root();
        let mut edge =
            edge_with_pending_approval(&root, "adapter.db", "codex", "approval-withdrawn", 0x55);
        let open = edge
            .pending_approval_projection_messages()
            .expect("read open approval projection")
            .pop()
            .expect("open approval projection exists");
        acknowledge_pending_approval_projections(&mut edge);
        edge.append_observation(
            "dispatch-codex",
            "native-approval-withdrawn-revision-2",
            b"approval-request-withdrawn-raw",
            HarnessObservation {
                attempt_id: "attempt-codex".to_owned(),
                dispatch_id: "dispatch-codex".to_owned(),
                fencing_token: 7,
                payload: Some(harness_observation::Payload::ApprovalRequest(
                    ApprovalRequestObservation {
                        approval_request_id: "approval-withdrawn".to_owned(),
                        kind: ApprovalKind::Command as i32,
                        action_digest_sha256: "a".repeat(64),
                        requested_scope_ref: "scope://safe".to_owned(),
                        display_summary_ref: "summary://approval-withdrawn".to_owned(),
                        display_summary: None,
                        native_routing_ref: "native://approval-withdrawn".to_owned(),
                        lifecycle: ApprovalRequestLifecycleKind::Withdrawn as i32,
                        request_revision: 2,
                    },
                )),
                ..Default::default()
            },
            3,
        )
        .expect("append withdrawn approval observation");
        acknowledge_pending_approval_projections(&mut edge);

        let resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge,
            adapter_id: "codex".to_owned(),
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .expect("valid local user policy");
        let error = resolver
            .resolve_issue(
                &IssueHarnessApprovalDecisionCommand {
                    approval_request_id: "approval-withdrawn".to_owned(),
                    expected_action_digest_sha256: "a".repeat(64),
                    expected_request_observation_id: open.source_observation_id,
                    expected_request_observation_sequence: open.source_revision,
                    expected_request_revision: 1,
                    reason_code: "stale-open-request".to_owned(),
                    ..Default::default()
                },
                &AuthenticatedPolicyPrincipal {
                    kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
                    principal_id: "os-user:test".to_owned(),
                    authenticated: true,
                },
            )
            .expect_err("withdrawn latest request must reject the old Open command");
        assert_eq!(error, PolicyReferenceRejection::RequestMismatch);
        drop(resolver);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_adapter_second_store_issue_consume_and_reopen_use_exact_binding() {
        let root = edge_root();
        let first = edge_with_pending_approval(&root, "first.db", "codex", "first", 0x61);
        let mut second = edge_with_pending_approval(&root, "second.db", "codex", "second", 0x62);
        let projection = second
            .pending_approval_projection_messages()
            .unwrap()
            .remove(0);
        second
            .prepare_approval("second", "dispatch-codex", &"d".repeat(64), 2)
            .unwrap();
        second.begin_approval("second", 2).unwrap();
        let receipt = ApprovalDecisionReceipt {
            receipt_id: "second-receipt".to_owned(),
            approval_request_id: "second".to_owned(),
            decision: ApprovalDecision::Deny as i32,
            disposition: DeliveryDisposition::Delivered as i32,
            receipt_digest_sha256: "a".repeat(64),
            delivered_at: None,
        };
        second
            .record_approval_receipt(
                "second",
                "delivered",
                &receipt.encode_to_vec(),
                b"safe fixture receipt",
                3,
            )
            .unwrap();
        acknowledge_pending_approval_projections(&mut second);
        drop(first);
        drop(second);
        let principal = AuthenticatedPolicyPrincipal {
            kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
            principal_id: "os-user:test".to_owned(),
            authenticated: true,
        };
        let issue = IssueHarnessApprovalDecisionCommand {
            approval_request_id: "second".to_owned(),
            expected_action_digest_sha256: "a".repeat(64),
            expected_request_observation_id: projection.source_observation_id,
            expected_request_observation_sequence: projection.source_revision,
            expected_request_revision: 1,
            ..Default::default()
        };
        let mut original = None;
        // Pass 0 registers the store that owns the request second, so a lookup
        // that resolves by adapter identity alone selects the sibling store and
        // cannot find the receipt. Pass 1 reverses the registration order, so
        // the pair shows the store is chosen by durable request binding rather
        // than by registration order.
        for pass in 0..2 {
            let mut sources = [("first.db", 0x61), ("second.db", 0x62)];
            if pass == 1 {
                sources.reverse();
            }
            let adapters = sources
                .into_iter()
                .map(|(file, key)| LocalUserPolicyAdapterConfig {
                    edge: AdapterEdge::open(AdapterEdgeConfig {
                        database_path: root.join(file),
                        adapter_id: "codex".to_owned(),
                        store_epoch: "codex-policy-test-epoch".to_owned(),
                        key: AdapterEdgeKey::new([key; 32]),
                    })
                    .unwrap(),
                    adapter_id: "codex".to_owned(),
                })
                .collect();
            let resolver = LocalUserPolicyResolver::new_multi(LocalUserPolicyResolverMultiConfig {
                adapters,
                authorization_policy_ref: authorization_contract_ref(),
                authentication_context_ref: "local-ipc:test".to_owned(),
                allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
                decision_ttl: Duration::from_secs(300),
            })
            .unwrap();
            let resolved = resolver.resolve_issue(&issue, &principal).unwrap();
            if let Some(binding) = &original {
                assert_eq!(binding, &resolved.request);
            }
            original = Some(resolved.request.clone());
            let command = ConsumeHarnessApprovalDecisionCommand {
                adapter_receipt: Some(receipt.clone()),
                ..Default::default()
            };
            let mut record = HarnessApprovalDecisionRecord {
                request: Some(resolved.request),
                decision: receipt.decision,
                ..Default::default()
            };
            for _ in 0..2 {
                assert_eq!(
                    resolver
                        .validate_adapter_receipt(&command, &record, &principal)
                        .unwrap(),
                    vec!["adapter-approval-receipt:second-receipt@durable"]
                );
            }
            record.request.as_mut().unwrap().fencing_token += 1;
            assert_eq!(
                resolver
                    .validate_adapter_receipt(&command, &record, &principal)
                    .unwrap_err(),
                PolicyReferenceRejection::RequestMismatch
            );
        }
        // The receipt is bound to the store that owns the request. Reopen both
        // stores and show the sibling - which shares the adapter ID and is
        // registered before the owner in pass 0 - holds no receipt the consume
        // could have returned, while still owning a competing request. A lookup
        // that resolves by adapter identity alone is therefore observably wrong
        // rather than merely untested.
        let sibling = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join("first.db"),
            adapter_id: "codex".to_owned(),
            store_epoch: "codex-policy-test-epoch".to_owned(),
            key: AdapterEdgeKey::new([0x61; 32]),
        })
        .expect("reopen sibling store");
        assert!(
            sibling
                .approval_authorization_snapshot()
                .expect("read sibling snapshot")
                .entries
                .iter()
                .any(|entry| matches!(
                    entry.projection.observation.payload.as_ref(),
                    Some(harness_observation::Payload::ApprovalRequest(request))
                        if request.approval_request_id == "first"
                )),
            "the sibling store must own a competing request under the same adapter ID"
        );
        assert!(
            sibling
                .approval_receipt("second")
                .expect("read sibling receipt")
                .is_none(),
            "the sibling store must not hold the owning store's receipt"
        );
        let owner = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join("second.db"),
            adapter_id: "codex".to_owned(),
            store_epoch: "codex-policy-test-epoch".to_owned(),
            key: AdapterEdgeKey::new([0x62; 32]),
        })
        .expect("reopen owning store");
        assert_eq!(
            owner
                .approval_receipt("second")
                .expect("read owning receipt"),
            Some(receipt.clone()),
            "the owning store must hold the exact receipt the consume returned"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_adapter_cross_store_request_collision_rejects_issue_and_consume() {
        let root = edge_root();
        let first = edge_with_pending_approval(&root, "a.db", "codex", "collision", 0x63);
        let second = edge_with_pending_approval(&root, "b.db", "codex", "collision", 0x64);
        let resolver = LocalUserPolicyResolver::new_multi(LocalUserPolicyResolverMultiConfig {
            adapters: vec![first, second]
                .into_iter()
                .map(|edge| LocalUserPolicyAdapterConfig {
                    edge,
                    adapter_id: "codex".to_owned(),
                })
                .collect(),
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .unwrap();
        let principal = AuthenticatedPolicyPrincipal {
            kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
            principal_id: "os-user:test".to_owned(),
            authenticated: true,
        };
        assert_eq!(
            resolver
                .resolve_issue(
                    &IssueHarnessApprovalDecisionCommand {
                        approval_request_id: "collision".to_owned(),
                        ..Default::default()
                    },
                    &principal
                )
                .unwrap_err(),
            PolicyReferenceRejection::IntegrityFailure
        );
        assert_eq!(
            resolver
                .validate_adapter_receipt(
                    &ConsumeHarnessApprovalDecisionCommand {
                        adapter_receipt: Some(ApprovalDecisionReceipt::default()),
                        ..Default::default()
                    },
                    &HarnessApprovalDecisionRecord {
                        request: Some(HarnessApprovalRequestBinding {
                            adapter_id: "codex".to_owned(),
                            approval_request_id: "collision".to_owned(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    &principal
                )
                .unwrap_err(),
            PolicyReferenceRejection::IntegrityFailure
        );
        drop(resolver);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn multi_provider_policy_routes_exactly_one_adapter_and_rejects_collisions() {
        let root = edge_root();
        let codex = edge_with_pending_approval(&root, "codex.db", "codex", "approval-codex", 0x51);
        let opencode =
            edge_with_pending_approval(&root, "opencode.db", "opencode", "approval-glm", 0x52);
        let resolver = LocalUserPolicyResolver::new_multi(LocalUserPolicyResolverMultiConfig {
            adapters: vec![
                LocalUserPolicyAdapterConfig {
                    edge: codex,
                    adapter_id: "codex".to_owned(),
                },
                LocalUserPolicyAdapterConfig {
                    edge: opencode,
                    adapter_id: "opencode".to_owned(),
                },
            ],
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .expect("valid multi-provider policy");
        let principal = AuthenticatedPolicyPrincipal {
            kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
            principal_id: "os-user:test".to_owned(),
            authenticated: true,
        };
        let (expected_request_observation_id, expected_request_observation_sequence) = {
            let edge = resolver.adapters[1].edge.lock().expect("opencode edge");
            let projection = edge
                .pending_approval_projection_messages()
                .expect("pending projection")[0]
                .clone();
            (projection.source_observation_id, projection.source_revision)
        };
        let resolved = resolver
            .resolve_issue(
                &IssueHarnessApprovalDecisionCommand {
                    approval_request_id: "approval-glm".to_owned(),
                    expected_action_digest_sha256: "a".repeat(64),
                    expected_request_observation_id,
                    expected_request_observation_sequence,
                    expected_request_revision: 1,
                    reason_code: "multi-provider-test".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .expect("approval must route to OpenCode");
        assert_eq!(resolved.request.adapter_id, "opencode");

        drop(resolver);
        let mut duplicate_a = edge_with_pending_approval(
            &root,
            "duplicate-a.db",
            "duplicate-a",
            "approval-collision",
            0x53,
        );
        let mut duplicate_b = edge_with_pending_approval(
            &root,
            "duplicate-b.db",
            "duplicate-b",
            "approval-collision",
            0x54,
        );
        acknowledge_pending_approval_projections(&mut duplicate_a);
        acknowledge_pending_approval_projections(&mut duplicate_b);
        let collision = LocalUserPolicyResolver::new_multi(LocalUserPolicyResolverMultiConfig {
            adapters: vec![
                LocalUserPolicyAdapterConfig {
                    edge: duplicate_a,
                    adapter_id: "duplicate-a".to_owned(),
                },
                LocalUserPolicyAdapterConfig {
                    edge: duplicate_b,
                    adapter_id: "duplicate-b".to_owned(),
                },
            ],
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .expect("valid collision fixture");
        let error = collision
            .resolve_issue(
                &IssueHarnessApprovalDecisionCommand {
                    approval_request_id: "approval-collision".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .expect_err("cross-provider approval collision must fail closed");
        assert_eq!(error, PolicyReferenceRejection::IntegrityFailure);
        drop(collision);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn acknowledged_private_request_issues_through_the_real_policy_authority() {
        use egopulse_domain_contracts::v01::egopulse::{
            common::v1::CommandMetadata,
            policy::v1::{PolicyDecisionCommand, policy_decision_command},
        };
        use egopulse_policy_decision_authority::{
            PolicyAuthorityConfig, PolicyDecisionAuthority, PolicySqlCipherKey,
            canonical_request_digest,
        };

        let root = edge_root();
        let mut edge =
            edge_with_pending_approval(&root, "adapter.db", "codex", "approval-issue", 0x56);
        let projection = edge
            .pending_approval_projection_messages()
            .expect("projection")
            .remove(0);
        acknowledge_pending_approval_projections(&mut edge);
        let entry = edge
            .approval_authorization_snapshot()
            .expect("consistent owner snapshot")
            .entries
            .remove(0);
        let request = private_approval_request(&entry).expect("private binding");
        assert_eq!(request.native_routing_ref, "native://approval-issue");
        for field in 0..8 {
            let mut changed = entry.clone();
            match field {
                0 => changed.projection.observation.native_event_digest_sha256 = "0".repeat(64),
                1 => {
                    changed.projection.observation.capability_profile_id =
                        "profile:other".to_owned()
                }
                2 => changed.projection.fencing_token += 1,
                3 => changed.projection.run_id = "run-other".to_owned(),
                4 => changed.projection.source_revision += 1,
                5 => changed.evidence.raw_event.push(b'x'),
                6 => changed.lineage = None,
                _ => changed.envelope.route_binding = None,
            }
            assert_eq!(
                private_approval_request(&changed),
                Err(PolicyReferenceRejection::IntegrityFailure)
            );
        }
        let public = match projection
            .observation
            .payload
            .as_ref()
            .expect("public payload")
        {
            harness_observation::Payload::ApprovalRequest(request) => request,
            _ => panic!("approval payload"),
        };
        assert!(public.native_routing_ref.is_empty());
        let resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge,
            adapter_id: "codex".to_owned(),
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .expect("resolver");
        let mut authority = PolicyDecisionAuthority::open(
            PolicyAuthorityConfig {
                database_path: root.join("policy.db"),
                store_epoch: "policy-issue-test".to_owned(),
                key: PolicySqlCipherKey::new([0x57; 32]),
            },
            resolver,
        )
        .expect("real policy authority");
        let mut command = PolicyDecisionCommand {
            command: Some(
                policy_decision_command::Command::IssueHarnessApprovalDecision(
                    IssueHarnessApprovalDecisionCommand {
                        metadata: Some(CommandMetadata {
                            command_id: "policy-issue-test".to_owned(),
                            idempotency_key: "policy-issue-test".to_owned(),
                            idempotency_scope: "policy-test".to_owned(),
                            issued_at: Some(current_timestamp().expect("time")),
                            correlation_id: "policy-issue-test".to_owned(),
                            ..Default::default()
                        }),
                        approval_request_id: public.approval_request_id.clone(),
                        expected_action_digest_sha256: public.action_digest_sha256.clone(),
                        expected_request_observation_id: projection.source_observation_id,
                        expected_request_observation_sequence: projection.source_revision,
                        expected_request_revision: public.request_revision,
                        decision: ApprovalDecision::AllowOnce as i32,
                        reason_code: "ISOLATED_POLICY_TEST".to_owned(),
                        ..Default::default()
                    },
                ),
            ),
        };
        let digest = canonical_request_digest(&command);
        let Some(policy_decision_command::Command::IssueHarnessApprovalDecision(issue)) =
            command.command.as_mut()
        else {
            panic!("issue")
        };
        issue
            .metadata
            .as_mut()
            .expect("metadata")
            .request_digest_sha256 = digest;
        let principal = AuthenticatedPolicyPrincipal {
            kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
            principal_id: "os-user:test".to_owned(),
            authenticated: true,
        };
        let result = authority
            .execute(&command, &principal)
            .expect("execute issue");
        assert!(
            result.committed,
            "Policy rejected trusted request: {:?}",
            result.safe_error_fingerprint
        );
        assert!(
            authority
                .execute(&command, &principal)
                .expect("exact replay")
                .replayed
        );
        drop(authority);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn policy_configuration_rejects_an_adapter_owner_alias() {
        let root = edge_root();
        let edge = edge_with_pending_approval(&root, "adapter.db", "codex", "approval-owner", 0x58);
        let configured = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge,
            adapter_id: "other-owner".to_owned(),
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        });
        assert!(matches!(
            configured,
            Err(LocalUserPolicyConfigurationError::InvalidConfiguration)
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn policy_resolver_builds_binding_from_durable_adapter_projection() {
        let root = edge_root();
        let mut edge = AdapterEdge::open(AdapterEdgeConfig {
            database_path: root.join("adapter.db"),
            adapter_id: "codex".to_owned(),
            store_epoch: "policy-test-epoch".to_owned(),
            key: AdapterEdgeKey::new([0x43; 32]),
        })
        .expect("open adapter edge");
        edge.prepare_dispatch(
            &DispatchEnvelope {
                run_id: "run-1".to_owned(),
                run_revision: 1,
                step_id: "step-1".to_owned(),
                step_revision: 1,
                attempt_id: "attempt-1".to_owned(),
                attempt_revision: 1,
                dispatch_id: "dispatch-1".to_owned(),
                dispatch_fingerprint: "f".repeat(64),
                fencing_token: 7,
                capability_profile_ref: Some(ContractReference {
                    contract_id: "profile:policy-test".to_owned(),
                    ..Default::default()
                }),
                route_binding: Some(DispatchRouteBinding {
                    capability_profile_id: "profile:policy-test".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            1,
        )
        .expect("prepare dispatch");
        edge.bind_dispatch_task_lineage("dispatch-1", "task-policy", 1, 1, 1)
            .expect("bind task lineage");
        edge.append_observation(
            "dispatch-1",
            "native-approval-1",
            b"approval-request-raw",
            HarnessObservation {
                attempt_id: "attempt-1".to_owned(),
                dispatch_id: "dispatch-1".to_owned(),
                fencing_token: 7,
                capability_profile_id: "profile:policy-test".to_owned(),
                payload: Some(harness_observation::Payload::ApprovalRequest(
                    ApprovalRequestObservation {
                        approval_request_id: "approval-1".to_owned(),
                        kind: ApprovalKind::Command as i32,
                        action_digest_sha256: "a".repeat(64),
                        requested_scope_ref: "scope://safe".to_owned(),
                        display_summary_ref: "summary://approval-1".to_owned(),
                        display_summary: None,
                        native_routing_ref: "native://approval-1".to_owned(),
                        lifecycle: ApprovalRequestLifecycleKind::Open as i32,
                        request_revision: 3,
                    },
                )),
                ..Default::default()
            },
            2,
        )
        .expect("append approval observation");
        edge.prepare_approval("approval-1", "dispatch-1", &"d".repeat(64), 2)
            .expect("prepare approval");
        edge.begin_approval("approval-1", 2)
            .expect("begin approval");
        let receipt = ApprovalDecisionReceipt {
            receipt_id: "approval-receipt-1".to_owned(),
            approval_request_id: "approval-1".to_owned(),
            decision: ApprovalDecision::AllowOnce as i32,
            disposition: DeliveryDisposition::Delivered as i32,
            receipt_digest_sha256: "r".repeat(64),
            delivered_at: None,
        };
        edge.record_approval_receipt(
            "approval-1",
            "delivered",
            &receipt.encode_to_vec(),
            b"approval-receipt-raw",
            3,
        )
        .expect("record approval receipt");
        let projection = edge
            .pending_approval_projection_messages()
            .expect("read approval projection")
            .pop()
            .expect("approval projection exists");
        assert!(
            edge.acknowledge_approval_projection_message(
                &projection.message_id,
                &projection.payload_digest_sha256,
            )
            .expect("acknowledge approval projection")
        );
        assert!(
            edge.pending_approval_projection_messages()
                .expect("projection outbox drained")
                .is_empty()
        );
        let resolver = LocalUserPolicyResolver::new(LocalUserPolicyResolverConfig {
            edge,
            adapter_id: "codex".to_owned(),
            authorization_policy_ref: authorization_contract_ref(),
            authentication_context_ref: "local-ipc:test".to_owned(),
            allowed_scope_refs: BTreeSet::from(["scope://safe".to_owned()]),
            decision_ttl: Duration::from_secs(300),
        })
        .expect("valid local user policy");
        let principal = AuthenticatedPolicyPrincipal {
            kind: egopulse_policy_decision_authority::PolicyPrincipalKind::LocalUser,
            principal_id: "os-user:test".to_owned(),
            authenticated: true,
        };
        let resolved = resolver
            .resolve_issue(
                &IssueHarnessApprovalDecisionCommand {
                    approval_request_id: "approval-1".to_owned(),
                    expected_action_digest_sha256: "a".repeat(64),
                    expected_request_observation_id: projection.source_observation_id.clone(),
                    expected_request_observation_sequence: projection.source_revision,
                    expected_request_revision: 3,
                    reason_code: "approved-for-test".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .expect("durable request resolves");
        assert_eq!(resolved.request.adapter_id, "codex");
        assert_eq!(resolved.request.dispatch_id, "dispatch-1");
        assert_eq!(resolved.request.fencing_token, 7);
        assert_eq!(resolved.request.request_revision, 3);
        assert_eq!(resolved.request.native_routing_ref, "native://approval-1");
        assert_eq!(
            resolved.authority_proof.authenticated_principal_id,
            "os-user:test"
        );
        assert_eq!(resolved.evidence_refs.len(), 1);
        let evidence = resolver
            .validate_adapter_receipt(
                &ConsumeHarnessApprovalDecisionCommand {
                    adapter_receipt: Some(receipt),
                    ..Default::default()
                },
                &HarnessApprovalDecisionRecord {
                    request: Some(resolved.request.clone()),
                    decision: ApprovalDecision::AllowOnce as i32,
                    ..Default::default()
                },
                &principal,
            )
            .expect("stored adapter receipt resolves");
        assert_eq!(
            evidence,
            vec!["adapter-approval-receipt:approval-receipt-1@durable"]
        );

        let revision_error = resolver
            .resolve_issue(
                &IssueHarnessApprovalDecisionCommand {
                    approval_request_id: "approval-1".to_owned(),
                    expected_action_digest_sha256: "a".repeat(64),
                    expected_request_observation_id: projection.source_observation_id,
                    expected_request_observation_sequence: projection.source_revision,
                    expected_request_revision: 4,
                    reason_code: "stale-revision".to_owned(),
                    ..Default::default()
                },
                &principal,
            )
            .expect_err("stale request revision must be rejected by the resolver");
        assert_eq!(revision_error, PolicyReferenceRejection::RequestMismatch);
        drop(resolver);
        let _ = fs::remove_dir_all(root);
    }
}
