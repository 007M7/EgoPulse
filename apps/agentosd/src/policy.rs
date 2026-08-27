use std::{
    collections::BTreeSet,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use egopulse_client_kernel::authorization_contract_ref;
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    harness::v1::{ApprovalRequestLifecycleKind, harness_observation},
    policy::v1::{
        ConsumeHarnessApprovalDecisionCommand, HarnessApprovalDecisionRecord,
        HarnessApprovalRequestBinding, IssueHarnessApprovalDecisionCommand, PolicyAuthorityProof,
    },
};
use egopulse_harness_adapter::{AdapterEdge, AdapterEdgeError};
use egopulse_policy_decision_authority::{
    AuthenticatedPolicyPrincipal, PolicyReferenceRejection, PolicyReferenceResolver,
    ResolvedApprovalAuthorization,
};
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
        let mut adapter_ids = BTreeSet::new();
        if config.adapters.iter().any(|adapter| {
            adapter.adapter_id.trim().is_empty() || !adapter_ids.insert(adapter.adapter_id.clone())
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
            let projections = adapter
                .edge
                .lock()
                .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?
                .pending_approval_projection_messages()
                .map_err(map_edge_error)?;
            for projection in projections.into_iter().filter(|value| {
                value.observation.payload.as_ref().is_some_and(|payload| {
                    matches!(
                        payload,
                        harness_observation::Payload::ApprovalRequest(request)
                            if request.approval_request_id == command.approval_request_id
                    )
                })
            }) {
                if matched.is_some() {
                    return Err(PolicyReferenceRejection::IntegrityFailure);
                }
                matched = Some((adapter.adapter_id.clone(), projection));
            }
        }
        let (adapter_id, projection) = matched.ok_or(PolicyReferenceRejection::NotFound)?;
        let request = match projection.observation.payload {
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
        let binding = HarnessApprovalRequestBinding {
            adapter_id,
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
        let adapter = self
            .adapters
            .iter()
            .find(|adapter| adapter.adapter_id == request.adapter_id)
            .ok_or(PolicyReferenceRejection::NotFound)?;
        let stored = adapter
            .edge
            .lock()
            .map_err(|_| PolicyReferenceRejection::IntegrityFailure)?
            .approval_receipt(&request.approval_request_id)
            .map_err(map_edge_error)?
            .ok_or(PolicyReferenceRejection::NotFound)?;
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
            DeliveryDisposition, DispatchEnvelope, HarnessObservation, harness_observation,
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
                ..Default::default()
            },
            1,
        )
        .expect("prepare dispatch");
        edge.append_observation(
            &format!("dispatch-{adapter_id}"),
            &format!("native-{approval_request_id}"),
            b"approval-request-raw",
            HarnessObservation {
                attempt_id: format!("attempt-{adapter_id}"),
                dispatch_id: format!("dispatch-{adapter_id}"),
                fencing_token: 7,
                payload: Some(harness_observation::Payload::ApprovalRequest(
                    ApprovalRequestObservation {
                        approval_request_id: approval_request_id.to_owned(),
                        kind: ApprovalKind::Command as i32,
                        action_digest_sha256: "a".repeat(64),
                        requested_scope_ref: "scope://safe".to_owned(),
                        display_summary_ref: format!("summary://{approval_request_id}"),
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
        let duplicate_a = edge_with_pending_approval(
            &root,
            "duplicate-a.db",
            "duplicate-a",
            "approval-collision",
            0x53,
        );
        let duplicate_b = edge_with_pending_approval(
            &root,
            "duplicate-b.db",
            "duplicate-b",
            "approval-collision",
            0x54,
        );
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
                ..Default::default()
            },
            1,
        )
        .expect("prepare dispatch");
        edge.append_observation(
            "dispatch-1",
            "native-approval-1",
            b"approval-request-raw",
            HarnessObservation {
                attempt_id: "attempt-1".to_owned(),
                dispatch_id: "dispatch-1".to_owned(),
                fencing_token: 7,
                payload: Some(harness_observation::Payload::ApprovalRequest(
                    ApprovalRequestObservation {
                        approval_request_id: "approval-1".to_owned(),
                        kind: ApprovalKind::Command as i32,
                        action_digest_sha256: "a".repeat(64),
                        requested_scope_ref: "scope://safe".to_owned(),
                        display_summary_ref: "summary://approval-1".to_owned(),
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
