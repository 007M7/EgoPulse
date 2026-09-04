use egopulse_domain_contracts::profiles::{
    HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID, HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use egopulse_domain_contracts::v01::egopulse::harness::v1::{
    AuthorizedContextConsumptionProof, ContentMutationOperation, DeliveryDisposition,
    DispatchContextConsumptionProof, DispatchEnvelope, DispatchReceipt, DispatchRouteBinding,
    HarnessContentMarkerKind, HarnessContentSafetyFlag, HarnessContentSignalObservation,
    HarnessObservation, LifecycleKind, NotContextBoundProof, ObservationCriticality,
    SideEffectCertainty, dispatch_context_consumption_proof, dispatch_route_binding,
    harness_observation, safe_harness_content_record,
};
use egopulse_harness_adapter::{
    AdapterEdge, AdapterEdgeConfig, AdapterEdgeKey, ContentRetentionCompactionRequest,
    DispatchPreparation, GovernedHarnessContentProjector, HarnessContentDrain,
    ManagedDisclosureCredentials, SafeContentCommit, SystemAdapterClock, TrustedContentLineage,
    approval_required_content_candidate, assistant_text_content_candidate,
    assistant_text_mutation_candidate, bind_content_signal, blocked_source_content_candidate,
    canonical_dispatch_route_binding_digest, canonical_safe_record_digest,
    lifecycle_content_candidate, project_safe_content, usage_content_candidate,
};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct Store {
    root: PathBuf,
}

impl Store {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("egopulse-{label}-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).expect("create R9C Adapter fixture root");
        Self { root }
    }

    fn database(&self) -> PathBuf {
        self.root.join("adapter.sqlcipher")
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove R9C Adapter fixture root");
        }
    }
}

fn open_edge(path: &Path) -> AdapterEdge {
    AdapterEdge::open(AdapterEdgeConfig {
        database_path: path.to_owned(),
        adapter_id: "codex-adapter".to_owned(),
        store_epoch: "r9c-adapter-v4-test".to_owned(),
        key: AdapterEdgeKey::new([0x39; 32]),
    })
    .expect("open R9C Adapter Edge")
}

fn route_binding() -> DispatchRouteBinding {
    let mut binding = DispatchRouteBinding {
        provider_bootstrap_profile_id: "gpt-codex-default".to_owned(),
        selected_harness_id: "codex_app_server".to_owned(),
        provider_model_id: "gpt-5.6-sol".to_owned(),
        catalog_snapshot: Some(
            dispatch_route_binding::CatalogSnapshot::CatalogSnapshotSha256("a".repeat(64)),
        ),
        capability_profile_id: "codex-app-server-v2-0.148.0-alpha.15".to_owned(),
        route_binding_sha256: String::new(),
    };
    binding.route_binding_sha256 =
        canonical_dispatch_route_binding_digest(&binding).expect("canonical route binding");
    binding
}

fn envelope(dispatch_id: &str, binding: Option<DispatchRouteBinding>) -> DispatchEnvelope {
    DispatchEnvelope {
        run_id: "run-r9c".to_owned(),
        run_revision: 1,
        step_id: "step-r9c".to_owned(),
        step_revision: 1,
        attempt_id: "attempt-r9c".to_owned(),
        attempt_revision: 1,
        dispatch_id: dispatch_id.to_owned(),
        dispatch_fingerprint: "d".repeat(64),
        fencing_token: 7,
        capability_profile_ref: Some(ContractReference {
            contract_id: "codex-app-server-v2-0.148.0-alpha.15".to_owned(),
            version: "0.1.0".to_owned(),
            sha256: "c".repeat(64),
        }),
        input_bundle_ref: "input-r9c.json".to_owned(),
        input_bundle_sha256: "e".repeat(64),
        route_binding: binding,
        ..DispatchEnvelope::default()
    }
}

fn delivered_receipt(
    dispatch: &DispatchEnvelope,
    binding: &DispatchRouteBinding,
) -> DispatchReceipt {
    let mut receipt = DispatchReceipt {
        receipt_id: format!("receipt-{}", dispatch.dispatch_id),
        disposition: DeliveryDisposition::Delivered as i32,
        attempt_id: dispatch.attempt_id.clone(),
        dispatch_id: dispatch.dispatch_id.clone(),
        fencing_token: dispatch.fencing_token,
        adapter_id: "codex-adapter".to_owned(),
        capability_profile_id: binding.capability_profile_id.clone(),
        evidence_ref: "adapter-edge:test".to_owned(),
        ..DispatchReceipt::default()
    };
    receipt.receipt_digest_sha256 = hex::encode(Sha256::digest(receipt.encode_to_vec()));
    receipt
}

fn bound_content_observation(
    dispatch: &DispatchEnvelope,
    binding: &DispatchRouteBinding,
    receipt: &DispatchReceipt,
    native_id: &str,
    native_sequence: u64,
    raw: &[u8],
    candidate: egopulse_domain_contracts::v01::egopulse::harness::v1::UserVisibleContentCandidate,
) -> HarnessObservation {
    let mut observation = HarnessObservation {
        attempt_id: dispatch.attempt_id.clone(),
        dispatch_id: dispatch.dispatch_id.clone(),
        fencing_token: dispatch.fencing_token,
        native_event_id: Some(native_id.to_owned()),
        native_sequence: Some(native_sequence),
        native_event_digest_sha256: hex::encode(Sha256::digest(raw)),
        capability_profile_id: binding.capability_profile_id.clone(),
        criticality: ObservationCriticality::Informational as i32,
        payload: Some(harness_observation::Payload::ContentSignal(
            HarnessContentSignalObservation {
                candidate: Some(candidate),
                ..HarnessContentSignalObservation::default()
            },
        )),
        ..HarnessObservation::default()
    };
    let source = observation.clone();
    let Some(harness_observation::Payload::ContentSignal(signal)) = observation.payload.as_mut()
    else {
        panic!("content fixture")
    };
    bind_content_signal(
        &source,
        signal,
        &receipt.receipt_id,
        &receipt.receipt_digest_sha256,
        &binding.route_binding_sha256,
        DispatchContextConsumptionProof {
            branch: Some(dispatch_context_consumption_proof::Branch::NotContextBound(
                NotContextBoundProof {},
            )),
        },
    )
    .expect("bind exact content source tuple");
    observation
}

#[test]
fn r9c_route_binding_is_persisted_only_with_the_original_dispatch_envelope() {
    let store = Store::new("route-binding-v4");
    let mut edge = open_edge(&store.database());
    let binding = route_binding();
    let bound = envelope("dispatch-bound", Some(binding.clone()));
    assert_eq!(
        edge.prepare_dispatch(&bound, 10)
            .expect("prepare bound dispatch"),
        DispatchPreparation::Ready
    );
    assert_eq!(
        edge.dispatch_route_binding(&bound.dispatch_id)
            .expect("read persisted route binding"),
        Some(binding)
    );

    let legacy = envelope("dispatch-legacy", None);
    edge.prepare_dispatch(&legacy, 11)
        .expect("prepare unbound historic-compatible dispatch");
    assert_eq!(
        edge.dispatch_route_binding(&legacy.dispatch_id)
            .expect("read absent route binding"),
        None
    );
    let mut illegal_backfill = legacy.clone();
    illegal_backfill.route_binding = Some(route_binding());
    assert!(
        edge.prepare_dispatch(&illegal_backfill, 12).is_err(),
        "an existing envelope can never be enriched after persistence"
    );
    assert_eq!(
        edge.inspect()
            .expect("inspect Edge")
            .dispatch_route_binding_count,
        1
    );
}

#[test]
fn r9c_candidate_crash_window_recovers_to_exact_safe_ledger_without_reredaction() {
    let store = Store::new("candidate-safe-ledger-v4");
    let database = store.database();
    let binding = route_binding();
    let dispatch = envelope("dispatch-content", Some(binding.clone()));
    let raw = b"codex-agent-message-raw";
    let mut observation = HarnessObservation {
        attempt_id: dispatch.attempt_id.clone(),
        dispatch_id: dispatch.dispatch_id.clone(),
        fencing_token: dispatch.fencing_token,
        native_event_id: Some("native-agent-message-1".to_owned()),
        native_sequence: Some(1),
        native_event_digest_sha256: hex::encode(Sha256::digest(raw)),
        capability_profile_id: binding.capability_profile_id.clone(),
        criticality: ObservationCriticality::Informational as i32,
        payload: Some(harness_observation::Payload::ContentSignal(
            HarnessContentSignalObservation {
                candidate: assistant_text_content_candidate(
                    "message-r9c",
                    b"hello\r\nsecret%22slash%5C\t\x1b".to_vec(),
                ),
                ..HarnessContentSignalObservation::default()
            },
        )),
        ..HarnessObservation::default()
    };
    let proof = DispatchContextConsumptionProof {
        branch: Some(dispatch_context_consumption_proof::Branch::NotContextBound(
            NotContextBoundProof {},
        )),
    };
    let source = observation.clone();
    let Some(harness_observation::Payload::ContentSignal(signal)) = observation.payload.as_mut()
    else {
        panic!("content fixture")
    };
    bind_content_signal(
        &source,
        signal,
        "receipt-content",
        &"b".repeat(64),
        &binding.route_binding_sha256,
        proof,
    )
    .expect("bind trusted content tuple");

    {
        let mut edge = open_edge(&database);
        edge.prepare_dispatch(&dispatch, 10).expect("prepare");
        edge.begin_delivery(&dispatch.dispatch_id, 11)
            .expect("begin delivery");
        edge.record_dispatch_receipt(
            &DispatchReceipt {
                receipt_id: "receipt-content".to_owned(),
                disposition: DeliveryDisposition::Delivered as i32,
                attempt_id: dispatch.attempt_id.clone(),
                dispatch_id: dispatch.dispatch_id.clone(),
                fencing_token: dispatch.fencing_token,
                adapter_id: "codex-adapter".to_owned(),
                capability_profile_id: binding.capability_profile_id.clone(),
                receipt_digest_sha256: "b".repeat(64),
                evidence_ref: "adapter-edge:test".to_owned(),
                ..DispatchReceipt::default()
            },
            b"delivery-evidence",
            12,
        )
        .expect("record delivered receipt");
        edge.bind_dispatch_task_lineage(&dispatch.dispatch_id, "task-r9c", 1, 1, 13)
            .expect("bind task lineage");
        edge.append_observation(
            &dispatch.dispatch_id,
            "content:1",
            raw,
            observation.clone(),
            14,
        )
        .expect("candidate transaction commits");
        let inspection = edge.inspect().expect("inspect pending candidate");
        assert_eq!(inspection.content_candidate_count, 1);
        assert_eq!(inspection.pending_content_candidate_count, 1);
        assert_eq!(inspection.safe_content_ledger_count, 0);
    }

    let mut edge = open_edge(&database);
    let pending = edge
        .pending_content_candidates()
        .expect("recover pending candidate");
    assert_eq!(pending.len(), 1);
    let projection = project_safe_content(
        &pending[0].observation,
        &pending[0].signal,
        &binding,
        &TrustedContentLineage {
            task_id: "task-r9c".to_owned(),
            run_id: dispatch.run_id.clone(),
            step_id: dispatch.step_id.clone(),
        },
        &["secret\"slash\\".to_owned()],
        None,
    )
    .expect("deterministic projection after reopen");
    let record = projection.record();
    assert_eq!(
        canonical_safe_record_digest(record).as_deref(),
        Some(record.record_digest_sha256.as_str())
    );
    let safe_harness_content_record::Payload::AssistantText(text) =
        record.payload.as_ref().expect("safe payload")
    else {
        panic!("safe assistant payload")
    };
    assert_eq!(text.safe_text_utf8, "hello\n[REDACTED]    �");
    let committed_safe_text_bytes = text.safe_text_utf8.len() as u64;
    assert!(
        record
            .safety_flags
            .contains(&(HarnessContentSafetyFlag::CredentialRedacted as i32))
    );
    assert!(
        record
            .safety_flags
            .contains(&(HarnessContentSafetyFlag::ControlRedacted as i32))
    );
    assert_eq!(
        record.disclosure_profile_ref.as_ref().unwrap().contract_id,
        HARNESS_CONTENT_DISCLOSURE_CONTRACT_ID
    );
    assert_eq!(
        record.disclosure_profile_ref.as_ref().unwrap().sha256,
        HARNESS_CONTENT_DISCLOSURE_PROFILE_DIGEST_SHA256
    );

    assert!(matches!(
        edge.commit_safe_content_projection(&projection, 15)
            .expect("commit safe ledger and outbox"),
        SafeContentCommit::Committed {
            first_sequence: 1,
            last_sequence: 1,
            ..
        }
    ));
    let after_commit = edge.inspect().expect("inspect safe commit");
    assert_eq!(after_commit.pending_content_candidate_count, 0);
    assert_eq!(after_commit.safe_content_ledger_count, 1);
    assert_eq!(after_commit.pending_content_projection_count, 1);
    let budgets = edge
        .safe_content_budget_snapshot("task-r9c", &dispatch.attempt_id)
        .expect("attempt/task budget accounting");
    assert_eq!(budgets.attempt.safe_text_bytes, committed_safe_text_bytes);
    assert_eq!(budgets.attempt.safe_record_count, 1);
    assert_eq!(budgets.task.safe_text_bytes, committed_safe_text_bytes);
    assert_eq!(budgets.task.safe_record_count, 1);
    assert!(!budgets.attempt.limit_reached);
    assert!(!budgets.task.limit_reached);
    assert!(matches!(
        edge.commit_safe_content_projection(&projection, 16)
            .expect("exact safe replay"),
        SafeContentCommit::Replay {
            first_sequence: 1,
            last_sequence: 1,
            ..
        }
    ));
    assert_eq!(edge.inspect().expect("inspect replay"), after_commit);
}

#[test]
fn r9c_independent_projector_restarts_replays_quarantines_and_rebuilds_owner_state() {
    let store = Store::new("independent-projector-v4");
    let database = store.database();
    let binding = route_binding();
    let dispatch = envelope("dispatch-projector", Some(binding.clone()));
    let receipt = delivered_receipt(&dispatch, &binding);
    let candidate = assistant_text_content_candidate("message-projector", b"safe secret".to_vec())
        .expect("candidate");
    let first = bound_content_observation(
        &dispatch,
        &binding,
        &receipt,
        "native-content-1",
        1,
        b"raw-content-1",
        candidate.clone(),
    );
    {
        let mut edge = open_edge(&database);
        edge.prepare_dispatch(&dispatch, 10).expect("prepare");
        edge.begin_delivery(&dispatch.dispatch_id, 11)
            .expect("begin delivery");
        edge.record_dispatch_receipt(&receipt, b"delivery-evidence", 12)
            .expect("record canonical delivered receipt");
        edge.bind_dispatch_task_lineage(&dispatch.dispatch_id, "task-projector", 1, 1, 13)
            .expect("bind task lineage");
        edge.append_observation(
            &dispatch.dispatch_id,
            "content-projector-1",
            b"raw-content-1",
            first,
            14,
        )
        .expect("persist raw candidate before projector starts");
        assert_eq!(edge.inspect().unwrap().safe_content_ledger_count, 0);
    }

    let mut projector = GovernedHarnessContentProjector::new(
        open_edge(&database),
        ManagedDisclosureCredentials::managed_available(vec!["secret".to_owned()]),
        SystemAdapterClock,
    );
    assert!(matches!(
        projector.drain_once().expect("restart drain"),
        HarnessContentDrain::Committed(SafeContentCommit::Committed {
            first_sequence: 1,
            last_sequence: 1,
            ..
        })
    ));
    assert_eq!(projector.drain_once().unwrap(), HarnessContentDrain::Idle);
    drop(projector);

    let mut edge = open_edge(&database);
    let owner_after_commit = edge
        .content_owner_snapshot("task-projector")
        .expect("owner snapshot")
        .expect("owner snapshot exists");
    assert_eq!(owner_after_commit.owner_sequence, 1);
    assert_eq!(owner_after_commit.floor_sequence, 0);
    assert_eq!(owner_after_commit.records.len(), 1);
    let safe_harness_content_record::Payload::AssistantText(safe) = owner_after_commit.records[0]
        .record
        .payload
        .as_ref()
        .expect("safe payload")
    else {
        panic!("safe text")
    };
    assert_eq!(safe.safe_text_utf8, "safe [REDACTED]");
    let pending_outbox = edge.pending_safe_content_projection().expect("safe outbox");
    assert_eq!(pending_outbox.len(), 1);
    assert!(
        edge.acknowledge_safe_content_projection(
            &pending_outbox[0].message_id,
            &pending_outbox[0].payload_digest_sha256,
        )
        .expect("digest-bound ACK")
    );
    assert!(
        !edge
            .acknowledge_safe_content_projection(
                &pending_outbox[0].message_id,
                &pending_outbox[0].payload_digest_sha256,
            )
            .expect("exact ACK replay")
    );
    assert!(
        edge.acknowledge_safe_content_projection(&pending_outbox[0].message_id, &"0".repeat(64))
            .is_err()
    );

    let exact_replay = bound_content_observation(
        &dispatch,
        &binding,
        &receipt,
        "native-content-2",
        2,
        b"raw-content-2",
        candidate,
    );
    edge.append_observation(
        &dispatch.dispatch_id,
        "content-projector-2",
        b"raw-content-2",
        exact_replay,
        15,
    )
    .expect("persist same revision and digest");
    drop(edge);
    let mut projector = GovernedHarnessContentProjector::new(
        open_edge(&database),
        ManagedDisclosureCredentials::managed_unavailable(),
        SystemAdapterClock,
    );
    assert_eq!(
        projector.drain_once().expect("same revision replay"),
        HarnessContentDrain::Replayed
    );
    drop(projector);

    let mut edge = open_edge(&database);
    let conflicting = assistant_text_mutation_candidate(
        "message-projector",
        1,
        0,
        ContentMutationOperation::Append,
        b"different".to_vec(),
        &[],
    )
    .expect("conflicting revision candidate");
    let conflict = bound_content_observation(
        &dispatch,
        &binding,
        &receipt,
        "native-content-3",
        3,
        b"raw-content-3",
        conflicting,
    );
    edge.append_observation(
        &dispatch.dispatch_id,
        "content-projector-3",
        b"raw-content-3",
        conflict,
        16,
    )
    .expect("persist conflicting revision");
    drop(edge);
    let mut projector = GovernedHarnessContentProjector::new(
        open_edge(&database),
        ManagedDisclosureCredentials::managed_unavailable(),
        SystemAdapterClock,
    );
    assert_eq!(
        projector.drain_once().expect("conflict quarantine"),
        HarnessContentDrain::Quarantined {
            reason_code: "CONTENT_REVISION_DIGEST_CONFLICT"
        }
    );
    let inspection = projector.edge().inspect().expect("inspect quarantine");
    assert_eq!(inspection.safe_content_ledger_count, 1);
    assert_eq!(inspection.quarantined_content_candidate_count, 1);
    assert_eq!(
        projector
            .edge()
            .content_owner_snapshot("task-projector")
            .expect("reopened owner snapshot")
            .expect("owner snapshot remains"),
        owner_after_commit
    );
    drop(projector);

    let mut edge = open_edge(&database);
    let compaction_request = ContentRetentionCompactionRequest {
        task_id: "task-projector".to_owned(),
        attempt_id: dispatch.attempt_id.clone(),
        final_epoch: "content-epoch-r9c".to_owned(),
        expected_owner_sequence: 1,
        terminal_committed_at: Timestamp {
            seconds: 100,
            nanos: 7,
        },
        compacted_at: Timestamp {
            seconds: 2_592_100,
            nanos: 7,
        },
    };
    let compacted = edge
        .compact_terminal_safe_content(&compaction_request)
        .expect("atomic owner baseline/floor/delete/tombstone/outbox compaction");
    assert_eq!(compacted.owner_snapshot.owner_sequence, 1);
    assert_eq!(compacted.owner_snapshot.floor_sequence, 1);
    assert!(compacted.owner_snapshot.records.is_empty());
    assert_eq!(
        compacted.owner_snapshot.tombstones.as_slice(),
        std::slice::from_ref(&compacted.tombstone)
    );
    assert_eq!(edge.inspect().unwrap().safe_content_ledger_count, 0);
    let retained = edge
        .retained_safe_content_projection_for_rebuild()
        .expect("typed compaction outbox remains rebuildable");
    assert_eq!(retained.len(), 2);
    assert_eq!(
        edge.content_owner_snapshot("task-projector")
            .expect("compacted owner baseline remains independently readable"),
        Some(compacted.owner_snapshot.clone())
    );
    assert_eq!(
        edge.compact_terminal_safe_content(&compaction_request)
            .expect("exact compaction replay"),
        compacted
    );
    assert!(matches!(
        edge.retained_safe_content_for_rebuild("task-projector", 0)
            .expect("old cursor requires owner baseline"),
        Some(egopulse_harness_adapter::RetainedSafeContent::ResetRequired(snapshot))
            if snapshot == compacted.owner_snapshot
    ));
}

#[test]
fn r9c_structured_candidate_constructors_are_closed_and_payload_free() {
    assert!(
        lifecycle_content_candidate(
            LifecycleKind::ExecutionStarted,
            SideEffectCertainty::NoneProven,
            Some(false),
        )
        .is_some()
    );
    assert!(
        lifecycle_content_candidate(
            LifecycleKind::Unspecified,
            SideEffectCertainty::Unknown,
            None,
        )
        .is_none()
    );
    assert!(usage_content_candidate(3, 5, Some(2)).payload.is_some());
    assert!(approval_required_content_candidate().payload.is_some());
    for allowed in [
        HarnessContentMarkerKind::ForbiddenCategory,
        HarnessContentMarkerKind::UnknownCategory,
    ] {
        let candidate = blocked_source_content_candidate(allowed).expect("closed marker");
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("provider-secret"));
        assert!(!debug.contains("raw payload"));
    }
    assert!(blocked_source_content_candidate(HarnessContentMarkerKind::InvalidText).is_none());
}

#[test]
fn r9c_invalid_context_source_binding_fails_before_mutating_the_signal() {
    let candidate = assistant_text_content_candidate("context-binding", b"safe".to_vec())
        .expect("bounded assistant candidate");
    let observation = HarnessObservation {
        attempt_id: "attempt-context-binding".to_owned(),
        dispatch_id: "dispatch-context-binding".to_owned(),
        fencing_token: 1,
        native_event_id: Some("native-context-binding".to_owned()),
        native_sequence: Some(1),
        native_event_digest_sha256: "a".repeat(64),
        capability_profile_id: "profile-context-binding".to_owned(),
        criticality: ObservationCriticality::Informational as i32,
        ..HarnessObservation::default()
    };
    let mut signal = HarnessContentSignalObservation {
        candidate: Some(candidate),
        ..HarnessContentSignalObservation::default()
    };
    let before = signal.clone();
    assert!(
        bind_content_signal(
            &observation,
            &mut signal,
            "receipt-context-binding",
            &"b".repeat(64),
            &"c".repeat(64),
            DispatchContextConsumptionProof {
                branch: Some(
                    dispatch_context_consumption_proof::Branch::AuthorizedContext(
                        AuthorizedContextConsumptionProof {
                            authorization_id: String::new(),
                            committed_request_digest_sha256: "d".repeat(64),
                        },
                    )
                ),
            },
        )
        .is_err()
    );
    assert_eq!(signal, before, "failed binding must not partially mutate");
}
