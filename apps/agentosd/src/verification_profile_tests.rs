use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use egopulse_artifact_authority::ArtifactAuthority;
use egopulse_domain_contracts::v01::egopulse::{
    artifact::v1::ArtifactDescriptor,
    verification::v1::{CheckerAssuranceClass, CheckerProfile, CriterionRequirement},
};
use egopulse_verification_authority::{
    ArtifactBackedReferenceResolver, CriterionPolicySnapshot, VerificationAuthority,
    VerificationAuthorityConfig, VerificationSqlCipherKey,
};

use crate::{
    ArtifactAuthorityReferenceSource, ConfiguredArtifactAdmissionGuard,
    verification_material_tests::{
        Fixture, open_artifact, profile_attestation_transformation_ref,
        profile_attestation_type_ref, reference,
    },
    verification_profile::{
        PreparedRepositoryCheckerProfiles, RepositoryCheckerDeploymentConfig,
        RepositoryCheckerDeploymentPreparer, RepositoryCheckerProfileDeployment,
        RepositoryCheckerRole,
    },
};

const SCOPE_PROFILE_ID: &str = "checker-profile:repository-scope:v1";
const TESTS_PROFILE_ID: &str = "checker-profile:repository-tests:v1";
const REVIEW_PROFILE_ID: &str = "checker-profile:repository-review:v1";

#[tokio::test]
async fn two_real_task_lineages_reuse_three_profiles_without_growing_attestations() {
    let fixture = Fixture::new().await;
    let second_binding = fixture.seed_second_task().await;
    let first_material = fixture
        .resolver()
        .resolve(&fixture.binding, unix_seconds())
        .expect("first verified Task material");
    let second_material = fixture
        .resolver()
        .resolve(&second_binding, unix_seconds())
        .expect("second verified Task material");
    assert_ne!(
        first_material.binding.lineage, second_material.binding.lineage,
        "the reuse path must be exercised by independent Task lineage"
    );

    let verification = open_verification(fixture.root.path(), Arc::clone(&fixture.artifact));
    let preparer = profile_preparer(
        Arc::clone(&fixture.artifact),
        fixture.admission.clone(),
        Arc::clone(&verification),
    );
    let first = preparer
        .prepare_for(&first_material, timestamp())
        .expect("first deployment creates three profiles");
    let first_attestations = attestation_snapshots(&fixture.artifact);
    let second = preparer
        .prepare_for(&second_material, timestamp())
        .expect("second Task reuses immutable profiles");
    let second_attestations = attestation_snapshots(&fixture.artifact);

    assert_profiles_identical(&first, &second);
    assert_eq!(first_attestations, second_attestations);
    assert_eq!(second_attestations.len(), 3);
}

#[tokio::test]
async fn reopened_artifact_and_verification_owners_reuse_the_same_profiles() {
    let fixture = Fixture::new().await;
    let second_binding = fixture.seed_second_task().await;
    let first_material = fixture
        .resolver()
        .resolve(&fixture.binding, unix_seconds())
        .expect("first verified Task material");
    let second_material = fixture
        .resolver()
        .resolve(&second_binding, unix_seconds())
        .expect("second verified Task material");
    let verification = open_verification(fixture.root.path(), Arc::clone(&fixture.artifact));
    let preparer = profile_preparer(
        Arc::clone(&fixture.artifact),
        fixture.admission.clone(),
        Arc::clone(&verification),
    );
    let first = preparer
        .prepare_for(&first_material, timestamp())
        .expect("initial profile deployment");
    let second = preparer
        .prepare_for(&second_material, timestamp())
        .expect("second Task profile replay");
    assert_profiles_identical(&first, &second);
    let before_restart = attestation_snapshots(&fixture.artifact);

    drop(preparer);
    drop(verification);
    let acceptance_ref = fixture.frozen.acceptance_contract_ref();
    let policy = fixture.policy.clone();
    let Fixture {
        root,
        context,
        artifact,
        admission,
        workspace_base: _,
        contract_path: _,
        policy: _,
        binding: _,
        frozen: _,
    } = fixture;
    drop(context);
    drop(admission);
    drop(artifact);

    let (artifact, admission) = open_artifact(root.path(), &policy, &acceptance_ref);
    let verification = open_verification(root.path(), Arc::clone(&artifact));
    let reopened = profile_preparer(Arc::clone(&artifact), admission, Arc::clone(&verification))
        .prepare_for(&second_material, timestamp())
        .expect("reopened owners reuse immutable profiles");
    let after_restart = attestation_snapshots(&artifact);

    assert_profiles_identical(&first, &reopened);
    assert_eq!(before_restart, after_restart);
    assert_eq!(after_restart.len(), 3);
}

fn open_verification(
    root: &Path,
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
) -> Arc<Mutex<VerificationAuthority>> {
    let resolver = ArtifactBackedReferenceResolver::new(
        ArtifactAuthorityReferenceSource::new_shared(artifact),
        vec![
            criterion(
                "scope",
                CheckerAssuranceClass::Deterministic,
                SCOPE_PROFILE_ID,
            ),
            criterion(
                "tests",
                CheckerAssuranceClass::Deterministic,
                TESTS_PROFILE_ID,
            ),
            criterion(
                "review",
                CheckerAssuranceClass::ModelAssisted,
                REVIEW_PROFILE_ID,
            ),
        ],
    )
    .expect("profile fixture reference resolver");
    Arc::new(Mutex::new(
        VerificationAuthority::open(
            VerificationAuthorityConfig {
                database_path: root.join("verification-profile.db"),
                store_epoch: "verification-profile-reuse".to_owned(),
                key: VerificationSqlCipherKey::new([0x73; 32]),
            },
            resolver,
        )
        .expect("Verification Authority"),
    ))
}

fn criterion(
    id: &str,
    assurance: CheckerAssuranceClass,
    profile_id: &str,
) -> CriterionPolicySnapshot {
    CriterionPolicySnapshot {
        criterion_id: id.to_owned(),
        requirement: CriterionRequirement::MustPass as i32,
        minimum_assurance: assurance as i32,
        not_applicable_allowed: false,
        checker_profile_ids: vec![profile_id.to_owned()],
    }
}

fn profile_preparer(
    artifact: Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
    admission: crate::artifact::DerivedWorkspaceAdmissionHandle,
    verification: Arc<Mutex<VerificationAuthority>>,
) -> RepositoryCheckerDeploymentPreparer {
    RepositoryCheckerDeploymentPreparer::new(artifact, admission, verification, profile_config())
        .expect("profile deployment preparer")
}

fn profile_config() -> RepositoryCheckerDeploymentConfig {
    RepositoryCheckerDeploymentConfig {
        scope: deployment(RepositoryCheckerRole::Scope, SCOPE_PROFILE_ID),
        tests: deployment(RepositoryCheckerRole::Tests, TESTS_PROFILE_ID),
        review: deployment(RepositoryCheckerRole::Review, REVIEW_PROFILE_ID),
        attestation_type_ref: profile_attestation_type_ref(),
        attestation_transformation_ref: profile_attestation_transformation_ref(),
        retention_profile_ref: reference("repository-retention", 0x41),
        governed_collector_principal_id: "collector:repository".to_owned(),
        artifact_authority_principal_id: "authority:artifact".to_owned(),
        sensitivity_class: "local-user-data".to_owned(),
    }
}

fn deployment(role: RepositoryCheckerRole, profile_id: &str) -> RepositoryCheckerProfileDeployment {
    let suffix = match role {
        RepositoryCheckerRole::Scope => "scope",
        RepositoryCheckerRole::Tests => "tests",
        RepositoryCheckerRole::Review => "review",
    };
    RepositoryCheckerProfileDeployment {
        role,
        checker_profile_id: profile_id.to_owned(),
        input_contract_ref: reference(&format!("repository-{suffix}-input"), 0x81),
        output_contract_ref: reference(&format!("repository-{suffix}-output"), 0x82),
        sandbox_profile_ref: reference("readonly-repository-sandbox", 0x83),
        tool_policy_ref: reference(&format!("repository-{suffix}-tools"), 0x84),
        data_egress_policy_ref: reference("repository-local-only", 0x85),
        budget_profile_ref: reference(&format!("repository-{suffix}-budget"), 0x86),
        timeout_ms: 30_000,
        model: (role == RepositoryCheckerRole::Review).then(|| "codex-review-fixture".to_owned()),
    }
}

fn attestation_snapshots(
    artifact: &Arc<Mutex<ArtifactAuthority<ConfiguredArtifactAdmissionGuard>>>,
) -> Vec<ArtifactDescriptor> {
    let authority = artifact.lock().expect("Artifact lock");
    [SCOPE_PROFILE_ID, TESTS_PROFILE_ID, REVIEW_PROFILE_ID]
        .into_iter()
        .map(|profile_id| {
            authority
                .read_artifact(&format!(
                    "artifact:checker-profile-attestation:{profile_id}"
                ))
                .expect("read attestation Artifact")
                .expect("attestation Artifact exists")
        })
        .collect()
}

fn assert_profiles_identical(
    expected: &PreparedRepositoryCheckerProfiles,
    actual: &PreparedRepositoryCheckerProfiles,
) {
    assert_profile_identical(&expected.scope, &actual.scope);
    assert_profile_identical(&expected.tests, &actual.tests);
    assert_profile_identical(&expected.review, &actual.review);
}

fn assert_profile_identical(expected: &CheckerProfile, actual: &CheckerProfile) {
    assert_eq!(actual, expected);
    assert_eq!(actual.revision, 1);
    assert_eq!(actual.attestation_evidence_artifact_ids.len(), 1);
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs()
        .try_into()
        .expect("timestamp range")
}

fn timestamp() -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: unix_seconds(),
        nanos: 0,
    }
}
