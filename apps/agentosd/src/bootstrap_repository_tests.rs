use super::{
    ConfiguredArtifactAdmissionGuardConfig, GovernedReturnCollectorConfig,
    ProductionBootstrapError, validate_repository_claim_binding,
};
use egopulse_domain_contracts::v01::egopulse::common::v1::ContractReference;
use std::collections::BTreeSet;

fn reference(id: &str, version: &str, byte: char) -> ContractReference {
    ContractReference {
        contract_id: id.to_owned(),
        version: version.to_owned(),
        sha256: byte.to_string().repeat(64),
    }
}

fn guard(
    semantics: Vec<ContractReference>,
    acceptances: Vec<ContractReference>,
) -> ConfiguredArtifactAdmissionGuardConfig {
    ConfiguredArtifactAdmissionGuardConfig {
        allowed_workspace_refs: BTreeSet::from(["workspace:repository".to_owned()]),
        allowed_artifact_type_refs: vec![reference("artifact", "v1", 'a')],
        allowed_transformation_contract_refs: vec![reference("transform", "v1", 'b')],
        allowed_retention_profile_refs: vec![reference("retention", "v1", 'c')],
        allowed_claim_semantic_profile_refs: semantics,
        allowed_claim_acceptance_contract_refs: acceptances,
        allowed_evidence_profile_refs: vec![reference("evidence", "v1", 'd')],
    }
}

fn collector(
    semantic: ContractReference,
    acceptance: ContractReference,
) -> GovernedReturnCollectorConfig {
    GovernedReturnCollectorConfig {
        artifact_type_ref: reference("artifact", "v1", 'a'),
        transformation_contract_ref: reference("transform", "v1", 'b'),
        retention_profile_ref: reference("retention", "v1", 'c'),
        claim_semantic_profile_ref: semantic,
        claim_acceptance_contract_ref: acceptance,
        evidence_profile_ref: reference("evidence", "v1", 'd'),
        workspace_ref: "workspace:repository".to_owned(),
        collector_principal_id: "collector:repository".to_owned(),
        artifact_authority_principal_id: "authority:artifact".to_owned(),
    }
}

#[test]
fn repository_claim_binding_uses_explicit_d02_profile_regardless_of_allowlist_order() {
    let d02 = reference("repository_change_acceptance", "v1", '1');
    let other = reference("other_claim_profile", "v1", '2');
    let acceptance = reference("repository_acceptance", "v3", '3');
    let other_acceptance = reference("other_acceptance", "v1", '4');

    for (semantics, acceptances) in [
        (
            vec![other.clone(), d02.clone()],
            vec![other_acceptance.clone(), acceptance.clone()],
        ),
        (
            vec![d02.clone(), other.clone()],
            vec![acceptance.clone(), other_acceptance.clone()],
        ),
    ] {
        let policy = guard(semantics, acceptances);
        let configured = collector(d02.clone(), acceptance.clone());
        validate_repository_claim_binding(&policy, &acceptance, &configured)
            .expect("an explicit D-02 binding must not depend on allowlist order");
    }
}

#[test]
fn repository_claim_binding_rejects_wrong_semantic_identity_version_digest_or_acceptance_ref() {
    let d02 = reference("repository_change_acceptance", "v1", '1');
    let acceptance = reference("repository_acceptance", "v3", '3');
    let other_acceptance = reference("other_acceptance", "v1", '4');
    let policy = guard(
        vec![d02.clone(), reference("other_claim_profile", "v1", '2')],
        vec![acceptance.clone(), other_acceptance.clone()],
    );

    for configured in [
        collector(
            reference("other_claim_profile", "v1", '2'),
            acceptance.clone(),
        ),
        collector(
            reference("repository_change_acceptance", "v2", '1'),
            acceptance.clone(),
        ),
        collector(
            reference("repository_change_acceptance", "v1", '9'),
            acceptance.clone(),
        ),
        collector(d02.clone(), other_acceptance),
    ] {
        assert!(matches!(
            validate_repository_claim_binding(&policy, &acceptance, &configured),
            Err(ProductionBootstrapError::InvalidConfiguration(_))
        ));
    }
}
