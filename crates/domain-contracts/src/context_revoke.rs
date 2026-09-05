//! Contract-frozen semantic confirmation binding for a Founder Context revoke.
//!
//! Strings are hashed as their exact UTF-8 bytes. This module deliberately does
//! not trim, normalize, sort, or otherwise reinterpret client-visible input.

use sha2::{Digest, Sha256};

pub const CONTEXT_REVOKE_SEMANTIC_CONTRACT_ID: &str = "egopulse.context-revoke-confirmation.v1";
pub const CONTEXT_REVOKE_SEMANTIC_CONTRACT_VERSION: &str = "0.1.0";
pub const CONTEXT_REVOKE_SEMANTIC_DOMAIN_SEPARATOR: &str = "egopulse/context-revoke/v1";
pub const CONTEXT_REVOKE_SEMANTIC_PROFILE_DIGEST_SHA256: &str =
    "ee77f4894dfd64394f674d37634a29383bf453dc68494f3d75268e85df2590e4";

#[derive(Clone, Copy, Debug)]
pub struct ContextRevokeSemanticRequest<'a> {
    pub founder_principal_id: &'a str,
    pub snapshot_id: &'a str,
    pub expected_state_revision: u64,
    pub reason_code: &'a str,
    pub evidence_refs: &'a [String],
    pub confirmation_proof_ref: &'a str,
}

impl<'a> ContextRevokeSemanticRequest<'a> {
    /// Returns the canonical bytes frozen by the Context revoke semantic
    /// profile. Every value is framed as `u64_le(byte_length) || value`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        append_field(
            &mut out,
            CONTEXT_REVOKE_SEMANTIC_DOMAIN_SEPARATOR.as_bytes(),
        );
        append_field(&mut out, self.founder_principal_id.as_bytes());
        append_field(&mut out, self.snapshot_id.as_bytes());
        append_field(&mut out, &self.expected_state_revision.to_le_bytes());
        append_field(&mut out, self.reason_code.as_bytes());
        append_field(&mut out, &(self.evidence_refs.len() as u64).to_le_bytes());
        for item in self.evidence_refs {
            append_field(&mut out, item.as_bytes());
        }
        append_field(&mut out, self.confirmation_proof_ref.as_bytes());
        out
    }

    #[must_use]
    pub fn digest_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }
}

fn append_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_BYTES: &[u8] =
        include_bytes!("../../../contracts/profiles/context-revoke/v1/v01-default.json");
    const VALID_LOCAL_API_FIXTURE_BYTES: &[u8] = include_bytes!(
        "../../../contracts/fixtures/localapi/v1/valid-context-revoke-semantic-digest.json"
    );

    #[test]
    fn embedded_profile_digest_and_identity_are_frozen() {
        assert_eq!(
            hex::encode(Sha256::digest(PROFILE_BYTES)),
            CONTEXT_REVOKE_SEMANTIC_PROFILE_DIGEST_SHA256
        );
        let profile: serde_json::Value =
            serde_json::from_slice(PROFILE_BYTES).expect("semantic profile parses");
        assert_eq!(profile["contractId"], CONTEXT_REVOKE_SEMANTIC_CONTRACT_ID);
        assert_eq!(
            profile["contractVersion"],
            CONTEXT_REVOKE_SEMANTIC_CONTRACT_VERSION
        );
        assert_eq!(
            profile["domainSeparator"],
            CONTEXT_REVOKE_SEMANTIC_DOMAIN_SEPARATOR
        );
    }

    #[test]
    fn fixed_contract_vector_matches_independent_expected_bytes_and_digest() {
        let evidence_refs = vec!["evidence:1".to_owned(), "evidence:2".to_owned()];
        let req = ContextRevokeSemanticRequest {
            founder_principal_id: "founder:alice",
            snapshot_id: "ctx:001",
            expected_state_revision: 2,
            reason_code: "withdrawn",
            evidence_refs: &evidence_refs,
            confirmation_proof_ref: "proof:local:1",
        };
        assert_eq!(
            hex::encode(req.canonical_bytes()),
            "1a0000000000000065676f70756c73652f636f6e746578742d7265766f6b652f76310d00000000000000666f756e6465723a616c69636507000000000000006374783a30303108000000000000000200000000000000090000000000000077697468647261776e080000000000000002000000000000000a0000000000000065766964656e63653a310a0000000000000065766964656e63653a320d0000000000000070726f6f663a6c6f63616c3a31"
        );
        assert_eq!(
            req.digest_sha256(),
            "dc1242cf2e4c83e32ee5f95ef8cd6a5b3d8b2e64d8ab875d21ccfbb7604b9a35"
        );
    }

    #[test]
    fn local_api_fixture_is_bound_to_the_same_oracle() {
        let fixture: serde_json::Value =
            serde_json::from_slice(VALID_LOCAL_API_FIXTURE_BYTES).expect("fixture parses");
        let operation = &fixture["operation"]["executeContextMutation"];
        let evidence_refs = operation["evidenceRefs"]
            .as_array()
            .expect("evidence refs")
            .iter()
            .map(|value| value.as_str().expect("evidence ref string").to_owned())
            .collect::<Vec<_>>();
        let request = ContextRevokeSemanticRequest {
            founder_principal_id: fixture["principal"]["principalId"]
                .as_str()
                .expect("Founder principal"),
            snapshot_id: operation["snapshotId"].as_str().expect("snapshot id"),
            expected_state_revision: operation["expectedStateRevision"]
                .as_u64()
                .expect("state revision"),
            reason_code: operation["reasonCode"].as_str().expect("reason code"),
            evidence_refs: &evidence_refs,
            confirmation_proof_ref: operation["confirmationProofRef"]
                .as_str()
                .expect("confirmation proof ref"),
        };
        assert_eq!(
            hex::encode(request.canonical_bytes()),
            operation["canonicalBytesHex"]
                .as_str()
                .expect("canonical fixture bytes")
        );
        assert_eq!(
            request.digest_sha256(),
            operation["requestDigestSha256"]
                .as_str()
                .expect("fixture digest")
        );
    }

    #[test]
    fn every_semantic_field_and_evidence_order_changes_the_digest() {
        fn digest(
            founder_principal_id: &str,
            snapshot_id: &str,
            expected_state_revision: u64,
            reason_code: &str,
            evidence_refs: &[String],
            confirmation_proof_ref: &str,
        ) -> String {
            ContextRevokeSemanticRequest {
                founder_principal_id,
                snapshot_id,
                expected_state_revision,
                reason_code,
                evidence_refs,
                confirmation_proof_ref,
            }
            .digest_sha256()
        }

        let evidence = vec!["evidence:1".to_owned(), "evidence:2".to_owned()];
        let baseline = digest(
            "founder:alice",
            "ctx:001",
            2,
            "withdrawn",
            &evidence,
            "proof:local:1",
        );
        let reversed = vec!["evidence:2".to_owned(), "evidence:1".to_owned()];
        let one_evidence = vec!["evidence:1".to_owned()];
        let variants = [
            digest(
                "founder:bob",
                "ctx:001",
                2,
                "withdrawn",
                &evidence,
                "proof:local:1",
            ),
            digest(
                "founder:alice",
                "ctx:002",
                2,
                "withdrawn",
                &evidence,
                "proof:local:1",
            ),
            digest(
                "founder:alice",
                "ctx:001",
                3,
                "withdrawn",
                &evidence,
                "proof:local:1",
            ),
            digest(
                "founder:alice",
                "ctx:001",
                2,
                "superseded",
                &evidence,
                "proof:local:1",
            ),
            digest(
                "founder:alice",
                "ctx:001",
                2,
                "withdrawn",
                &reversed,
                "proof:local:1",
            ),
            digest(
                "founder:alice",
                "ctx:001",
                2,
                "withdrawn",
                &one_evidence,
                "proof:local:1",
            ),
            digest(
                "founder:alice",
                "ctx:001",
                2,
                "withdrawn",
                &evidence,
                "proof:local:2",
            ),
        ];
        assert!(variants.iter().all(|value| value != &baseline));
    }
}
