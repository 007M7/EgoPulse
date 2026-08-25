use std::sync::{Arc, Mutex};

use egopulse_artifact_authority::{
    ArtifactAdmissionGuard, ArtifactAuthority, ArtifactAuthorityFailure, ArtifactClock,
};
use egopulse_domain_contracts::v01::egopulse::artifact::v1::{
    ArtifactDescriptor, ArtifactSet, Claim, Evidence,
};
use egopulse_verification_authority::{ArtifactReferenceSource, ArtifactReferenceSourceError};

/// Read-only adapter from the Artifact Authority's shared owner handle to the
/// Verification Authority reference boundary.
///
/// The adapter deliberately exposes decoded snapshots only. Verification
/// cannot obtain the Artifact Authority store, blob store, guard, or writer
/// handle through this type. All reads use the one owner handle opened by the
/// composition root, so a second database connection cannot observe or repair
/// a different state.
pub struct ArtifactAuthorityReferenceSource<G, C> {
    authority: Arc<Mutex<ArtifactAuthority<G, C>>>,
}

impl<G, C> ArtifactAuthorityReferenceSource<G, C>
where
    G: ArtifactAdmissionGuard,
    C: ArtifactClock,
{
    #[must_use]
    pub fn new(authority: ArtifactAuthority<G, C>) -> Self {
        Self::new_shared(Arc::new(Mutex::new(authority)))
    }

    #[must_use]
    pub fn new_shared(authority: Arc<Mutex<ArtifactAuthority<G, C>>>) -> Self {
        Self { authority }
    }
}

impl<G, C> ArtifactReferenceSource for ArtifactAuthorityReferenceSource<G, C>
where
    G: ArtifactAdmissionGuard + Send + 'static,
    C: ArtifactClock + Send + 'static,
{
    fn read_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactDescriptor>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_artifact(artifact_id)
            .map_err(map_authority_failure)
    }

    fn read_claim(&self, claim_id: &str) -> Result<Option<Claim>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_claim(claim_id)
            .map_err(map_authority_failure)
    }

    fn read_evidence(
        &self,
        evidence_id: &str,
    ) -> Result<Option<Evidence>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_evidence(evidence_id)
            .map_err(map_authority_failure)
    }

    fn read_artifact_set(
        &self,
        artifact_set_id: &str,
    ) -> Result<Option<ArtifactSet>, ArtifactReferenceSourceError> {
        self.authority
            .lock()
            .map_err(|_| ArtifactReferenceSourceError::Unavailable)?
            .read_artifact_set(artifact_set_id)
            .map_err(map_authority_failure)
    }
}

fn map_authority_failure(error: ArtifactAuthorityFailure) -> ArtifactReferenceSourceError {
    match error {
        ArtifactAuthorityFailure::Storage => ArtifactReferenceSourceError::Unavailable,
        ArtifactAuthorityFailure::Blob(_) | ArtifactAuthorityFailure::Decode(_) => {
            ArtifactReferenceSourceError::Corrupt
        }
    }
}
