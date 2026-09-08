//! Saved confirmation arguments grant no authority; replay uses a fresh session.
use super::{ClientAttachment, ClientWorkError, ConfirmedWork, is_canonical_sha256};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableReworkConfirmation {
    schema: String,
    principal_id: String,
    epoch: String,
    task_id: String,
    snapshot_id: String,
    binding: String,
    key: String,
}

impl DurableReworkConfirmation {
    pub fn capture(
        client: &ClientAttachment,
        task_id: String,
        snapshot_id: String,
        binding: String,
        key: String,
    ) -> Result<Self, ClientWorkError> {
        let session = client
            .kernel
            .session()
            .ok_or(ClientWorkError::Protocol("session unavailable"))?;
        let record = Self {
            schema: "egopulse.client-rework-confirmation/v1".to_owned(),
            principal_id: session.authenticated_principal_id.clone(),
            epoch: session.current_position.epoch.clone(),
            task_id,
            snapshot_id,
            binding,
            key,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), ClientWorkError> {
        if self.schema != "egopulse.client-rework-confirmation/v1"
            || [&self.principal_id, &self.epoch, &self.task_id, &self.key]
                .iter()
                .any(|value| {
                    value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
                })
            || !self
                .snapshot_id
                .strip_prefix("ctx:")
                .is_some_and(is_canonical_sha256)
            || !is_canonical_sha256(&self.binding)
        {
            return Err(ClientWorkError::Protocol(
                "invalid saved Rework confirmation",
            ));
        }
        Ok(())
    }

    pub fn write_new(&self, path: &Path) -> Result<(), ClientWorkError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ClientWorkError::Protocol("recovery serialization failed"))?;
        super::recovery_store::write_new(&bytes, path).map_err(|_| {
            ClientWorkError::Protocol("Rework recovery could not be saved; confirmation not sent")
        })
    }

    pub fn read(path: &Path) -> Result<Self, ClientWorkError> {
        let bytes = super::recovery_store::read(path)
            .map_err(|_| ClientWorkError::Protocol("Rework recovery could not be read"))?;
        let record: Self = serde_json::from_slice(&bytes)
            .map_err(|_| ClientWorkError::Protocol("invalid Rework recovery record"))?;
        record.validate()?;
        Ok(record)
    }

    pub async fn replay(
        &self,
        client: &ClientAttachment,
    ) -> Result<ConfirmedWork, ClientWorkError> {
        self.validate()?;
        let session = client
            .kernel
            .session()
            .ok_or(ClientWorkError::Protocol("session unavailable"))?;
        if self.principal_id != session.authenticated_principal_id
            || self.epoch != session.current_position.epoch
        {
            return Err(ClientWorkError::Protocol(
                "Rework recovery belongs to another principal or store",
            ));
        }
        let confirmed = client
            .confirm_rework(
                self.task_id.clone(),
                self.snapshot_id.clone(),
                self.binding.clone(),
                self.key.clone(),
            )
            .await?;
        if let Some(super::task_command_result::Outcome::Task(task)) =
            confirmed.result.outcome.as_ref()
            && (task.task_id != self.task_id || task.input_snapshot_id != self.snapshot_id)
        {
            return Err(ClientWorkError::Protocol(
                "Rework recovery response changed the confirmed binding",
            ));
        }
        Ok(confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_rework_confirmation_roundtrips_and_rejects_modified_envelope() {
        let directory = tempfile::tempdir().expect("temporary recovery directory");
        let path = directory.path().join("rework.json");
        let record = DurableReworkConfirmation {
            schema: "egopulse.client-rework-confirmation/v1".to_owned(),
            principal_id: "founder:test".to_owned(),
            epoch: "store:test".to_owned(),
            task_id: "task:existing".to_owned(),
            snapshot_id: format!("ctx:{}", "a".repeat(64)),
            binding: "b".repeat(64),
            key: "confirm:exact".to_owned(),
        };
        record.write_new(&path).expect("protected record");
        let restored = DurableReworkConfirmation::read(&path).expect("restore record");
        assert_eq!(restored.task_id, record.task_id);
        assert_eq!(restored.snapshot_id, record.snapshot_id);
        assert_eq!(restored.binding, record.binding);
        assert_eq!(restored.key, record.key);
        assert!(
            record.write_new(&path).is_err(),
            "never overwrite a saved operation"
        );
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read envelope"))
                .expect("envelope");
        envelope["protected_payload_hex"] = serde_json::Value::String("00".to_owned());
        std::fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("encode envelope"),
        )
        .expect("tamper fixture");
        assert!(DurableReworkConfirmation::read(&path).is_err());
    }
}
