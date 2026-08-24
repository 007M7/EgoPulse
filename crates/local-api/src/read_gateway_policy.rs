use std::time::Duration;

use thiserror::Error;

pub const READ_GATEWAY_POLICY_V01: &str = "egopulse.read-gateway-policy/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadGatewayPolicy {
    version: String,
    default_page_size: u32,
    max_page_size: u32,
    minimum_position_wait_timeout: Duration,
    cursor_ttl: Duration,
    await_token_ttl: Duration,
    default_await_timeout: Duration,
    max_await_timeout: Duration,
    retained_sequences: u64,
    compaction_interval_sequences: u64,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReadGatewayPolicyError {
    #[error("read gateway policy is invalid")]
    Invalid,
}

impl ReadGatewayPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: impl Into<String>,
        default_page_size: u32,
        max_page_size: u32,
        minimum_position_wait_timeout: Duration,
        cursor_ttl: Duration,
        await_token_ttl: Duration,
        default_await_timeout: Duration,
        max_await_timeout: Duration,
        retained_sequences: u64,
        compaction_interval_sequences: u64,
    ) -> Result<Self, ReadGatewayPolicyError> {
        let policy = Self {
            version: version.into(),
            default_page_size,
            max_page_size,
            minimum_position_wait_timeout,
            cursor_ttl,
            await_token_ttl,
            default_await_timeout,
            max_await_timeout,
            retained_sequences,
            compaction_interval_sequences,
        };
        policy.validate()?;
        Ok(policy)
    }

    #[must_use]
    pub fn v01() -> Self {
        Self::new(
            READ_GATEWAY_POLICY_V01,
            50,
            200,
            Duration::from_secs(5),
            Duration::from_secs(30 * 60),
            Duration::from_secs(5 * 60),
            Duration::from_secs(5),
            Duration::from_secs(30),
            10_000,
            1_000,
        )
        .expect("the frozen v0.1 read gateway policy is valid")
    }

    fn validate(&self) -> Result<(), ReadGatewayPolicyError> {
        if self.version.is_empty()
            || self.version.len() > 128
            || self.version.chars().any(char::is_control)
            || self.default_page_size == 0
            || self.max_page_size < self.default_page_size
            || self.minimum_position_wait_timeout.is_zero()
            || self.cursor_ttl.is_zero()
            || self.await_token_ttl.is_zero()
            || self.default_await_timeout.is_zero()
            || self.max_await_timeout < self.default_await_timeout
            || self.retained_sequences == 0
            || self.compaction_interval_sequences == 0
            || self.compaction_interval_sequences > self.retained_sequences
        {
            Err(ReadGatewayPolicyError::Invalid)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn default_page_size(&self) -> u32 {
        self.default_page_size
    }

    #[must_use]
    pub const fn max_page_size(&self) -> u32 {
        self.max_page_size
    }

    #[must_use]
    pub const fn minimum_position_wait_timeout(&self) -> Duration {
        self.minimum_position_wait_timeout
    }

    #[must_use]
    pub const fn effective_page_size(&self, requested: u32) -> u32 {
        if requested == 0 {
            self.default_page_size
        } else if requested > self.max_page_size {
            self.max_page_size
        } else {
            requested
        }
    }

    #[must_use]
    pub const fn cursor_ttl(&self) -> Duration {
        self.cursor_ttl
    }

    #[must_use]
    pub const fn await_token_ttl(&self) -> Duration {
        self.await_token_ttl
    }

    #[must_use]
    pub const fn default_await_timeout(&self) -> Duration {
        self.default_await_timeout
    }

    #[must_use]
    pub const fn max_await_timeout(&self) -> Duration {
        self.max_await_timeout
    }

    #[must_use]
    pub fn effective_await_timeout(&self, requested_milliseconds: u32) -> Duration {
        if requested_milliseconds == 0 {
            self.default_await_timeout
        } else {
            Duration::from_millis(u64::from(requested_milliseconds)).min(self.max_await_timeout)
        }
    }

    #[must_use]
    pub const fn retained_sequences(&self) -> u64 {
        self.retained_sequences
    }

    #[must_use]
    pub const fn compaction_interval_sequences(&self) -> u64 {
        self.compaction_interval_sequences
    }

    #[must_use]
    pub const fn retention_floor(&self, current_sequence: u64) -> u64 {
        current_sequence.saturating_sub(self.retained_sequences)
    }

    #[must_use]
    pub const fn should_compact(
        &self,
        last_compacted_sequence: u64,
        current_sequence: u64,
    ) -> bool {
        match current_sequence.checked_sub(last_compacted_sequence) {
            Some(delta) => delta >= self.compaction_interval_sequences,
            None => false,
        }
    }
}

impl Default for ReadGatewayPolicy {
    fn default() -> Self {
        Self::v01()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v01_freezes_one_consistent_policy_boundary() {
        let policy = ReadGatewayPolicy::v01();
        assert_eq!(policy.version(), READ_GATEWAY_POLICY_V01);
        assert_eq!(policy.effective_page_size(0), 50);
        assert_eq!(policy.effective_page_size(1), 1);
        assert_eq!(policy.effective_page_size(200), 200);
        assert_eq!(policy.effective_page_size(201), 200);
        assert_eq!(
            policy.minimum_position_wait_timeout(),
            Duration::from_secs(5)
        );
        assert_eq!(policy.cursor_ttl(), Duration::from_secs(1_800));
        assert_eq!(policy.await_token_ttl(), Duration::from_secs(300));
        assert_eq!(policy.effective_await_timeout(0), Duration::from_secs(5));
        assert_eq!(policy.effective_await_timeout(1), Duration::from_millis(1));
        assert_eq!(
            policy.effective_await_timeout(30_001),
            Duration::from_secs(30)
        );
        assert_eq!(policy.retention_floor(9_999), 0);
        assert_eq!(policy.retention_floor(10_001), 1);
        assert!(!policy.should_compact(5_000, 5_999));
        assert!(policy.should_compact(5_000, 6_000));
        assert!(!policy.should_compact(6_000, 5_000));
    }

    #[test]
    fn incoherent_replacement_policy_is_rejected() {
        assert_eq!(
            ReadGatewayPolicy::new(
                "test/v1",
                50,
                49,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(1),
                1_000,
                1_001,
            ),
            Err(ReadGatewayPolicyError::Invalid)
        );
    }
}
