use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use egopulse_domain_contracts::v01::egopulse::{
    common::v1::ContractReference,
    localapi::v1::{
        HarnessContentPosition, ProjectionAwaitToken, ProjectionPosition, SourceDomain,
        SourceRevision,
    },
};
use hmac::{Hmac, Mac};
use prost_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    read_gateway_policy::ReadGatewayPolicy,
    session::{AuthenticatedSession, SessionClock},
};

type HmacSha256 = Hmac<Sha256>;

const CURSOR_TOKEN_PREFIX: &str = "c1";
const CONTENT_CURSOR_TOKEN_PREFIX: &str = "hc1";
const AWAIT_TOKEN_PREFIX: &str = "a1";
const CURSOR_SCHEMA: &str = "egopulse.read-cursor/v1";
const CONTENT_CURSOR_SCHEMA: &str = "egopulse.harness-content-cursor/v1";
const AWAIT_SCHEMA: &str = "egopulse.projection-await/v1";
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_PERMISSION_CODE_BYTES: usize = 128;
const MAX_CONTENT_PAGE_SIZE: u32 = 256;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReadTokenError {
    #[error("read token configuration is invalid")]
    InvalidConfiguration,
    #[error("read token input is invalid")]
    InvalidInput,
    #[error("read token is invalid")]
    InvalidToken,
    #[error("read token has expired")]
    Expired,
    #[error("read token scope does not match")]
    ScopeMismatch,
    #[error("read token binding does not match")]
    BindingMismatch,
    #[error("read token is outside the retained projection range")]
    ResetRequired,
}

/// A 256-bit MAC key supplied by the governed key provider. This type stores and
/// clears key bytes; it deliberately does not generate or persist product keys.
pub struct TokenMacKey(Zeroizing<[u8; 32]>);

impl TokenMacKey {
    pub fn new(key: [u8; 32]) -> Result<Self, ReadTokenError> {
        if key.iter().all(|byte| *byte == 0) {
            Err(ReadTokenError::InvalidConfiguration)
        } else {
            Ok(Self(Zeroizing::new(key)))
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadTokenScope {
    principal_id: String,
    scope_sha256: String,
}

impl ReadTokenScope {
    /// Builds a surface-neutral scope. Session/client identifiers are intentionally
    /// excluded so a short-lived token can survive reconnects and move between the
    /// CLI, TUI, and Desktop while the principal and governed capability set stay equal.
    pub fn from_session(session: &AuthenticatedSession) -> Result<Self, ReadTokenError> {
        validate_identifier(&session.authenticated_principal_id)?;
        validate_permissions(&session.permission_codes)?;
        validate_contract_reference(&session.authorization_policy_ref)?;
        validate_contract_reference(&session.negotiated_contract_ref)?;
        validate_contract_reference(&session.client_kernel_contract_ref)?;

        let material = ScopeMaterial {
            permission_codes: session
                .permission_codes
                .iter()
                .map(String::as_str)
                .collect(),
            authorization_policy_ref: ContractMaterial::from(&session.authorization_policy_ref),
            negotiated_contract_ref: ContractMaterial::from(&session.negotiated_contract_ref),
            client_kernel_contract_ref: ContractMaterial::from(&session.client_kernel_contract_ref),
        };
        let encoded = serde_json::to_vec(&material).map_err(|_| ReadTokenError::InvalidInput)?;
        Ok(Self {
            principal_id: session.authenticated_principal_id.clone(),
            scope_sha256: format!("{:x}", Sha256::digest(encoded)),
        })
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    #[must_use]
    pub fn scope_sha256(&self) -> &str {
        &self.scope_sha256
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScopeMaterial<'a> {
    permission_codes: Vec<&'a str>,
    authorization_policy_ref: ContractMaterial<'a>,
    negotiated_contract_ref: ContractMaterial<'a>,
    client_kernel_contract_ref: ContractMaterial<'a>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ContractMaterial<'a> {
    contract_id: &'a str,
    version: &'a str,
    sha256: &'a str,
}

impl<'a> From<&'a ContractReference> for ContractMaterial<'a> {
    fn from(reference: &'a ContractReference) -> Self {
        Self {
            contract_id: &reference.contract_id,
            version: &reference.version,
            sha256: &reference.sha256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorCollection {
    TaskViews,
    HarnessApprovalViews,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorSort {
    TaskUpdatedAtDescTaskIdAsc,
    ApprovalProjectionSequenceDescApprovalRequestIdAsc,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CursorAnchor {
    Task {
        updated_at_seconds: i64,
        updated_at_nanos: i32,
        task_id: String,
    },
    HarnessApproval {
        projection_sequence: u64,
        approval_request_id: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CursorIssue {
    pub collection: CursorCollection,
    pub filter_sha256: String,
    pub sort: CursorSort,
    pub effective_page_size: u32,
    pub snapshot_position: ProjectionPosition,
    pub anchor: CursorAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorExpectation {
    pub collection: CursorCollection,
    pub filter_sha256: String,
    pub sort: CursorSort,
    pub effective_page_size: u32,
    pub current_epoch: String,
    pub retention_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCursor {
    pub collection: CursorCollection,
    pub filter_sha256: String,
    pub sort: CursorSort,
    pub effective_page_size: u32,
    pub snapshot_epoch: String,
    pub snapshot_sequence: u64,
    pub anchor: CursorAnchor,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    schema: String,
    policy_version: String,
    principal_id: String,
    scope_sha256: String,
    collection: CursorCollection,
    filter_sha256: String,
    sort: CursorSort,
    effective_page_size: u32,
    snapshot_epoch: String,
    snapshot_sequence: u64,
    anchor: CursorAnchor,
    issued_at: SignedInstant,
    expires_at: SignedInstant,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContentCursorIssue {
    pub filter_sha256: String,
    pub effective_page_size: u32,
    pub snapshot_position: HarnessContentPosition,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentCursorExpectation {
    pub filter_sha256: String,
    pub effective_page_size: u32,
    pub current_epoch: String,
    pub retention_floor: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedContentCursor {
    pub filter_sha256: String,
    pub effective_page_size: u32,
    pub snapshot_epoch: String,
    pub snapshot_sequence: u64,
    pub snapshot_projected_at: Option<Timestamp>,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContentCursorPayload {
    schema: String,
    policy_version: String,
    principal_id: String,
    scope_sha256: String,
    filter_sha256: String,
    effective_page_size: u32,
    snapshot_epoch: String,
    snapshot_sequence: u64,
    snapshot_projected_at: Option<SignedInstant>,
    last_sequence: u64,
    issued_at: SignedInstant,
    expires_at: SignedInstant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwaitTarget {
    Task { task_id: String },
    HarnessApproval { approval_request_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAwaitToken {
    pub required_source_revision: SourceRevision,
    pub target: AwaitTarget,
    pub expires_at: Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AwaitPayload {
    schema: String,
    policy_version: String,
    principal_id: String,
    scope_sha256: String,
    required_source_revision: SignedSourceRevision,
    target: AwaitTarget,
    issued_at: SignedInstant,
    expires_at: SignedInstant,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedSourceRevision {
    domain: i32,
    aggregate_id: String,
    revision: u64,
    last_event_id: String,
}

impl From<&SourceRevision> for SignedSourceRevision {
    fn from(source: &SourceRevision) -> Self {
        Self {
            domain: source.domain,
            aggregate_id: source.aggregate_id.clone(),
            revision: source.revision,
            last_event_id: source.last_event_id.clone(),
        }
    }
}

impl From<SignedSourceRevision> for SourceRevision {
    fn from(source: SignedSourceRevision) -> Self {
        Self {
            domain: source.domain,
            aggregate_id: source.aggregate_id,
            revision: source.revision,
            last_event_id: source.last_event_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedInstant {
    seconds: i64,
    nanos: i32,
}

impl SignedInstant {
    fn from_system_time(time: SystemTime) -> Result<Self, ReadTokenError> {
        let duration = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReadTokenError::InvalidConfiguration)?;
        Ok(Self {
            seconds: i64::try_from(duration.as_secs())
                .map_err(|_| ReadTokenError::InvalidConfiguration)?,
            nanos: i32::try_from(duration.subsec_nanos())
                .map_err(|_| ReadTokenError::InvalidConfiguration)?,
        })
    }

    fn to_system_time(self) -> Result<SystemTime, ReadTokenError> {
        if self.seconds < 0 || !(0..1_000_000_000).contains(&self.nanos) {
            return Err(ReadTokenError::InvalidToken);
        }
        UNIX_EPOCH
            .checked_add(Duration::new(
                u64::try_from(self.seconds).map_err(|_| ReadTokenError::InvalidToken)?,
                u32::try_from(self.nanos).map_err(|_| ReadTokenError::InvalidToken)?,
            ))
            .ok_or(ReadTokenError::InvalidToken)
    }

    fn to_timestamp(self) -> Timestamp {
        Timestamp {
            seconds: self.seconds,
            nanos: self.nanos,
        }
    }

    fn from_timestamp(value: &Timestamp) -> Result<Self, ReadTokenError> {
        if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
            return Err(ReadTokenError::InvalidInput);
        }
        Ok(Self {
            seconds: value.seconds,
            nanos: value.nanos,
        })
    }
}

pub struct ReadTokenCodec {
    key: TokenMacKey,
    policy: ReadGatewayPolicy,
    clock: Arc<dyn SessionClock>,
}

impl ReadTokenCodec {
    #[must_use]
    pub fn new(key: TokenMacKey, policy: ReadGatewayPolicy, clock: Arc<dyn SessionClock>) -> Self {
        Self { key, policy, clock }
    }

    #[must_use]
    pub fn policy(&self) -> &ReadGatewayPolicy {
        &self.policy
    }

    pub fn issue_cursor(
        &self,
        scope: &ReadTokenScope,
        issue: CursorIssue,
    ) -> Result<String, ReadTokenError> {
        validate_scope(scope)?;
        validate_cursor_binding(
            issue.collection,
            &issue.filter_sha256,
            issue.sort,
            issue.effective_page_size,
            &issue.snapshot_position.epoch,
            &issue.anchor,
            self.policy.max_page_size(),
        )?;
        let issued_at_time = self.clock.now();
        let expires_at_time = issued_at_time
            .checked_add(self.policy.cursor_ttl())
            .ok_or(ReadTokenError::InvalidConfiguration)?;
        let payload = CursorPayload {
            schema: CURSOR_SCHEMA.to_owned(),
            policy_version: self.policy.version().to_owned(),
            principal_id: scope.principal_id.clone(),
            scope_sha256: scope.scope_sha256.clone(),
            collection: issue.collection,
            filter_sha256: issue.filter_sha256,
            sort: issue.sort,
            effective_page_size: issue.effective_page_size,
            snapshot_epoch: issue.snapshot_position.epoch,
            snapshot_sequence: issue.snapshot_position.sequence,
            anchor: issue.anchor,
            issued_at: SignedInstant::from_system_time(issued_at_time)?,
            expires_at: SignedInstant::from_system_time(expires_at_time)?,
        };
        self.sign_payload(CURSOR_TOKEN_PREFIX, &payload)
    }

    pub fn verify_cursor(
        &self,
        token: &str,
        scope: &ReadTokenScope,
        expected: &CursorExpectation,
    ) -> Result<VerifiedCursor, ReadTokenError> {
        validate_scope(scope)?;
        validate_cursor_expectation(expected, self.policy.max_page_size())?;
        let bytes = self.verify_signed(CURSOR_TOKEN_PREFIX, token)?;
        let payload: CursorPayload =
            serde_json::from_slice(&bytes).map_err(|_| ReadTokenError::InvalidToken)?;
        if payload.schema != CURSOR_SCHEMA || payload.policy_version != self.policy.version() {
            return Err(ReadTokenError::BindingMismatch);
        }
        validate_cursor_binding(
            payload.collection,
            &payload.filter_sha256,
            payload.sort,
            payload.effective_page_size,
            &payload.snapshot_epoch,
            &payload.anchor,
            self.policy.max_page_size(),
        )
        .map_err(|_| ReadTokenError::InvalidToken)?;
        validate_lifetime(
            payload.issued_at,
            payload.expires_at,
            self.policy.cursor_ttl(),
            self.clock.now(),
        )?;
        if payload.principal_id != scope.principal_id || payload.scope_sha256 != scope.scope_sha256
        {
            return Err(ReadTokenError::ScopeMismatch);
        }
        if payload.collection != expected.collection
            || payload.filter_sha256 != expected.filter_sha256
            || payload.sort != expected.sort
            || payload.effective_page_size != expected.effective_page_size
        {
            return Err(ReadTokenError::BindingMismatch);
        }
        if payload.snapshot_epoch != expected.current_epoch
            || payload.snapshot_sequence < expected.retention_floor
        {
            return Err(ReadTokenError::ResetRequired);
        }
        Ok(VerifiedCursor {
            collection: payload.collection,
            filter_sha256: payload.filter_sha256,
            sort: payload.sort,
            effective_page_size: payload.effective_page_size,
            snapshot_epoch: payload.snapshot_epoch,
            snapshot_sequence: payload.snapshot_sequence,
            anchor: payload.anchor,
        })
    }

    pub fn issue_content_cursor(
        &self,
        scope: &ReadTokenScope,
        issue: ContentCursorIssue,
    ) -> Result<String, ReadTokenError> {
        validate_scope(scope)?;
        validate_content_cursor_binding(
            &issue.filter_sha256,
            issue.effective_page_size,
            &issue.snapshot_position.epoch,
            issue.snapshot_position.sequence,
            issue.snapshot_position.projected_at.as_ref(),
            issue.last_sequence,
        )?;
        let issued_at_time = self.clock.now();
        let expires_at_time = issued_at_time
            .checked_add(self.policy.cursor_ttl())
            .ok_or(ReadTokenError::InvalidConfiguration)?;
        self.sign_payload(
            CONTENT_CURSOR_TOKEN_PREFIX,
            &ContentCursorPayload {
                schema: CONTENT_CURSOR_SCHEMA.to_owned(),
                policy_version: self.policy.version().to_owned(),
                principal_id: scope.principal_id.clone(),
                scope_sha256: scope.scope_sha256.clone(),
                filter_sha256: issue.filter_sha256,
                effective_page_size: issue.effective_page_size,
                snapshot_epoch: issue.snapshot_position.epoch,
                snapshot_sequence: issue.snapshot_position.sequence,
                snapshot_projected_at: issue
                    .snapshot_position
                    .projected_at
                    .as_ref()
                    .map(SignedInstant::from_timestamp)
                    .transpose()?,
                last_sequence: issue.last_sequence,
                issued_at: SignedInstant::from_system_time(issued_at_time)?,
                expires_at: SignedInstant::from_system_time(expires_at_time)?,
            },
        )
    }

    pub fn verify_content_cursor(
        &self,
        token: &str,
        scope: &ReadTokenScope,
        expected: &ContentCursorExpectation,
    ) -> Result<VerifiedContentCursor, ReadTokenError> {
        validate_scope(scope)?;
        validate_content_cursor_expectation(expected)?;
        let bytes = self.verify_signed(CONTENT_CURSOR_TOKEN_PREFIX, token)?;
        let payload: ContentCursorPayload =
            serde_json::from_slice(&bytes).map_err(|_| ReadTokenError::InvalidToken)?;
        if payload.schema != CONTENT_CURSOR_SCHEMA
            || payload.policy_version != self.policy.version()
        {
            return Err(ReadTokenError::BindingMismatch);
        }
        validate_content_cursor_binding(
            &payload.filter_sha256,
            payload.effective_page_size,
            &payload.snapshot_epoch,
            payload.snapshot_sequence,
            payload
                .snapshot_projected_at
                .map(SignedInstant::to_timestamp)
                .as_ref(),
            payload.last_sequence,
        )
        .map_err(|_| ReadTokenError::InvalidToken)?;
        validate_lifetime(
            payload.issued_at,
            payload.expires_at,
            self.policy.cursor_ttl(),
            self.clock.now(),
        )?;
        if payload.principal_id != scope.principal_id || payload.scope_sha256 != scope.scope_sha256
        {
            return Err(ReadTokenError::ScopeMismatch);
        }
        if payload.filter_sha256 != expected.filter_sha256
            || payload.effective_page_size != expected.effective_page_size
        {
            return Err(ReadTokenError::BindingMismatch);
        }
        if payload.snapshot_epoch != expected.current_epoch
            || payload.snapshot_sequence < expected.retention_floor
            || payload.last_sequence < expected.retention_floor
        {
            return Err(ReadTokenError::ResetRequired);
        }
        Ok(VerifiedContentCursor {
            filter_sha256: payload.filter_sha256,
            effective_page_size: payload.effective_page_size,
            snapshot_epoch: payload.snapshot_epoch,
            snapshot_sequence: payload.snapshot_sequence,
            snapshot_projected_at: payload
                .snapshot_projected_at
                .map(SignedInstant::to_timestamp),
            last_sequence: payload.last_sequence,
        })
    }

    pub fn issue_await_token(
        &self,
        scope: &ReadTokenScope,
        required_source_revision: SourceRevision,
        target: AwaitTarget,
    ) -> Result<ProjectionAwaitToken, ReadTokenError> {
        validate_scope(scope)?;
        validate_source_revision(&required_source_revision)?;
        validate_await_target(&target)?;
        let issued_at_time = self.clock.now();
        let expires_at_time = issued_at_time
            .checked_add(self.policy.await_token_ttl())
            .ok_or(ReadTokenError::InvalidConfiguration)?;
        let expires_at = SignedInstant::from_system_time(expires_at_time)?;
        let payload = AwaitPayload {
            schema: AWAIT_SCHEMA.to_owned(),
            policy_version: self.policy.version().to_owned(),
            principal_id: scope.principal_id.clone(),
            scope_sha256: scope.scope_sha256.clone(),
            required_source_revision: SignedSourceRevision::from(&required_source_revision),
            target,
            issued_at: SignedInstant::from_system_time(issued_at_time)?,
            expires_at,
        };
        Ok(ProjectionAwaitToken {
            token: self.sign_payload(AWAIT_TOKEN_PREFIX, &payload)?,
            required_source_revision: Some(required_source_revision),
            expires_at: Some(expires_at.to_timestamp()),
        })
    }

    pub fn verify_await_token(
        &self,
        token: &ProjectionAwaitToken,
        scope: &ReadTokenScope,
    ) -> Result<VerifiedAwaitToken, ReadTokenError> {
        validate_scope(scope)?;
        let bytes = self.verify_signed(AWAIT_TOKEN_PREFIX, &token.token)?;
        let payload: AwaitPayload =
            serde_json::from_slice(&bytes).map_err(|_| ReadTokenError::InvalidToken)?;
        if payload.schema != AWAIT_SCHEMA || payload.policy_version != self.policy.version() {
            return Err(ReadTokenError::BindingMismatch);
        }
        let signed_source: SourceRevision = payload.required_source_revision.clone().into();
        validate_source_revision(&signed_source).map_err(|_| ReadTokenError::InvalidToken)?;
        validate_await_target(&payload.target).map_err(|_| ReadTokenError::InvalidToken)?;
        validate_lifetime(
            payload.issued_at,
            payload.expires_at,
            self.policy.await_token_ttl(),
            self.clock.now(),
        )?;
        if payload.principal_id != scope.principal_id || payload.scope_sha256 != scope.scope_sha256
        {
            return Err(ReadTokenError::ScopeMismatch);
        }
        let visible_source = token
            .required_source_revision
            .as_ref()
            .ok_or(ReadTokenError::InvalidToken)?;
        let visible_expiry = token
            .expires_at
            .as_ref()
            .ok_or(ReadTokenError::InvalidToken)?;
        if visible_source != &signed_source || visible_expiry != &payload.expires_at.to_timestamp()
        {
            return Err(ReadTokenError::BindingMismatch);
        }
        Ok(VerifiedAwaitToken {
            required_source_revision: signed_source,
            target: payload.target,
            expires_at: payload.expires_at.to_timestamp(),
        })
    }

    fn sign_payload<T: Serialize>(
        &self,
        prefix: &str,
        payload: &T,
    ) -> Result<String, ReadTokenError> {
        let payload = serde_json::to_vec(payload).map_err(|_| ReadTokenError::InvalidInput)?;
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
        let mut mac = HmacSha256::new_from_slice(self.key.as_bytes())
            .map_err(|_| ReadTokenError::InvalidConfiguration)?;
        mac.update(prefix.as_bytes());
        mac.update(b".");
        mac.update(encoded_payload.as_bytes());
        let encoded_tag = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(format!("{prefix}.{encoded_payload}.{encoded_tag}"))
    }

    fn verify_signed(&self, prefix: &str, token: &str) -> Result<Vec<u8>, ReadTokenError> {
        let mut segments = token.split('.');
        let actual_prefix = segments.next().ok_or(ReadTokenError::InvalidToken)?;
        let encoded_payload = segments.next().ok_or(ReadTokenError::InvalidToken)?;
        let encoded_tag = segments.next().ok_or(ReadTokenError::InvalidToken)?;
        if segments.next().is_some()
            || actual_prefix != prefix
            || encoded_payload.is_empty()
            || encoded_tag.is_empty()
        {
            return Err(ReadTokenError::InvalidToken);
        }
        let tag = URL_SAFE_NO_PAD
            .decode(encoded_tag)
            .map_err(|_| ReadTokenError::InvalidToken)?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_bytes())
            .map_err(|_| ReadTokenError::InvalidConfiguration)?;
        mac.update(prefix.as_bytes());
        mac.update(b".");
        mac.update(encoded_payload.as_bytes());
        mac.verify_slice(&tag)
            .map_err(|_| ReadTokenError::InvalidToken)?;
        URL_SAFE_NO_PAD
            .decode(encoded_payload)
            .map_err(|_| ReadTokenError::InvalidToken)
    }
}

fn validate_lifetime(
    issued_at: SignedInstant,
    expires_at: SignedInstant,
    expected_ttl: Duration,
    now: SystemTime,
) -> Result<(), ReadTokenError> {
    let issued_at = issued_at.to_system_time()?;
    let expires_at = expires_at.to_system_time()?;
    if expires_at.duration_since(issued_at).ok() != Some(expected_ttl) {
        return Err(ReadTokenError::InvalidToken);
    }
    if now < issued_at {
        return Err(ReadTokenError::InvalidToken);
    }
    if now >= expires_at {
        Err(ReadTokenError::Expired)
    } else {
        Ok(())
    }
}

fn validate_scope(scope: &ReadTokenScope) -> Result<(), ReadTokenError> {
    validate_identifier(&scope.principal_id)?;
    if !is_sha256(&scope.scope_sha256) {
        Err(ReadTokenError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_cursor_expectation(
    expected: &CursorExpectation,
    max_page_size: u32,
) -> Result<(), ReadTokenError> {
    if !is_sha256(&expected.filter_sha256)
        || expected.effective_page_size == 0
        || expected.effective_page_size > max_page_size
    {
        return Err(ReadTokenError::InvalidInput);
    }
    validate_identifier(&expected.current_epoch)?;
    validate_collection_sort(expected.collection, expected.sort)
}

fn validate_cursor_binding(
    collection: CursorCollection,
    filter_sha256: &str,
    sort: CursorSort,
    effective_page_size: u32,
    snapshot_epoch: &str,
    anchor: &CursorAnchor,
    max_page_size: u32,
) -> Result<(), ReadTokenError> {
    if !is_sha256(filter_sha256) || effective_page_size == 0 || effective_page_size > max_page_size
    {
        return Err(ReadTokenError::InvalidInput);
    }
    validate_identifier(snapshot_epoch)?;
    validate_collection_sort(collection, sort)?;
    match (collection, anchor) {
        (
            CursorCollection::TaskViews,
            CursorAnchor::Task {
                updated_at_nanos,
                task_id,
                ..
            },
        ) if (0..1_000_000_000).contains(updated_at_nanos) => validate_identifier(task_id),
        (
            CursorCollection::HarnessApprovalViews,
            CursorAnchor::HarnessApproval {
                approval_request_id,
                ..
            },
        ) => validate_identifier(approval_request_id),
        _ => Err(ReadTokenError::InvalidInput),
    }
}

fn validate_content_cursor_expectation(
    expected: &ContentCursorExpectation,
) -> Result<(), ReadTokenError> {
    if !is_sha256(&expected.filter_sha256)
        || expected.effective_page_size == 0
        || expected.effective_page_size > MAX_CONTENT_PAGE_SIZE
    {
        return Err(ReadTokenError::InvalidInput);
    }
    validate_identifier(&expected.current_epoch)
}

fn validate_content_cursor_binding(
    filter_sha256: &str,
    effective_page_size: u32,
    snapshot_epoch: &str,
    snapshot_sequence: u64,
    snapshot_projected_at: Option<&Timestamp>,
    last_sequence: u64,
) -> Result<(), ReadTokenError> {
    if !is_sha256(filter_sha256)
        || effective_page_size == 0
        || effective_page_size > MAX_CONTENT_PAGE_SIZE
        || last_sequence > snapshot_sequence
        || snapshot_projected_at
            .is_some_and(|value| value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos))
    {
        return Err(ReadTokenError::InvalidInput);
    }
    validate_identifier(snapshot_epoch)
}

fn validate_collection_sort(
    collection: CursorCollection,
    sort: CursorSort,
) -> Result<(), ReadTokenError> {
    if matches!(
        (collection, sort),
        (
            CursorCollection::TaskViews,
            CursorSort::TaskUpdatedAtDescTaskIdAsc
        ) | (
            CursorCollection::HarnessApprovalViews,
            CursorSort::ApprovalProjectionSequenceDescApprovalRequestIdAsc
        )
    ) {
        Ok(())
    } else {
        Err(ReadTokenError::InvalidInput)
    }
}

fn validate_source_revision(source: &SourceRevision) -> Result<(), ReadTokenError> {
    let domain = SourceDomain::try_from(source.domain).map_err(|_| ReadTokenError::InvalidInput)?;
    if domain == SourceDomain::Unspecified || source.revision == 0 {
        return Err(ReadTokenError::InvalidInput);
    }
    validate_identifier(&source.aggregate_id)?;
    validate_identifier(&source.last_event_id)
}

fn validate_await_target(target: &AwaitTarget) -> Result<(), ReadTokenError> {
    match target {
        AwaitTarget::Task { task_id } => validate_identifier(task_id),
        AwaitTarget::HarnessApproval {
            approval_request_id,
        } => validate_identifier(approval_request_id),
    }
}

fn validate_permissions(permission_codes: &BTreeSet<String>) -> Result<(), ReadTokenError> {
    if permission_codes.is_empty()
        || permission_codes.iter().any(|code| {
            code.is_empty()
                || code.len() > MAX_PERMISSION_CODE_BYTES
                || !code.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-')
                })
        })
    {
        Err(ReadTokenError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_contract_reference(reference: &ContractReference) -> Result<(), ReadTokenError> {
    validate_identifier(&reference.contract_id)?;
    validate_identifier(&reference.version)?;
    if is_sha256(&reference.sha256) {
        Ok(())
    } else {
        Err(ReadTokenError::InvalidInput)
    }
}

fn validate_identifier(value: &str) -> Result<(), ReadTokenError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        Err(ReadTokenError::InvalidInput)
    } else {
        Ok(())
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
