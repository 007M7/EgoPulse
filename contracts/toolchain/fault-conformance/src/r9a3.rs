use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PROTOCOL_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u32 = 1;
pub const WITNESS_FILE_NAME: &str = "r9a3-side-effect-witness.db";
pub const MAX_FRAME_BYTES: usize = 4_096;

const MAX_IDENTIFIER_BYTES: usize = 128;
const SHA256_HEX_BYTES: usize = 64;
const REQUEST_FRAME_MAGIC: &[u8; 8] = b"R9A3REQ1";
const ACK_FRAME_MAGIC: &[u8; 8] = b"R9A3ACK1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R9a3ErrorKind {
    InvalidInput,
    Conflict,
    Storage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R9a3Error {
    kind: R9a3ErrorKind,
    message: String,
}

impl R9a3Error {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: R9a3ErrorKind::InvalidInput,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: R9a3ErrorKind::Conflict,
            message: message.into(),
        }
    }

    fn storage(message: impl Into<String>) -> Self {
        Self {
            kind: R9a3ErrorKind::Storage,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> R9a3ErrorKind {
        self.kind
    }
}

impl fmt::Display for R9a3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for R9a3Error {}

impl From<rusqlite::Error> for R9a3Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::storage(format!("R-9A.3 SQLite failure: {error}"))
    }
}

impl From<std::io::Error> for R9a3Error {
    fn from(error: std::io::Error) -> Self {
        Self::storage(format!("R-9A.3 filesystem failure: {error}"))
    }
}

pub type R9a3Result<T> = Result<T, R9a3Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRequest {
    pub protocol_version: u16,
    pub operation_id: String,
    pub dispatch_id: String,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub request_digest_sha256: String,
    pub payload_digest_sha256: String,
}

impl SendRequest {
    pub fn validate(&self) -> R9a3Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(R9a3Error::invalid("unsupported R-9A.3 protocol version"));
        }
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("dispatch_id", &self.dispatch_id)?;
        validate_identifier("attempt_id", &self.attempt_id)?;
        if self.fencing_token == 0 || self.fencing_token > i64::MAX as u64 {
            return Err(R9a3Error::invalid("fencing_token must be in 1..=i64::MAX"));
        }
        validate_digest("request_digest_sha256", &self.request_digest_sha256)?;
        validate_digest("payload_digest_sha256", &self.payload_digest_sha256)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendAck {
    pub protocol_version: u16,
    pub effect_id: String,
    pub durable_sequence: u64,
    pub operation_id: String,
    pub dispatch_id: String,
    pub attempt_id: String,
    pub fencing_token: u64,
    pub request_digest_sha256: String,
    pub payload_digest_sha256: String,
    pub replayed: bool,
}

impl SendAck {
    pub fn validate(&self) -> R9a3Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(R9a3Error::invalid("unsupported R-9A.3 ACK version"));
        }
        validate_effect_id(&self.effect_id)?;
        if self.durable_sequence == 0 || self.durable_sequence > i64::MAX as u64 {
            return Err(R9a3Error::invalid(
                "durable_sequence must be in 1..=i64::MAX",
            ));
        }
        validate_identifier("operation_id", &self.operation_id)?;
        validate_identifier("dispatch_id", &self.dispatch_id)?;
        validate_identifier("attempt_id", &self.attempt_id)?;
        if self.fencing_token == 0 || self.fencing_token > i64::MAX as u64 {
            return Err(R9a3Error::invalid(
                "ACK fencing_token must be in 1..=i64::MAX",
            ));
        }
        validate_digest("request_digest_sha256", &self.request_digest_sha256)?;
        validate_digest("payload_digest_sha256", &self.payload_digest_sha256)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SideEffect {
    pub effect_id: String,
    pub durable_sequence: u64,
    pub request: SendRequest,
}

impl SideEffect {
    pub fn original_ack(&self) -> SendAck {
        SendAck {
            protocol_version: self.request.protocol_version,
            effect_id: self.effect_id.clone(),
            durable_sequence: self.durable_sequence,
            operation_id: self.request.operation_id.clone(),
            dispatch_id: self.request.dispatch_id.clone(),
            attempt_id: self.request.attempt_id.clone(),
            fencing_token: self.request.fencing_token,
            request_digest_sha256: self.request.request_digest_sha256.clone(),
            payload_digest_sha256: self.request.payload_digest_sha256.clone(),
            replayed: false,
        }
    }

    fn validate(&self) -> R9a3Result<()> {
        self.request.validate()?;
        let ack = self.original_ack();
        ack.validate()?;
        if self.effect_id != effect_id_for(&self.request) {
            return Err(R9a3Error::storage(
                "stored effect_id does not match the immutable request",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SideEffectWriter {
    database_path: PathBuf,
    root_identity: String,
    instance: String,
}

impl SideEffectWriter {
    pub fn initialize(root: &Path, instance: &str) -> R9a3Result<Self> {
        validate_identifier("instance", instance)?;
        fs::create_dir_all(root)?;
        let root_identity = canonical_root(root)?;
        let database_path = root.join(WITNESS_FILE_NAME);
        let mut connection = Connection::open(&database_path)?;
        configure_new_writer(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS witness_identity(
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               schema_version INTEGER NOT NULL,
               witness_root TEXT NOT NULL,
               witness_instance TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS effects(
               durable_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
               effect_id TEXT NOT NULL UNIQUE,
               protocol_version INTEGER NOT NULL,
               operation_id TEXT NOT NULL UNIQUE,
               dispatch_id TEXT NOT NULL UNIQUE,
               attempt_id TEXT NOT NULL,
               fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
               request_digest_sha256 TEXT NOT NULL,
               payload_digest_sha256 TEXT NOT NULL
             ) STRICT;",
        )?;
        let identity: Option<(i64, String, String)> = transaction
            .query_row(
                "SELECT schema_version, witness_root, witness_instance
                 FROM witness_identity WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match identity {
            None => {
                transaction.execute(
                    "INSERT INTO witness_identity(
                       singleton, schema_version, witness_root, witness_instance
                     ) VALUES(1, ?1, ?2, ?3)",
                    params![i64::from(SCHEMA_VERSION), root_identity, instance],
                )?;
            }
            Some((schema, stored_root, stored_instance))
                if schema == i64::from(SCHEMA_VERSION)
                    && stored_root == root_identity
                    && stored_instance == instance => {}
            Some(_) => {
                transaction.rollback()?;
                return Err(R9a3Error::conflict(
                    "R-9A.3 witness identity or schema does not match",
                ));
            }
        }
        transaction.commit()?;
        Ok(Self {
            database_path,
            root_identity,
            instance: instance.to_owned(),
        })
    }

    pub fn commit_effect(&self, request: &SendRequest) -> R9a3Result<SendAck> {
        request.validate()?;
        let mut connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_existing_writer(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_identity(&transaction, &self.root_identity, &self.instance)?;
        let matches = load_matching_effects(&transaction, request)?;
        if !matches.is_empty() {
            if matches.len() == 1 && matches[0].request == *request {
                let mut ack = matches[0].original_ack();
                ack.replayed = true;
                transaction.commit()?;
                return Ok(ack);
            }
            transaction.rollback()?;
            return Err(R9a3Error::conflict(
                "operation_id or dispatch_id already names a different side effect",
            ));
        }

        let effect_id = effect_id_for(request);
        transaction.execute(
            "INSERT INTO effects(
               effect_id, protocol_version, operation_id, dispatch_id, attempt_id,
               fencing_token, request_digest_sha256, payload_digest_sha256
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                effect_id,
                i64::from(request.protocol_version),
                request.operation_id,
                request.dispatch_id,
                request.attempt_id,
                request.fencing_token as i64,
                request.request_digest_sha256,
                request.payload_digest_sha256,
            ],
        )?;
        let durable_sequence = u64::try_from(transaction.last_insert_rowid())
            .map_err(|_| R9a3Error::storage("SQLite returned an invalid durable sequence"))?;
        let effect = SideEffect {
            effect_id,
            durable_sequence,
            request: request.clone(),
        };
        effect.validate()?;
        transaction.commit()?;
        Ok(effect.original_ack())
    }
}

#[derive(Clone, Debug)]
pub struct SideEffectReader {
    database_path: PathBuf,
    root_identity: String,
    instance: String,
}

impl SideEffectReader {
    pub fn open_existing(root: &Path, instance: &str) -> R9a3Result<Self> {
        validate_identifier("instance", instance)?;
        let root_identity = canonical_root(root)?;
        let reader = Self {
            database_path: root.join(WITNESS_FILE_NAME),
            root_identity,
            instance: instance.to_owned(),
        };
        let _ = reader.open()?;
        Ok(reader)
    }

    pub fn effect_count(&self) -> R9a3Result<u64> {
        let connection = self.open()?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM effects", [], |row| row.get(0))?;
        u64::try_from(count).map_err(|_| R9a3Error::storage("effect count is negative"))
    }

    pub fn effect_for_dispatch(&self, dispatch_id: &str) -> R9a3Result<Option<SideEffect>> {
        validate_identifier("dispatch_id", dispatch_id)?;
        let connection = self.open()?;
        load_effect_by(&connection, "dispatch_id", dispatch_id)
    }

    pub fn effect_for_operation(&self, operation_id: &str) -> R9a3Result<Option<SideEffect>> {
        validate_identifier("operation_id", operation_id)?;
        let connection = self.open()?;
        load_effect_by(&connection, "operation_id", operation_id)
    }

    pub fn all_effects(&self) -> R9a3Result<Vec<SideEffect>> {
        let connection = self.open()?;
        let mut statement = connection.prepare(
            "SELECT durable_sequence, effect_id, protocol_version, operation_id,
                    dispatch_id, attempt_id, fencing_token, request_digest_sha256,
                    payload_digest_sha256
             FROM effects ORDER BY durable_sequence",
        )?;
        let effects = statement
            .query_map([], effect_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        validate_effects(effects)
    }

    fn open(&self) -> R9a3Result<Connection> {
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "query_only", "ON")?;
        let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
        if query_only != 1 {
            return Err(R9a3Error::storage(
                "R-9A.3 reader did not enter query-only mode",
            ));
        }
        validate_identity(&connection, &self.root_identity, &self.instance)?;
        Ok(connection)
    }
}

fn canonical_root(root: &Path) -> R9a3Result<String> {
    Ok(fs::canonicalize(root)?.display().to_string())
}

fn configure_new_writer(connection: &Connection) -> R9a3Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    assert_wal(connection)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    assert_synchronous_full(connection)
}

fn configure_existing_writer(connection: &Connection) -> R9a3Result<()> {
    connection.busy_timeout(Duration::from_secs(5))?;
    assert_wal(connection)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    assert_synchronous_full(connection)
}

fn assert_wal(connection: &Connection) -> R9a3Result<()> {
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(R9a3Error::storage(
            "R-9A.3 existing witness is not in WAL mode",
        ));
    }
    Ok(())
}

fn assert_synchronous_full(connection: &Connection) -> R9a3Result<()> {
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if synchronous != 2 {
        return Err(R9a3Error::storage(
            "R-9A.3 writer did not enter synchronous FULL mode",
        ));
    }
    Ok(())
}

pub fn encode_send_request_frame(request: &SendRequest) -> R9a3Result<Vec<u8>> {
    request.validate()?;
    let payload_capacity = checked_encoded_payload_len(
        8 + 2 + 8,
        [
            request.operation_id.len(),
            request.dispatch_id.len(),
            request.attempt_id.len(),
            request.request_digest_sha256.len(),
            request.payload_digest_sha256.len(),
        ],
    )?;
    let mut payload = Vec::with_capacity(payload_capacity);
    payload.extend_from_slice(REQUEST_FRAME_MAGIC);
    payload.extend_from_slice(&request.protocol_version.to_be_bytes());
    push_string(&mut payload, &request.operation_id)?;
    push_string(&mut payload, &request.dispatch_id)?;
    push_string(&mut payload, &request.attempt_id)?;
    payload.extend_from_slice(&request.fencing_token.to_be_bytes());
    push_string(&mut payload, &request.request_digest_sha256)?;
    push_string(&mut payload, &request.payload_digest_sha256)?;
    wrap_frame(payload)
}

pub fn decode_send_request_frame(frame: &[u8]) -> R9a3Result<SendRequest> {
    let payload = checked_payload(frame, REQUEST_FRAME_MAGIC)?;
    let mut cursor = FrameCursor::new(payload);
    let request = SendRequest {
        protocol_version: cursor.take_u16()?,
        operation_id: cursor.take_string()?,
        dispatch_id: cursor.take_string()?,
        attempt_id: cursor.take_string()?,
        fencing_token: cursor.take_u64()?,
        request_digest_sha256: cursor.take_string()?,
        payload_digest_sha256: cursor.take_string()?,
    };
    cursor.finish()?;
    request.validate()?;
    Ok(request)
}

pub fn write_send_request_frame<W: Write>(writer: &mut W, request: &SendRequest) -> R9a3Result<()> {
    writer.write_all(&encode_send_request_frame(request)?)?;
    Ok(())
}

pub fn read_send_request_frame<R: Read>(reader: &mut R) -> R9a3Result<SendRequest> {
    let frame = read_bounded_frame(reader)?;
    decode_send_request_frame(&frame)
}

pub fn encode_send_ack_frame(ack: &SendAck) -> R9a3Result<Vec<u8>> {
    ack.validate()?;
    let payload_capacity = checked_encoded_payload_len(
        8 + 2 + 8 + 8 + 1,
        [
            ack.effect_id.len(),
            ack.operation_id.len(),
            ack.dispatch_id.len(),
            ack.attempt_id.len(),
            ack.request_digest_sha256.len(),
            ack.payload_digest_sha256.len(),
        ],
    )?;
    let mut payload = Vec::with_capacity(payload_capacity);
    payload.extend_from_slice(ACK_FRAME_MAGIC);
    payload.extend_from_slice(&ack.protocol_version.to_be_bytes());
    push_string(&mut payload, &ack.effect_id)?;
    payload.extend_from_slice(&ack.durable_sequence.to_be_bytes());
    push_string(&mut payload, &ack.operation_id)?;
    push_string(&mut payload, &ack.dispatch_id)?;
    push_string(&mut payload, &ack.attempt_id)?;
    payload.extend_from_slice(&ack.fencing_token.to_be_bytes());
    push_string(&mut payload, &ack.request_digest_sha256)?;
    push_string(&mut payload, &ack.payload_digest_sha256)?;
    payload.push(u8::from(ack.replayed));
    wrap_frame(payload)
}

pub fn decode_send_ack_frame(frame: &[u8]) -> R9a3Result<SendAck> {
    let payload = checked_payload(frame, ACK_FRAME_MAGIC)?;
    let mut cursor = FrameCursor::new(payload);
    let ack = SendAck {
        protocol_version: cursor.take_u16()?,
        effect_id: cursor.take_string()?,
        durable_sequence: cursor.take_u64()?,
        operation_id: cursor.take_string()?,
        dispatch_id: cursor.take_string()?,
        attempt_id: cursor.take_string()?,
        fencing_token: cursor.take_u64()?,
        request_digest_sha256: cursor.take_string()?,
        payload_digest_sha256: cursor.take_string()?,
        replayed: match cursor.take_u8()? {
            0 => false,
            1 => true,
            _ => return Err(R9a3Error::invalid("ACK replayed flag must be 0 or 1")),
        },
    };
    cursor.finish()?;
    ack.validate()?;
    Ok(ack)
}

pub fn write_send_ack_frame<W: Write>(writer: &mut W, ack: &SendAck) -> R9a3Result<()> {
    writer.write_all(&encode_send_ack_frame(ack)?)?;
    Ok(())
}

pub fn read_send_ack_frame<R: Read>(reader: &mut R) -> R9a3Result<SendAck> {
    let frame = read_bounded_frame(reader)?;
    decode_send_ack_frame(&frame)
}

fn wrap_frame(payload: Vec<u8>) -> R9a3Result<Vec<u8>> {
    let frame_len = payload
        .len()
        .checked_add(4)
        .ok_or_else(|| R9a3Error::invalid("R-9A.3 frame length overflow"))?;
    if frame_len > MAX_FRAME_BYTES {
        return Err(R9a3Error::invalid("R-9A.3 frame exceeds MAX_FRAME_BYTES"));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| R9a3Error::invalid("R-9A.3 frame payload is too large"))?;
    let mut frame = Vec::with_capacity(frame_len);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn checked_encoded_payload_len<const N: usize>(
    fixed_payload_bytes: usize,
    string_lengths: [usize; N],
) -> R9a3Result<usize> {
    let payload_len = string_lengths
        .into_iter()
        .try_fold(fixed_payload_bytes, |total, len| {
            total
                .checked_add(2)
                .and_then(|value| value.checked_add(len))
        })
        .ok_or_else(|| R9a3Error::invalid("R-9A.3 frame length overflow"))?;
    let frame_len = payload_len
        .checked_add(4)
        .ok_or_else(|| R9a3Error::invalid("R-9A.3 frame length overflow"))?;
    if frame_len > MAX_FRAME_BYTES {
        return Err(R9a3Error::invalid("R-9A.3 frame exceeds MAX_FRAME_BYTES"));
    }
    Ok(payload_len)
}

fn checked_payload<'a>(frame: &'a [u8], magic: &[u8; 8]) -> R9a3Result<&'a [u8]> {
    if frame.len() < 4 {
        return Err(R9a3Error::invalid("R-9A.3 frame is truncated"));
    }
    let declared = u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
    let total = declared
        .checked_add(4)
        .ok_or_else(|| R9a3Error::invalid("R-9A.3 frame length overflow"))?;
    if total > MAX_FRAME_BYTES {
        return Err(R9a3Error::invalid("R-9A.3 frame exceeds MAX_FRAME_BYTES"));
    }
    if frame.len() != total {
        return Err(R9a3Error::invalid(
            "R-9A.3 frame length does not match its prefix",
        ));
    }
    frame[4..]
        .strip_prefix(magic)
        .ok_or_else(|| R9a3Error::invalid("R-9A.3 frame kind is invalid"))
}

fn read_bounded_frame<R: Read>(reader: &mut R) -> R9a3Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix)?;
    let declared = u32::from_be_bytes(prefix) as usize;
    let total = declared
        .checked_add(4)
        .ok_or_else(|| R9a3Error::invalid("R-9A.3 frame length overflow"))?;
    if total > MAX_FRAME_BYTES {
        return Err(R9a3Error::invalid("R-9A.3 frame exceeds MAX_FRAME_BYTES"));
    }
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&prefix);
    frame.resize(total, 0);
    reader.read_exact(&mut frame[4..])?;
    Ok(frame)
}

fn push_string(buffer: &mut Vec<u8>, value: &str) -> R9a3Result<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| R9a3Error::invalid("R-9A.3 frame string is too long"))?;
    buffer.extend_from_slice(&len.to_be_bytes());
    buffer.extend_from_slice(value.as_bytes());
    Ok(())
}

struct FrameCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> FrameCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, len: usize) -> R9a3Result<&'a [u8]> {
        if self.remaining.len() < len {
            return Err(R9a3Error::invalid("R-9A.3 frame is truncated"));
        }
        let (value, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(value)
    }

    fn take_u8(&mut self) -> R9a3Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> R9a3Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two-byte value"),
        ))
    }

    fn take_u64(&mut self) -> R9a3Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight-byte value"),
        ))
    }

    fn take_string(&mut self) -> R9a3Result<String> {
        let len = usize::from(self.take_u16()?);
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| R9a3Error::invalid("R-9A.3 frame string is not UTF-8"))
    }

    fn finish(self) -> R9a3Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(R9a3Error::invalid("R-9A.3 frame has trailing bytes"))
        }
    }
}

fn validate_identity(
    connection: &Connection,
    root_identity: &str,
    instance: &str,
) -> R9a3Result<()> {
    let identity: (i64, String, String) = connection.query_row(
        "SELECT schema_version, witness_root, witness_instance
         FROM witness_identity WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if identity
        != (
            i64::from(SCHEMA_VERSION),
            root_identity.to_owned(),
            instance.to_owned(),
        )
    {
        return Err(R9a3Error::conflict(
            "R-9A.3 witness identity or schema does not match",
        ));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> R9a3Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(R9a3Error::invalid(format!(
            "{label} must contain 1..={MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(R9a3Error::invalid(format!(
            "{label} contains whitespace, control, or unsupported bytes"
        )));
    }
    Ok(())
}

fn validate_digest(label: &str, value: &str) -> R9a3Result<()> {
    if value.len() != SHA256_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(R9a3Error::invalid(format!(
            "{label} must be exactly 64 lowercase hexadecimal bytes"
        )));
    }
    Ok(())
}

fn validate_effect_id(value: &str) -> R9a3Result<()> {
    let digest = value
        .strip_prefix("r9a3-effect-")
        .ok_or_else(|| R9a3Error::invalid("effect_id has an invalid prefix"))?;
    validate_digest("effect_id digest", digest)
}

fn effect_id_for(request: &SendRequest) -> String {
    let mut hasher = Sha256::new();
    for value in [
        request.operation_id.as_bytes(),
        request.dispatch_id.as_bytes(),
        request.attempt_id.as_bytes(),
        request.request_digest_sha256.as_bytes(),
        request.payload_digest_sha256.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hasher.update(request.protocol_version.to_be_bytes());
    hasher.update(request.fencing_token.to_be_bytes());
    format!("r9a3-effect-{}", hex::encode(hasher.finalize()))
}

fn load_matching_effects(
    connection: &Connection,
    request: &SendRequest,
) -> R9a3Result<Vec<SideEffect>> {
    let mut statement = connection.prepare(
        "SELECT durable_sequence, effect_id, protocol_version, operation_id,
                dispatch_id, attempt_id, fencing_token, request_digest_sha256,
                payload_digest_sha256
         FROM effects WHERE operation_id = ?1 OR dispatch_id = ?2
         ORDER BY durable_sequence",
    )?;
    let effects = statement
        .query_map(
            params![request.operation_id, request.dispatch_id],
            effect_from_row,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    validate_effects(effects)
}

fn load_effect_by(
    connection: &Connection,
    column: &str,
    value: &str,
) -> R9a3Result<Option<SideEffect>> {
    let sql = match column {
        "dispatch_id" => {
            "SELECT durable_sequence, effect_id, protocol_version, operation_id,
                    dispatch_id, attempt_id, fencing_token, request_digest_sha256,
                    payload_digest_sha256 FROM effects WHERE dispatch_id = ?1"
        }
        "operation_id" => {
            "SELECT durable_sequence, effect_id, protocol_version, operation_id,
                    dispatch_id, attempt_id, fencing_token, request_digest_sha256,
                    payload_digest_sha256 FROM effects WHERE operation_id = ?1"
        }
        _ => return Err(R9a3Error::storage("unsupported effect lookup column")),
    };
    connection
        .query_row(sql, [value], effect_from_row)
        .optional()?
        .map(|effect| {
            effect.validate()?;
            Ok(effect)
        })
        .transpose()
}

fn effect_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SideEffect> {
    let durable_sequence: i64 = row.get(0)?;
    let protocol_version: i64 = row.get(2)?;
    let fencing_token: i64 = row.get(6)?;
    Ok(SideEffect {
        effect_id: row.get(1)?,
        durable_sequence: u64::try_from(durable_sequence).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        request: SendRequest {
            protocol_version: u16::try_from(protocol_version).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
            operation_id: row.get(3)?,
            dispatch_id: row.get(4)?,
            attempt_id: row.get(5)?,
            fencing_token: u64::try_from(fencing_token).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
            request_digest_sha256: row.get(7)?,
            payload_digest_sha256: row.get(8)?,
        },
    })
}

fn validate_effects(effects: Vec<SideEffect>) -> R9a3Result<Vec<SideEffect>> {
    for effect in &effects {
        effect.validate()?;
    }
    Ok(effects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "egopulse-r9a3-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create R-9A.3 test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(operation: &str, dispatch: &str) -> SendRequest {
        SendRequest {
            protocol_version: PROTOCOL_VERSION,
            operation_id: operation.to_owned(),
            dispatch_id: dispatch.to_owned(),
            attempt_id: "attempt-01".to_owned(),
            fencing_token: 7,
            request_digest_sha256: "a".repeat(64),
            payload_digest_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn exact_replay_survives_reopen_and_reader_returns_original_effect() {
        let root = TestRoot::new("replay");
        let first_writer = SideEffectWriter::initialize(root.path(), "instance-01").unwrap();
        let input = request("operation-01", "dispatch-01");
        let original = first_writer.commit_effect(&input).unwrap();
        assert!(!original.replayed);

        let reopened = SideEffectWriter::initialize(root.path(), "instance-01").unwrap();
        let replay = reopened.commit_effect(&input).unwrap();
        assert_eq!(
            replay,
            SendAck {
                replayed: true,
                ..original.clone()
            }
        );
        assert_eq!(replay.attempt_id, input.attempt_id);
        assert_eq!(replay.fencing_token, input.fencing_token);

        let reader = SideEffectReader::open_existing(root.path(), "instance-01").unwrap();
        assert_eq!(reader.effect_count().unwrap(), 1);
        let effect = reader
            .effect_for_dispatch("dispatch-01")
            .unwrap()
            .expect("effect by dispatch");
        assert_eq!(effect.request, input);
        assert_eq!(effect.original_ack(), original);
        assert_eq!(
            reader.effect_for_operation("operation-01").unwrap(),
            Some(effect.clone())
        );
        assert_eq!(reader.all_effects().unwrap(), vec![effect]);
    }

    #[test]
    fn operation_dispatch_and_cross_row_drift_conflict_without_writes() {
        let root = TestRoot::new("conflict");
        let writer = SideEffectWriter::initialize(root.path(), "instance-01").unwrap();
        let first = request("operation-01", "dispatch-01");
        writer.commit_effect(&first).unwrap();

        let mut same_operation = request("operation-01", "dispatch-drift");
        same_operation.payload_digest_sha256 = "c".repeat(64);
        assert_eq!(
            writer.commit_effect(&same_operation).unwrap_err().kind(),
            R9a3ErrorKind::Conflict
        );

        let same_dispatch = request("operation-drift", "dispatch-01");
        assert_eq!(
            writer.commit_effect(&same_dispatch).unwrap_err().kind(),
            R9a3ErrorKind::Conflict
        );

        let second = request("operation-02", "dispatch-02");
        writer.commit_effect(&second).unwrap();
        let cross_row = request("operation-01", "dispatch-02");
        assert_eq!(
            writer.commit_effect(&cross_row).unwrap_err().kind(),
            R9a3ErrorKind::Conflict
        );

        let reader = SideEffectReader::open_existing(root.path(), "instance-01").unwrap();
        assert_eq!(reader.effect_count().unwrap(), 2);
        assert_eq!(
            reader
                .effect_for_dispatch("dispatch-01")
                .unwrap()
                .unwrap()
                .request,
            first
        );
        assert_eq!(
            reader
                .effect_for_dispatch("dispatch-02")
                .unwrap()
                .unwrap()
                .request,
            second
        );
    }

    #[test]
    fn invalid_requests_fail_before_effect_write() {
        let root = TestRoot::new("invalid");
        let writer = SideEffectWriter::initialize(root.path(), "instance-01").unwrap();
        let mut invalid = vec![];

        let mut value = request("operation-01", "dispatch-01");
        value.operation_id.clear();
        invalid.push(value);
        let mut value = request(" operation-01", "dispatch-01");
        value.dispatch_id.push('\n');
        invalid.push(value);
        let mut value = request("operation-01", "dispatch-01");
        value.request_digest_sha256 = "A".repeat(64);
        invalid.push(value);
        let mut value = request("operation-01", "dispatch-01");
        value.payload_digest_sha256 = "b".repeat(63);
        invalid.push(value);
        let mut value = request("operation-01", "dispatch-01");
        value.protocol_version += 1;
        invalid.push(value);
        let mut value = request("operation-01", "dispatch-01");
        value.fencing_token = 0;
        invalid.push(value);

        for value in invalid {
            assert_eq!(
                writer.commit_effect(&value).unwrap_err().kind(),
                R9a3ErrorKind::InvalidInput
            );
        }
        let reader = SideEffectReader::open_existing(root.path(), "instance-01").unwrap();
        assert_eq!(reader.effect_count().unwrap(), 0);
    }

    #[test]
    fn reader_is_read_only_query_only_and_rejects_identity_or_schema_drift() {
        let root = TestRoot::new("reader");
        let writer = SideEffectWriter::initialize(root.path(), "instance-01").unwrap();
        writer
            .commit_effect(&request("operation-01", "dispatch-01"))
            .unwrap();
        let reader = SideEffectReader::open_existing(root.path(), "instance-01").unwrap();
        let connection = reader.open().unwrap();
        assert!(connection.execute("DELETE FROM effects", []).is_err());
        drop(connection);

        assert_eq!(
            SideEffectReader::open_existing(root.path(), "instance-wrong")
                .unwrap_err()
                .kind(),
            R9a3ErrorKind::Conflict
        );

        let connection = Connection::open(root.path().join(WITNESS_FILE_NAME)).unwrap();
        configure_existing_writer(&connection).unwrap();
        connection
            .execute("UPDATE witness_identity SET schema_version = 2", [])
            .unwrap();
        assert_eq!(
            writer
                .commit_effect(&request("operation-02", "dispatch-02"))
                .unwrap_err()
                .kind(),
            R9a3ErrorKind::Conflict
        );
        let effect_count: i64 = connection
            .query_row("SELECT count(*) FROM effects", [], |row| row.get(0))
            .unwrap();
        assert_eq!(effect_count, 1);
        assert_eq!(
            SideEffectReader::open_existing(root.path(), "instance-01")
                .unwrap_err()
                .kind(),
            R9a3ErrorKind::Conflict
        );
    }

    #[test]
    fn commit_never_recreates_a_missing_witness_database() {
        let root = TestRoot::new("missing");
        let writer = SideEffectWriter::initialize(root.path(), "instance-01").unwrap();
        let database_path = root.path().join(WITNESS_FILE_NAME);
        fs::remove_file(&database_path).unwrap();
        assert_eq!(
            writer
                .commit_effect(&request("operation-01", "dispatch-01"))
                .unwrap_err()
                .kind(),
            R9a3ErrorKind::Storage
        );
        assert!(!database_path.exists());
    }

    #[test]
    fn bounded_frames_round_trip_stable_request_and_ack_bytes() {
        let input = request("operation-01", "dispatch-01");
        let request_frame = encode_send_request_frame(&input).unwrap();
        assert!(request_frame.len() <= MAX_FRAME_BYTES);
        assert_eq!(decode_send_request_frame(&request_frame).unwrap(), input);
        let mut request_wire = Vec::new();
        write_send_request_frame(&mut request_wire, &input).unwrap();
        assert_eq!(request_wire, request_frame);
        assert_eq!(
            read_send_request_frame(&mut request_wire.as_slice()).unwrap(),
            input
        );

        let effect = SideEffect {
            effect_id: effect_id_for(&input),
            durable_sequence: 9,
            request: input.clone(),
        };
        let ack = effect.original_ack();
        assert_eq!(ack.attempt_id, input.attempt_id);
        assert_eq!(ack.fencing_token, input.fencing_token);
        let ack_frame = encode_send_ack_frame(&ack).unwrap();
        assert_eq!(decode_send_ack_frame(&ack_frame).unwrap(), ack);
        let mut ack_wire = Vec::new();
        write_send_ack_frame(&mut ack_wire, &ack).unwrap();
        assert_eq!(ack_wire, ack_frame);
        assert_eq!(read_send_ack_frame(&mut ack_wire.as_slice()).unwrap(), ack);
    }

    #[test]
    fn frame_limits_are_checked_before_payload_read_or_parse() {
        let oversized = u32::try_from(MAX_FRAME_BYTES).unwrap().to_be_bytes();
        assert_eq!(
            read_send_request_frame(&mut oversized.as_slice())
                .unwrap_err()
                .kind(),
            R9a3ErrorKind::InvalidInput
        );

        let input = request("operation-01", "dispatch-01");
        let frame = encode_send_request_frame(&input).unwrap();
        assert_eq!(
            decode_send_request_frame(&frame[..frame.len() - 1])
                .unwrap_err()
                .kind(),
            R9a3ErrorKind::InvalidInput
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            decode_send_request_frame(&trailing).unwrap_err().kind(),
            R9a3ErrorKind::InvalidInput
        );

        let effect = SideEffect {
            effect_id: effect_id_for(&input),
            durable_sequence: 1,
            request: input,
        };
        let mut ack_frame = encode_send_ack_frame(&effect.original_ack()).unwrap();
        *ack_frame.last_mut().unwrap() = 2;
        assert_eq!(
            decode_send_ack_frame(&ack_frame).unwrap_err().kind(),
            R9a3ErrorKind::InvalidInput
        );
    }
}
