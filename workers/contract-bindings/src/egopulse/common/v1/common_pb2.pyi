import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CommandMetadata(_message.Message):
    __slots__ = ("command_id", "idempotency_key", "idempotency_scope", "request_digest_sha256", "issued_at", "correlation_id", "causation_id")
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_SCOPE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DIGEST_SHA256_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    CORRELATION_ID_FIELD_NUMBER: _ClassVar[int]
    CAUSATION_ID_FIELD_NUMBER: _ClassVar[int]
    command_id: str
    idempotency_key: str
    idempotency_scope: str
    request_digest_sha256: str
    issued_at: _timestamp_pb2.Timestamp
    correlation_id: str
    causation_id: str
    def __init__(self, command_id: _Optional[str] = ..., idempotency_key: _Optional[str] = ..., idempotency_scope: _Optional[str] = ..., request_digest_sha256: _Optional[str] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., correlation_id: _Optional[str] = ..., causation_id: _Optional[str] = ...) -> None: ...

class ContractReference(_message.Message):
    __slots__ = ("contract_id", "version", "sha256")
    CONTRACT_ID_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    contract_id: str
    version: str
    sha256: str
    def __init__(self, contract_id: _Optional[str] = ..., version: _Optional[str] = ..., sha256: _Optional[str] = ...) -> None: ...
