# Phase 2-07 Worker process framing and supervision

## Status

Implemented as generic infrastructure. This document does not define Memory
messages, change `contracts/`, regenerate bindings, or modify the V-01
manifest. The Memory/RAG cross-language message proposal remains pending
Founder approval.

## Boundary

```text
Rust authority / orchestrator
        |
        | supervised child process
        | stdin: one length-delimited request
        | stdout: one length-delimited response
        v
Python / TypeScript / native Worker
```

`egopulse-process-supervision` now provides a reusable framing layer for a
single request/response Worker exchange:

- a fixed four-byte big-endian unsigned length prefix;
- a default payload limit of 16 MiB;
- exact-one-frame decoding for a completed response;
- explicit errors for invalid limits, oversized payloads, truncated headers,
  truncated payloads, trailing bytes and clean end-of-stream;
- the existing process timeout, crash, cancellation-on-drop and bounded
  stdout governance remain in force.

The framing layer carries opaque bytes. It intentionally does not choose
Protobuf field names, schemas, serialization libraries or Memory business
semantics. A later approved contract can use this boundary without making the
process supervisor own that contract.

## Why this boundary

| Decision | Reason | Cost accepted |
|---|---|---|
| Length-delimited stdin/stdout | No listening port, simple Windows local deployment, reuses existing process supervision and works across Rust/Python/TypeScript | The child is process-scoped; each Worker needs startup and explicit framing/error handling |
| Big-endian four-byte length | Small deterministic codec with an unambiguous maximum and no dependency on a framework | Payloads are limited to a 32-bit length field and the protocol has less built-in evolution metadata than a full RPC stack |
| Opaque payloads | Keeps infrastructure independent from the still-unfrozen Memory contract | Callers must validate the actual payload schema at their own boundary |
| Exactly one response | Prevents accidental logs or multiple responses from becoming a valid result | Workers must keep diagnostics on stderr and follow the one-exchange lifecycle |

This is a transport and lifecycle decision, not a decision that Python is the
Memory authority or that a particular RAG algorithm is permanent.

## Validation evidence

The crate tests cover deterministic encoding, round-trip decoding, invalid
limits, oversized payloads, truncated headers, truncated payloads, trailing
bytes and clean EOF. Clippy is run with warnings denied. End-to-end Worker
crash, timeout and cancellation cases remain part of the first real Worker
vertical slice.
