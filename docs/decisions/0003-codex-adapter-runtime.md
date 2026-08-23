# ADR 0003: Rust-hosted Codex Adapter runtime

- Status: accepted for V-01 G4-04
- Date: 2026-08-23
- Decision owner: Founder

## Decision

The first native model Harness Adapter is implemented in Rust. `agentosd` directly supervises the
configured Codex executable over the official app-server v2 stdio protocol. The Adapter owns a
separate encrypted durable edge for delivery uncertainty, native evidence, idempotency and monotonic
observation sequencing. It never owns Run, Step, Attempt, Task or Artifact facts.

Codex thread, turn, item and JSON-RPC types remain private to `crates/codex-adapter`. The public
Adapter boundary uses only the generated provider-neutral C-03 Protobuf messages. A fake driver and
the real Codex driver must exercise the same Rust Adapter service and fixtures.

## Why

Rust already owns process supervision and deterministic recovery, and the frozen topology connects
`agentosd` directly to native Harness processes. This choice avoids a Node sidecar, a second
cross-runtime transport and a second process-supervision chain. It also keeps the TypeScript runtime
limited to the separately defined AgentOS-native Harness and Agent SDK roles.

## Cost

The Adapter cannot directly reuse Codex-generated TypeScript bindings. EgoPulse must maintain a
Rust-local JSON-RPC mapping, pin the generated v2 schema digest and run protocol drift fixtures for
each Codex upgrade. Experimental app-server changes are paid for inside `codex-adapter`; they must
not be repaired by changing Authority contracts.

The independent SQLCipher edge adds another migration, key, backup and integrity-check surface. It
stores delivery/evidence facts only and must not become a second Collaboration store.

## Rejected for V-01

- A TypeScript Codex sidecar would add Node packaging, another IPC hop and duplicated supervision.
- A Rust durable host plus TypeScript mapper would add an unproven cross-runtime protocol and a
  larger two-process failure matrix before the first vertical loop exists.

## Review triggers

- A second native Harness cannot be integrated without changing Authority models.
- Codex schema churn makes the Rust mapping repeatedly unsafe or uneconomical.
- A provider only exposes a supported official SDK in another runtime and an isolated mapper
  demonstrably reduces total failure and deployment cost.
