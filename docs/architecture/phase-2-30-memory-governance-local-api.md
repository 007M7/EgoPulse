# Phase 2-30: Governed Memory mutation Local API

## Decision

The Memory Authority's existing Rust candidate/accept/revoke primitives are
now exposed to CLI and TUI through one shared `ExecuteMemoryMutation` Local API
RPC. The surface is command-shaped and authenticated by the existing session
and authorization profile; it is not a direct database or Python-worker path.

```text
CLI / TUI
    |
    v
LocalCommandGatewayService/ExecuteMemoryMutation
    |  session + RPC/oneof authorization
    v
MemoryCommandPort
    |  explicit Authority-principal constraint
    v
Memory Authority (Rust, SQLCipher, single writer)
    |
    +--> candidate       (Agent/Model/Harness semantics preserved internally)
    +--> accepted        (Founder / FounderAuthority only)
    `--> revoked        (terminal; Founder governance only)
```

`submit_memory_candidate` is deliberately not an acceptance operation. The
initial Local API profile exposes it only to a reviewed local Founder grant;
future internal Agent/Model/Harness producers will use an in-process port with
their own authenticated principal, not impersonate a client. `accept_memory`
and `revoke_memory` require explicit evidence and expected revision, so stale
or replay-conflicting governance cannot silently win.

## Why this boundary

- Memory Authority remains the sole writer and keeps idempotency, state
  transition and durability behavior already implemented and tested in Rust.
- Local API owns peer/session/profile authorization; CLI and TUI do not decide
  who may govern a memory.
- Python RAG remains read-only and receives accepted snapshots only. No Memory
  mutation RPC invokes the worker or grants it a database handle.
- A single command shape keeps CLI, TUI and future Desktop on the same kernel
  path. Their only differences remain argument collection and rendering.

## Cost and deliberate omissions

The public V-01 contract and generated Rust/TypeScript/Python bindings change,
so the contract digest, manifest and compatibility checks must move together.
The first slice returns a durable mutation receipt rather than a projected
Memory view; projection/read-model work is separate. Agent-originated writes
are not simulated through a user session and remain an internal producer gate.

## Acceptance evidence

The implementation must prove: valid candidate submission, Founder accept,
terminal revoke, stale revision rejection, idempotent replay, unauthorized
principal rejection, and both CLI/TUI request construction through the same
RPC. A failed authority operation is returned as a typed Local API error; no
success-shaped receipt is fabricated.
