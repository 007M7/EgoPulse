# Phase 2.32 — Governed candidate producer admission

Status: implemented locally; candidate-only internal boundary

This slice establishes the process-local admission boundary for future Agent,
Model and Harness runtimes that need to propose memories. It does not promote
any provider to a production Harness, and it does not add a new public Local
API method.

## Decision

`agentosd` exposes a narrow `MemoryCandidateProducerPort`, a composition-time
`MemoryCandidateProducerRegistry`, and a single-producer capability handle:

```text
reviewed composition
        |
        v
producer_id -> fixed principal_id + fixed principal_kind
        |                  (Agent | Model | Harness only)
        +--> fixed scope_ref
        v
bind_producer(producer_id) -> MemoryCandidateProducerHandle
        |
        v
MemoryCandidateProducerHandle::submit_candidate(command)
        |
        v
Rust Memory Authority (single writer, SQLCipher, idempotency, event receipt)
        |
        v
candidate only
        |
        +--> Founder/FounderAuthority accept
        +--> GovernanceKernel/RecoveryCoordinator revoke
```

The producer handle has no producer-selection or principal argument. The
principal is constructed once
from the reviewed binding and cannot be selected by the model output, a worker
payload or a Local API client. `producer_id` is an internal composition route,
not a user-controlled authority claim. Each binding also fixes one `scope_ref`;
a candidate for another scope is rejected before the Memory Authority is
called.

The registry accepts only these producer identities:

| producer class | allowed operation | authority decision |
| --- | --- | --- |
| Agent | submit candidate | never accept or revoke |
| Model | submit candidate | never accept or revoke |
| Harness | submit candidate | never accept or revoke |

Founder, FounderAuthority, GovernanceKernel and RecoveryCoordinator are
rejected as producer registrations. They remain available only to their
separate governance paths, so a producer registration cannot accidentally
become a second governance writer.

## Why this is an architectural boundary

The frozen quality attributes are ownership, authority separation, auditability
and fail-closed behavior. They are preserved here by four properties:

1. The Memory Authority remains the only writer.
2. The producer capability is submit-only; acceptance and revocation are not
   methods on the producer port.
3. Identity is fixed at composition time and is not transported as mutable
   request data.
4. Existing authority guarantees remain in force: durable receipt,
   idempotency, request digest, revision/state rules and source/scope fields.

This is the reusable seam for multi-model collaboration. It does not pretend
that an arbitrary model or Harness is admitted: a future runner must first be
registered with a reviewed identity binding and then receive the corresponding
port from the daemon composition.

## Deliberate non-goals

- No Agent/Model/Harness candidate submission is exposed through the public
  protobuf Local API.
- No producer can call accept or revoke through this boundary.
- No semantic/vector RAG promotion is implied. Python retrieval remains
  read-only over accepted snapshots, and lexical retrieval remains the release
  baseline until representative-corpus evaluation passes its gate.
- No second Harness admission is implied. DSH and Kimi remain candidate-only
  until their authenticated lifecycle, artifact/return and recovery evidence
  is complete.

## Trade-offs and costs

The fixed binding adds explicit composition work: each future producer needs a
stable route, a stable principal ID and an admission review. This means a new
model cannot start writing candidates merely by sending a payload. The cost is
intentional: it prevents identity impersonation and keeps audit records
attributable.

The registry is process-local rather than a cross-process broker. Provider
runtimes should receive a single-producer handle, not the whole registry. That
keeps
the first release small and avoids introducing another durable queue, but it
means a future provider runner must be hosted in the daemon composition (or
use a separately authenticated owner port). The boundary is ready; the
provider-specific runtime integration is still a subsequent vertical slice.

## Evidence

Unit coverage in `apps/agentosd/src/memory_mutation.rs` verifies:

- Agent, Model and Harness bindings can submit candidates through distinct
  fixed routes;
- unknown routes fail closed;
- a producer cannot submit outside its bound scope;
- exact candidate replay preserves the Memory Authority receipt;
- governance identities cannot be registered as producers;
- empty and duplicate registrations are rejected.

The existing M-11 Windows E2E remains the proof for the public CLI/TUI path:
`docs/architecture/phase-2-31-memory-governance-mutation-e2e.md`.

Focused command:

```powershell
cargo test -p egopulse-agentosd --lib memory_mutation::tests
```
