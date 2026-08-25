# Phase 2-03 multi-Harness / multi-model boundary

## Current decision

Phase 2-03 starts with a capability-and-evidence boundary, not with a second
provider-specific client implementation. Codex remains the only active
production Harness until a second native integration passes the same probe,
contract and recovery evidence gates.

The model or provider is therefore a governed workflow fact:

```text
reviewed RunPlan / StepPlan
        |
        v
required capability profile ref + model-family selector
        |
        v
active attested Harness capability profile
        |
        v
selected adapter + native driver
        |
        v
Collaboration-owned dispatch envelope
        |
        v
provider-neutral delivery / ACK / outcome evidence
```

The UI, Memory/RAG layer and provider response must not choose or rewrite the
Harness. A second model can be proposed by a planning component, but it is
usable only after the workflow's capability binding and policy checks accept
it.

## What is frozen now

- `NativeHarnessDriver` remains the native-protocol boundary.
- `GovernedHarnessAdapter` remains the adapter-owned durable edge and evidence
  boundary.
- `dispatch_id`, attempt identity and fencing remain Collaboration-owned.
- Native session, thread, request and execution identifiers remain opaque
  Adapter-owned references.
- Capability profiles are versioned, digest-addressed and attested before an
  adapter can be selected.
- Capability mismatch, protocol drift, unavailable model, uncertain delivery
  and unknown terminal outcome are distinct failures; none is converted into a
  successful Task or Verdict fact.
- The first multi-model implementation may reuse the same local client kernel
  and command surfaces. It must not introduce a UI-specific routing path.

## What is deliberately not frozen yet

The second official Harness is not selected by popularity or by the amount of
existing SDK code. It must first answer the same two engineering questions as
Codex:

1. Why this Harness? It must expose enough structured dispatch, approval,
   lifecycle, cancellation, reconciliation and evidence semantics to satisfy
   the existing adapter contract without weakening the authority boundary.
2. What is the cost? The integration must record which semantics are native,
   emulated, process-only, unsupported or unknown. Those weaker semantics
   become explicit workflow/recovery constraints rather than hidden adapter
   behavior.

The initial candidates remain the previously researched Codex, Kimi CLI and
DeepSeek Harness ecosystems. Their selection is a Gate 2/3 input after a
local Windows x64 probe and contract matrix; it is not a new architecture
source and does not alter the frozen four-layer system architecture.

## Phase 2-03 acceptance gates

1. Capability profile: declaration, digest, attestation level, validity and
   model-family selectors are durable and independently reviewable.
2. Probe: executable identity, native protocol/schema fingerprint and required
   capability semantics are verified locally.
3. Dispatch: the second adapter consumes the existing provider-neutral dispatch
   envelope and writes only its own edge facts.
4. Approval: native approval requests are resolved through Adapter Edge and
   Policy Authority; no client-provided native routing is accepted.
5. Recovery: cancel, restart, reconcile and uncertain-terminal paths have
   evidence equivalent to the Codex vertical or are explicitly marked
   unsupported and held.
6. Multi-model: two model families can be selected by a reviewed workflow
   binding and cannot cross-write each other's Adapter or Authority stores.
7. Shared surfaces: CLI and TUI exercise the same Client Kernel calls; no
   second surface-specific model orchestration is introduced.

## Next implementation slice

The provider-neutral capability binding validator and its G4-09 fixture matrix
are closed. The shared Probe Gate is also implemented in
`GovernedHarnessAdapter`: it validates adapter identity, readiness enum,
independent probe evidence and native protocol fingerprint before a `Ready`
result can become capability-attestation input. A future Kimi or DeepSeek
adapter cannot bypass it by returning a provider-specific success shape.

The current code unit is the authenticated-session boundary for the Kimi
candidate. It records the ACP `initialize` result and the empty `session/new`
disposition, but it does not send a prompt. A candidate is not promoted to an
active Harness merely because its process starts or its session can be
created.

The ACP codec is now isolated in `crates/kimi-adapter/src/acp.rs`. It keeps
`session/update`, prompt/cancel request construction and server-side
`session/request_permission` messages separate from provider-neutral Driver
events. Unknown update kinds are preserved as explicit candidate evidence;
they are not silently treated as terminal success. The codec is not itself a
production dispatch implementation.

The first candidate implementation is now `crates/kimi-adapter`. It reuses
the existing process-supervision seam and performs only an ACP `initialize`
and empty-session probe. A reachable Kimi process is reported as `Degraded`
until a reviewed schema digest exists; an unauthenticated `session/new` is a
controlled `AuthenticationRequired` disposition; dispatch, observations,
approvals, cancellation and reconciliation all return `CapabilityMismatch`.
The crate is therefore a probe vehicle, not a second production Harness and
is not wired into the agent daemon bootstrap.

## G4-09 evidence recorded

The provider-neutral validator now accepts the workflow `StepPlan` directly:
`validate_step_capability_binding` requires a non-empty, digest-addressed
`required_capability_profile_ref` and delegates the remaining checks to the
existing capability validator. The fixture matrix covers the following
negative paths in addition to the valid binding:

- missing required profile binding;
- profile or digest drift;
- inactive profile;
- declaration-only profile without probe attestation;
- model-family selector drift;
- expired profile validity window.

The local evidence is `crates/harness-adapter/tests/capability_binding_g4_09.rs`.
It proves the pre-driver binding boundary only. It does not select a second
Harness or open production Verification execution.

## Shared Probe Gate evidence

`GovernedHarnessAdapter::probe` now rejects a mismatched adapter identity
before invoking the native driver. A driver result marked `Ready` is accepted
only when it has a stable probe ID, observation time, evidence references and
an observed protocol fingerprint matching both the request's expected schema
and the adapter's expected fingerprint. Unknown readiness values and protocol
drift fail closed as `ProtocolMismatch`.

The provider-neutral unit evidence is in
`crates/harness-adapter/src/runtime.rs` under `probe_tests`.

The candidate-only Kimi evidence is in
`crates/kimi-adapter/src/lib.rs` under `tests`, including an ignored live
Windows probe that requires an explicitly configured executable and isolated
share directory. It must not be promoted until the authenticated
`session/new`/prompt lifecycle and recovery matrix is complete.
