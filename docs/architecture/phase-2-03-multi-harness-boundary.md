# Phase 2-03 multi-Harness / multi-model boundary

## Status

The provider-neutral candidate boundary and G4-09 pre-driver capability gate
are implemented and locally verified. Codex remains the only production
Harness. Kimi and DeepSeek remain explicitly held candidates until their
native lifecycle, approval and recovery evidence satisfies the same contract.

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

The daemon now has a composition seam for that future multi-Harness runtime:
`CompositeHarnessDispatchRunner` invokes provider-specific runners through one
daemon scheduling hook. Each child runner may be bound to one reviewed
capability-profile ID and must own its own Adapter Edge. The composite only
sequences cycles and merges their public cycle reports; it does not select a
model, merge provider-owned facts or weaken Collaboration/Authority rules.

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

The first composition seam is locally verified: an empty composite is rejected
before daemon configuration, child cycle reports are merged deterministically
with terminal dispatch IDs de-duplicated, and a profile-bound runner ignores
dispatches whose capability binding is different or missing. This proves the
scheduling and isolation contract only; it does not promote DSH or Kimi and
does not claim that either candidate has completed Artifact or recovery
admission.

The current Kimi code unit now has a candidate execution boundary as well as
the authenticated-session probe: it can keep a fresh ACP session, send a
native `session/prompt`, consume ordered updates, route a native permission
request through the provider-neutral approval surface, cancel the session and
expose a one-shot terminal output candidate. These methods are still
candidate-only until an authenticated real-process lifecycle and recovery
matrix is recorded. A candidate is not promoted merely because its process
starts, its session can be created or its driver compiles.

The model-isolation prerequisite is now executable at the Adapter Edge. The
test `reviewed_harness_edges_are_isolated_and_cannot_cross_write` in
`crates/harness-adapter/src/edge.rs` opens separate encrypted edge stores for
`codex-adapter` and `dsh-adapter`, registers one dispatch and one observation
in each, and proves that neither store can read the other Harness's dispatch.
Each edge retains its own dispatch/observation counts and adapter-scoped raw
evidence references. This closes the storage-isolation prerequisite for
multi-model selection; it does not attest DSH's native Artifact/recovery
semantics and does not promote DSH.

The ACP codec is now isolated in `crates/kimi-adapter/src/acp.rs`. It keeps
`session/update`, prompt/cancel request construction and server-side
`session/request_permission` messages separate from provider-neutral Driver
events. Unknown update kinds are preserved as explicit candidate evidence;
they are not silently treated as terminal success. The codec is not itself a
production dispatch implementation.

The first candidate implementation is now `crates/kimi-adapter`. It reuses
the existing process-supervision seam. Its candidate-only driver performs
ACP `initialize`/`session/new`, native `session/prompt`, ordered update
consumption, provider-neutral permission routing, native cancellation and
one-shot terminal-output extraction. A reachable Kimi process is reported as
`Degraded` until a reviewed schema digest exists; an unauthenticated
`session/new` remains a controlled `AuthenticationRequired` disposition.
The crate is still a probe vehicle, not a second production Harness: no
authenticated lifecycle, Artifact/return or recovery matrix has been
attested, and it is not wired into the agent daemon bootstrap.

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
share directory. The probe now retains a bounded process exit/stderr
diagnostic when stdout reaches EOF, so a launcher failure is not confused with
an ACP or authentication result. It must not be promoted until the authenticated
`session/new`/prompt lifecycle and recovery matrix is complete.

The same test module now proves that the unverified dispatch, event, approval,
cancellation and reconciliation surfaces all return `CapabilityMismatch` with
`ProvenNotSent`. This is a candidate safety invariant, not evidence of
second-Harness support.

The DSH candidate now has a deliberately narrower execution slice in
`crates/dsh-adapter`: fresh ACP `session/prompt`, supervised terminal event
mapping, native `session/cancel`, and a governed native
`session/request_permission` round-trip. Its local replay tests pass against
the compiled DSH ACP demo. This does not change admission: native
`session/load`/`session/resume` are unsupported and the DSH ACP surface does
not expose an independently hashable EgoPulse Artifact return. The driver is
therefore still candidate-only and is not wired into daemon provider
selection.

The configured Windows x64 replay evidence was rerun against the local DSH
workspace with the Rust driver and passed all three scenarios:

```text
dsh_replay_driver_emits_terminal_lifecycle                         passed
dsh_replay_driver_sends_native_cancel_and_observes_interruption    passed
dsh_replay_driver_routes_native_permission_through_governed_decision passed
```

This raises confidence in the ACP process/lifecycle seam only. It does not
prove authenticated production access, `session/load` or `session/resume`,
provider-native Artifact semantics, or the full daemon Verification/return
settlement path; those rows remain explicit admission blockers.

The explicitly configured local Kimi probe was run against Kimi CLI 1.49.0
with an isolated Windows user directory. It produced the expected no-prompt
candidate evidence: initialize passed and `session/new` returned
`authentication_required`; no prompt or model call was sent. This proves only
that the ACP entry point and unauthenticated session boundary are reachable.

A second Python314 script entry was also tested and exited with code `1` before
returning an ACP initialize response. Its bounded stderr evidence identified
`ModuleNotFoundError: No module named 'typer'`. That is a reproducible
installation-level failure, not authentication evidence or a protocol result.
Both observations remain candidate evidence only; the Kimi candidate is not
promoted until the authenticated prompt, Artifact, Verification/return and
recovery matrix is complete.

## Phase 2-03 exit disposition

Phase 2-03 closes its provider-neutral boundary and candidate-probe slice, but
does not close second-Harness admission. The authoritative evidence is:

- G4-09 capability-binding and shared Probe Gate tests;
- the Kimi isolated no-prompt ACP probe reaching `initialize` and recording
  `session_disposition=authentication_required`; the separate default-profile
  probe recorded a pre-ACP process failure (`exit_code=1`, missing Python
  `typer` dependency);
- DSH isolated ACP prompt/cancel/permission evidence with Artifact and native
  recovery explicitly held;
- Codex remaining the sole active production Harness.

The next admission decision remains separate from the candidate execution
slice: either complete the missing DSH Artifact/recovery evidence or run the
authenticated Kimi lifecycle probe. Codex remains the only production Harness
until one candidate satisfies the complete contract. Memory/RAG runtime work
remains a parallel governed slice, but it does not silently promote a second
Harness.
