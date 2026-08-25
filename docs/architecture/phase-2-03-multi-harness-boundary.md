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

The next code unit is a provider-neutral capability binding validator and its
fixture matrix. It will validate the relationship between a `StepPlan`'s
required capability profile and an active attested profile before any native
driver is started. Only after that evidence is green will the second Harness
driver be added.

