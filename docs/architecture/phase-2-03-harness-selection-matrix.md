# Phase 2-03 Harness selection matrix

This document is an engineering selection record for the second native
Harness. It does not freeze a provider as an architecture source. The frozen
boundary is the provider-neutral `NativeHarnessDriver` plus
`GovernedHarnessAdapter`; a provider is admitted only by evidence.

## Decision criteria

| Criterion | Required evidence | Why it matters |
| --- | --- | --- |
| Native structured dispatch | A local probe and dispatch fixture return stable request/session/execution references | Prevents process-only text scraping from being mistaken for governed execution |
| Structured observations | ACK, running, terminal, diagnostic and artifact-related events are independently mappable | Allows Task, Verification and Verdict to consume evidence without provider coupling |
| Approval semantics | A native approval request can be routed through Adapter Edge and Policy | Keeps side-effect authority outside the model/provider |
| Cancellation and restart | Cancel, process restart and reconcile produce a known result or an explicit hold | Prevents duplicate execution and false terminal success |
| Multi-model isolation | Two model-family selectors bind to distinct reviewed profiles without cross-store writes | Makes “multi-model” a governed workflow property rather than UI routing |
| Windows x64 operability | Executable discovery, version and schema probe work on the target release platform | The first release is local Windows x64, not a server fleet |

## Candidate comparison

| Candidate | Why consider it | Cost / what we give up | Current status |
| --- | --- | --- | --- |
| Codex app-server | Already has a native structured protocol, an implemented adapter, durable approval/recovery fixtures and a pinned probe fingerprint | The protocol is version-sensitive; we pay adapter maintenance for native schema drift and retain Codex-specific process supervision | Active production Harness |
| Kimi CLI | Existing research indicates a useful CLI workflow and a possible second model family for local users; the ACP initialize/session boundary is locally reachable | The current isolated `session/new` requires authentication, so prompt, approval, cancellation and reconciliation semantics remain unproven; an adapter may otherwise degrade to process-only or emulated support | Candidate held at `authentication_required`; authenticated lifecycle probe required |
| DeepSeek Harness | Local source is available for study and it is relevant to the planned multi-model product surface | Its internal event/runtime model is not automatically the EgoPulse contract; integrating it may create a large TypeScript/runtime coupling and unclear native recovery semantics | Candidate held; native recovery unsupported |

The selection is intentionally not “the one with the most SDK code”. The
winner must show the lowest semantic gap while preserving the same authority,
durability and recovery guarantees. A lower implementation cost is not enough
if it moves approval, memory, routing or terminal truth into the Harness.

## Probe matrix to implement next

Each candidate receives the same provider-neutral probe request and the same
fixture expectations. The probe must record an evidence reference for every
row; a missing or self-reported row is not treated as support.

The zero-API-call executable discovery slice is recorded in
`phase-2-03-windows-probe-2026-08-26.md`. All three local command entry points
are discoverable. Codex remains the only production Harness; DSH now has
candidate ACP lifecycle evidence, but its recovery row is an explicit hold.

The follow-up protocol observations are recorded in
`phase-2-03-protocol-boundary-evidence-2026-08-26.md`. Kimi remains the next
candidate for an authenticated lifecycle probe; its current no-prompt probe
is explicitly recorded as `authentication_required`. DSH's isolated profile,
session creation, multi-turn prompt and cancellation probes pass, while its
native recovery limitation keeps it held.

The candidate-only Rust probe is `crates/kimi-adapter`. Its explicit degraded
result and fail-closed execution methods are part of the evidence: protocol
reachability has been implemented without silently upgrading it to structured
dispatch or recovery support.

| Probe row | Pass condition | Failure disposition |
| --- | --- | --- |
| Executable/version | Pinned executable is discoverable and reports the expected version | `Unavailable` |
| Protocol/schema | Native protocol fingerprint matches the reviewed profile digest | `ProtocolMismatch` |
| Structured dispatch | A no-side-effect fixture returns opaque native refs | Candidate held if process-only |
| ACK/lifecycle | Accepted, started and terminal observations are ordered and replayable | Candidate held |
| Approval | Native request maps to reviewed approval kind and Adapter Edge routing | Candidate held; no auto-approval |
| Cancel | Native cancellation or explicitly supported process termination has known semantics | Candidate held or restricted |
| Restart/reconcile | A restarted adapter can distinguish active, terminal and unknown outcomes | DSH probe: native load/resume unsupported; candidate held |
| Artifact/evidence | Returned output can be independently hashed and associated with the dispatch | Candidate held |
| Model binding | Two model selectors remain profile-bound and isolated | Candidate held |

## Promotion rule

Only a candidate that passes the local matrix may receive a `ProbeVerified`
capability profile. Until then it may be studied or run as an explicitly
unsupported development tool, but it cannot be selected by a reviewed
`StepPlan`, cannot write Task/Verification/Verdict authority stores, and cannot
be advertised as the second production Harness.
