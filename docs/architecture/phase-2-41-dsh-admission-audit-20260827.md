# Phase 2-41: DSH second-Harness admission audit

- Status: candidate retained; production admission not satisfied
- Evidence date: 2026-08-27
- Decision owner: Founder

## Audit scope

This audit compares the actual DSH ACP surface with the already-frozen
EgoPulse `NativeHarnessDriver` contract. It is an admission audit, not a
proposal to weaken the contract for a convenient provider integration.

The inspected DSH repository is `007M7/deepseek-harness-git` at commit
`a0edf49d2e41adfa573bf3c5656f0cafee3caf45`. The relevant ACP and subagent
documentation paths were clean relative to that commit; unrelated working
tree changes in that repository were not used as evidence.

## Observed native surface

The DSH ACP package documents and implements:

- `initialize`;
- `session/new` for a fresh agent;
- `session/prompt` and committed assistant text updates;
- `session/request_permission` and one-shot permission decisions;
- `session/cancel`.

The same ACP contract does not advertise or implement `session/load` or
`session/resume`. DSH's internal session persistence and snapshot/replay
facilities are not an equivalent native ACP resume contract: they do not give
the EgoPulse adapter a provider-attested way to identify the post-restart
state of an in-flight external dispatch.

The DSH subagent documentation also states that ACP children remain one-shot,
that continuation requires provider-specific remote-session persistence and a
continuation advertisement, and that the current ACP surface has no durable
report mailbox. These are relevant semantic gaps, not merely missing method
wrappers.

## EgoPulse evidence

The EgoPulse DSH adapter and tests currently prove:

- fresh ACP initialization and session creation;
- native prompt, ordered update and cancellation handling;
- governed permission routing through Adapter Edge and Policy Authority;
- one-shot terminal output candidate extraction;
- durable `OutcomeUnknown` recovery when native load/resume is unavailable;
- governed Artifact/return settlement for the isolated replay fixture.

The recovery test intentionally asserts
`dsh-reconcile:native-session-load-resume-unsupported` and verifies that an
uncertain delivery is never automatically redispatched. This is the correct
fail-closed result for the observed provider semantics.

## Admission result

DSH remains candidate-only. It cannot satisfy the second-Harness admission
gate until all of the following are independently evidenced:

1. authenticated real-provider lifecycle;
2. provider-native or equivalently attested restart/reconciliation semantics;
3. Artifact/return semantics that can be bound to the exact dispatch and
   terminal observation;
4. a documented treatment of accepted-but-unlogged work after process loss.

Adding a synthetic `session/load` wrapper around DSH's local snapshots would
not satisfy these conditions and would incorrectly convert `OutcomeUnknown`
into a successful recovery fact. No such wrapper is added.

The provider-neutral multi-model composition remains valid and unchanged:
DSH can continue to run as isolated candidate evidence, while Codex remains
the only production Harness. A future DSH admission, if the upstream
capability changes, can reuse the existing adapter and profile gates without
changing Memory Authority, Task Authority, or the CLI/TUI client kernel.
