# ADR 0006: Continue an applied Rework directive on the same Task

- Status: accepted design; runtime acceptance required before delivery
- Date: 2026-09-08
- Decision owner: Founder

## Decision

Phase-one closure includes continuing work after a Founder Rework decision. Reuse `ReviseTask`, Context Authority and the existing Harness execution path. Keep the Task identity and increment `work_revision`; do not replace the task with an unrelated new task or implement a second execution loop.

`PrepareRework` takes a Task identity, expected revision and retry key. The daemon resolves the applied Verdict, directive, sealed required changes and previous sealed repository result. The user reviews that immutable preparation before `ConfirmRework` submits the daemon-owned revision and activation. The RPCs reuse `local.work.prepare` and `local.work.confirm`. Raw `revise_task` remains system-only.

Run, Step, Attempt, Dispatch and workspace identities distinguish work revisions. Revision 1 retains its existing identity format for recovery compatibility. Retrying a revision must reproduce the same identities and command, including after a lost response.

The next workspace starts from the frozen baseline plus the previous sealed patch, checked against its sealed final manifest. It must not read mutable prior worktree content as authoritative input. Missing, mismatched or unsafe predecessor material blocks continuation before native dispatch. Context preserves the admitted route and existing input format; a model response cannot change these bindings.

Artifact execution revisions and later Task/Verdict revisions are distinct. The new execution follows the confirmed Rework Task through revision and activation; it must not infer a fixed revision offset from the predecessor Artifact. Each continuation replaces the current directive in the native prompt while preserving the original prompt and repository material. A proof field that the Harness does not read is insufficient to deliver instructions.

## Recovery

Client recovery preserves exact confirmation arguments and checks the authenticated principal and store epoch on replay. A saved record grants no permission. An uncertain response must not trigger another preparation or new Task automatically.

Both CLI and TUI save the protected confirmation record before sending. A storage failure prevents sending. Explicit pre-dispatch rejections can be shown as failures; an unavailable or incomplete response may follow a commit and must retain exact recovery.

After daemon restart, a durable Delivered receipt does not prove that the current adapter owns the original native session. Drain durable observations first. If no terminal result exists and native residency is lost, persist an explicit held/outcome-unknown state and reconcile through the existing recovery path. Do not leave a permanently active projection or resend a native dispatch merely to restore apparent progress.

## Acceptance

Prove a real same-Task two-round execution: sealed first-round changes, applied Rework directive, reviewed follow-up, a new work revision with distinct execution identities, inherited changes, visible result and a subsequent Founder decision. Prove exact replay, restart without repeated side effects, and rejection of missing or altered predecessor material. Compilation and isolated unit tests do not establish this closure.

Provider, Harness and model selection remain constrained by admitted compatible routes. Automatic route evaluation and governed Harness improvement are architectural extensions; they are not implied by this continuation interface.
