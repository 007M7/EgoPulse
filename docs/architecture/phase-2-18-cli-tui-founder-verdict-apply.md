# Phase 2-18: CLI/TUI Founder Verdict Apply Closure

Status: verified by real Windows daemon E2E.

## Scope

Both surfaces expose the same governed write capability:

```text
CLI: egopulse task apply-verdict ...
TUI: egopulse-tui task-apply-verdict ...
                 |
                 v
       Client Kernel session handshake
                 |
                 v
       LocalCommandGatewayService
                 |
                 v
       TaskAuthority.ApplyFounderVerdict
                 |
                 v
       ConfiguredTaskTransitionGuard
                 |
                 v
       FounderVerdictAuthority (read-only validation)
```

CLI and TUI differ in argument syntax and presentation only. Neither surface
opens an Authority store or interprets the Founder decision locally.

## Authorization contract

`apply_founder_verdict` is a user-facing command with the permission
`local.founder-verdict.apply`. Its owner remains `TaskAuthority`, and its
confirmation class remains `authority_contract`.

The frozen command rule accepts both `TaskAuthority.Founder` (the normal CLI
and TUI session) and `TaskAuthority.FounderAuthority` (a trusted authority
path). This is only an entry-point distinction; Task Authority still performs
the state, revision, work revision, verdict state, scope, artifact, and
verification-reference checks.

`revise_task`, `supersede_task`, and `expire_task` remain restricted to
`TaskAuthority.FounderAuthority`.

## Request contract

```text
egopulse task apply-verdict <task-id> \
  --expected-revision <task-revision> \
  --work-revision <work-revision> \
  <founder-verdict-id>

egopulse-tui task-apply-verdict <task-id> \
  --expected-revision <task-revision> \
  --work-revision <work-revision> \
  <founder-verdict-id>
```

The shared `client-operations::set_task_digest` function covers
`ApplyFounderVerdict`; command identifiers, timestamps, correlation metadata,
and request digests are excluded from the canonical digest consistently across
CLI, TUI, and future Desktop clients.

## Real E2E evidence

`apps/agentosd/tests/c5_00_daemon_fixture.rs` starts the real Windows daemon,
attaches both real binaries, creates a Draft Task, and invokes apply-verdict
through both surfaces. Both requests reach the same daemon and are rejected by
the Task Authority with a typed domain rejection; no client-side shortcut is
accepted.

The surface exit protocol is intentionally different: TUI reports command
errors with exit code 3, while CLI reports the JSON domain-conflict envelope
with exit code 6. The governed capability and authority result are identical.

## Downstream projection and consume

On a valid transition, Task Authority remains the sole Task writer and emits
the Founder Verdict consume outbox. The daemon's Founder Verdict consume
worker validates the payload digest, invokes the shared Verdict Authority
handle, and acknowledges the Task outbox only after commit or idempotent replay.
