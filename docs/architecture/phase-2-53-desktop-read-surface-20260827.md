# Phase 2-53: Desktop shared-kernel read and approval surface

- Date: 2026-08-27
- Scope: Tauri 2 + React + TypeScript Desktop surface
- Status: shared-kernel read slice, TaskCreate, Task cancellation, Approval decision, and Memory
  mutation commands implemented; shared-kernel Windows IPC loopback verified,
  native Tauri GUI automation remains a separate acceptance item

## Boundary

Desktop now uses the same `egopulse-client-operations::attach` path as the
other client surfaces. It opens a session with `ClientSurface::Desktop`, then
reads the bounded `ProjectionSnapshot` through the Local API. The Tauri layer
projects only safe display fields for the frontend. Its explicit TaskCreate
command uses the same typed command metadata and digest helpers as the other
surfaces and sends the command through `LocalCommandGatewayService`:

```text
Tauri command
  -> shared ClientAttachment
  -> authenticated Local API session
  -> read-model projection or typed command gateway
  -> Desktop-only display DTO
```

The Desktop process has no database handle, Memory writer, Provider selector,
Harness authority, or alternate session protocol. `foundation_status` reports
the structured architecture and local transport facts; `dashboard_snapshot`
reports projection health, staleness, position, tasks and approval requests.
`create_task` requires all frozen contract references and cannot invent default
contract or budget identities; Authority and Local API remain responsible for
authorization, digest validation, idempotency and persistence. `cancel_task`
accepts the task identifier, expected revision and explicit reason code from the
current projection/user action, then routes `RequestTaskCancellation` through
the same typed Task gateway. It does not terminate a Provider process directly
or claim cancellation completion before the Authority records the resulting
state. `decide_approval`
accepts only the decision facts copied from the current projection and routes
them through `DecideHarnessApproval`; it does not reconstruct approval context
or bypass the Policy Authority. `submit_memory_candidate`, `accept_memory` and
`revoke_memory` use the same typed Memory mutation gateway as CLI and TUI; the
Desktop process still has no Memory store handle.

## User-facing behavior

- browser preview remains explicit and does not pretend to be attached;
- the user selects a validated local daemon instance, defaulting to `default`;
- a missing daemon or rejected projection remains visible as a safe error state;
- stale projections are marked `STALE` rather than presented as current;
- task and approval identifiers remain available for correlation, while no
  secret or provider credential is displayed;
- TaskCreate and Task cancellation are explicit and contract-complete; a rejected command is surfaced
  without local fallback or direct WebView persistence;
- Approval decision is explicit: the UI displays the action digest and bounded
  request references, requires a reason code, and offers only `allow-once` or
  `deny` when the projection exposes `DECIDE_HARNESS_APPROVAL`;
- stale approval facts are rejected by the existing observation, revision and
  digest fences, with the safe Local API error surfaced to the user;
- Memory candidate submission, acceptance and revocation require explicit
  identifiers, evidence and idempotency keys; the returned receipt is shown
  only after the Memory Authority durability barrier;
- CLI, TUI and Desktop continue to share the same Rust client kernel and Local
  API contracts.

## Evidence

The following checks passed on Windows x64:

```text
cargo test -p egopulse-desktop                 passed
cargo clippy -p egopulse-desktop --all-targets -- -D warnings  passed
pnpm --filter @egopulse/desktop build           passed
```

The shared-kernel loopback acceptance also passed:

```text
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture \
  c5_05_real_desktop_surface_uses_shared_kernel_for_read_and_writes \
  -- --exact --nocapture --test-threads=1                 passed
```

It proves a Desktop-bound Client Kernel can read the real projection and send
TaskCreate plus Memory candidate commands over Windows named-pipe IPC. It does
not claim that the native Tauri window has been automated, nor does it claim
Provider/model selection, signed distribution, or final six-stage closure.
