# U-02c TUI governed approval queue evidence

- Date: 2026-09-03
- Scope: TUI actionable approval queue and explicit guided decision
- Status: locally verified
- Parent flow: U-02 Approval Watch and guided decision

## Outcome

U-02c composes the opaque approval baseline/session from U-02a and the shared
guided decision operation from U-02b into the production TUI. The TUI stores
only a safe page DTO containing approval and Task identities, keeps selection
by approval identity, and uses the same attached client for queue observation
and decision dispatch.

The page is reachable from the Dashboard with `a`. `Up` and `Down` move the
identity-backed selection, `Enter` opens an explicit decision modal, `r`
performs a full bounded refetch, and `Esc` returns to the Dashboard after
stopping the worker. Task Watch and Approval Queue runtimes are mutually
exclusive and are cleaned up before a surface transition or quit.

No Proto, Local API, Authority, database schema, Provider, Memory, Desktop, or
Task transition contract changes in this slice.

## Ownership and safety behavior

- `egopulse-tui::approval_queue::ApprovalQueueController` delegates baseline
  acquisition, baseline consumption, stream validation, queue reduction and
  guided command construction to `egopulse-client-operations`. It does not own
  a raw generated watch client, `HarnessApprovalViewStreamFrame`,
  `SnapshotStreamTracker`, `PolicyDecisionCommand`, or expected binding fields.
- Baseline installation is atomic. Reset stops use of the old stream, performs
  a complete refetch and replaces the page model before reading the replacement
  stream. Controller restarts use a generation fence, so events from an older
  controller lifecycle cannot mutate the model.
- EOF and retryable transport failures reconnect with the bounded delays
  `250/500/1000/2000/2000` milliseconds. Permission, protocol and integrity
  failures stop fail-closed. The channel is bounded to 32 entries; cancellation
  remains effective under backpressure, and stop has a timeout plus abort
  fallback.
- The modal has no default decision. It accepts only an explicit existing
  decision, a non-empty reason and an optional confirmation proof reference.
  `Esc` dispatches nothing, repeated `Enter` while submitting dispatches once,
  and an approval that disappeared from the current queue cannot be submitted.
- A successful decision is not removed optimistically. The queue changes only
  after the authoritative approval projection reports that the item is no
  longer actionable. An Authority commit accompanied by a projection warning
  keeps the committed receipt and explicitly instructs the user not to retry
  the decision; the safe recovery is to refresh the queue.

## Historical-view position defect and correction

During U-02c acceptance, a real daemon fixture exposed a defect in approval
baseline compilation: each historical approval view had been validated as if
its metadata position were the page's global projection position. An unrelated
domain may legitimately advance the global projection after an approval view
was last updated, so this produced an `IncompleteStreamFrame` false failure.

The compiler now validates every historical view independently at the view's
own metadata position, then requires that position to use the page epoch and
not exceed the page snapshot sequence. Regression evidence covers a global
page position ahead of historical view positions, plus fail-closed cases for a
future view sequence and a foreign epoch. Runtime stream ordering and digest
integrity rules remain unchanged.

## Automated evidence

The focused local verification completed with these results:

```text
cargo test -p egopulse-tui --lib
  11 passed; 0 failed

cargo test -p egopulse-tui --bin egopulse-tui
  24 passed; 0 failed

cargo test -p egopulse-client-operations
  30 passed; 0 failed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u02c_real_daemon_seeded_projection_uses_production_approval_queue_controller -- --exact --nocapture --test-threads=1
  1 passed; 0 failed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture c5_04_real_cli_rejects_malformed_await_and_submits_guided_approval -- --exact --nocapture --test-threads=1
  1 passed; 0 failed

cargo clippy -p egopulse-tui --all-targets -- -D warnings
  passed

cargo clippy -p egopulse-client-operations --all-targets -- -D warnings
  passed

cargo clippy -p egopulse-agentosd --test c5_00_daemon_fixture -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The U-02c C5 starts the real Windows daemon and Local IPC surface, uses the
production TUI approval controller, dispatches through the shared guided
operation, waits for the read-model item to leave the actionable queue, and
then reads the encrypted Policy Authority store as a typed persistence oracle.
It proves one issued decision with the expected binding and proves the Task
remains Active rather than being falsely completed.

The final anti-false-positive delta additionally proves cancellation while the
32-entry worker channel is full, stream release on explicit stop and Drop, old
generation event rejection, deterministic delivery of integrity failure,
Task-Watch/Approval-Queue lifecycle exclusion in one production App seam,
modal `Esc` with zero decision calls, repeated `Enter` with one decision call,
and a candidate disappearing after modal creation with zero decision calls.

## Evidence boundary

The C5 uses `StaticApprovalProjectionSource` to seed a deterministic approval
projection. It therefore proves daemon/IPC/read-model/controller/shared
decision/Policy-persistence composition, but does not prove the production
Adapter's complete approval-generation lifecycle. It is not a Windows PTY,
real-keyboard, packaged-terminal, long-duration reconnect, or concurrent
old/new daemon test. It does not claim R-9B/R-9C observation streaming,
Desktop, Provider admission, Memory/RAG admission, or release readiness.
