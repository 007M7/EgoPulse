# Phase 2-61 - TUI Task Watch evidence

## Scope

U-01b adds an explicit, observation-only Task Watch page to the existing terminal UI. It does not add or change Proto, Local API, Authority, persistence schema, CLI, Provider, Memory, Desktop, or Task transition behavior. The reusable production controller lives in `egopulse-tui::task_watch`; both the TUI binary and acceptance test drive that same seam. It consumes only `egopulse-client-operations::TaskWatch` and its request, update, classification, and error types; it does not own a generated watch client, raw stream frame, or `SnapshotStreamTracker`.

## Behavior proved

- `w` on the Dashboard obtains one complete projection baseline and starts the watch from that baseline position.
- The background channel is bounded to 32 messages. Every message carries a generation and stale generations are ignored.
- Applied updates replace a Task by its authoritative Task id. Replay and Heartbeat update stream position and liveness only; they do not change Task facts.
- Reset is a barrier: the old worker is stopped, one complete baseline is fetched and atomically installed, and a new generation starts from the new position.
- EOF and transport failures mark the page stale and use the bounded delays `250/500/1000/2000/2000` milliseconds. Kernel and stream-integrity failures stop fail-closed.
- `Esc` cancels and joins the worker before returning to a freshly loaded Dashboard. `r` performs the same bounded cleanup before a full refetch. `q` cleans up before exit. A timeout aborts the worker, and `Drop` remains a last-resort abort guard.
- Dashboard periodic polling is disabled while the Task Watch page is active.

## Automated evidence

The library controller tests replace the deleted binary-local reducer/worker copies. `controller_reset_generation_fence_integrity_and_no_false_completion` covers reset/refetch, stale-generation rejection, stable Task-id ordering, replay/heartbeat fact preservation, no false completion, and integrity fail-closed cleanup. `full_channel_cancellation_and_runtime_stop_drop_are_deterministic` covers a full 32-entry channel using reserve notification rather than timing guesses, cancellation, normal join, timeout/abort, and Drop termination. `eof_exact_cursor_permission_no_retry_and_finite_budget_use_worker_seam` covers exact-cursor EOF reconnect, permission/API no-retry, the five-delay budget, finite open/next counts, and no hot loop. Binary tests retain only surface responsibilities: `task_watch_page_renders_explicit_live_and_stale_state`, `task_watch_production_action_handler_cleans_up_escape_refetch_quit_and_error`, and `task_watch_reconnect_schedule_and_page_keys_are_frozen` exercise `TestBackend`, the production async action handler for `Esc`/`r`/`q`, abnormal-session cleanup, and visible keys/schedule.

The Windows C5 test `u01b_real_daemon_production_controller_observes_without_task_mutation` starts the real fixture daemon, injects its real TUI-surface `ClientAttachment` into `TaskWatchController`, and lets that production controller obtain the complete baseline and resume at the exact cursor. The existing governed TUI Task-create path then triggers a real projection update. Before the controller consumes it, the test saves both the daemon projection and a SQLCipher read-only Task Authority oracle. After `pump`, it compares the controller page model with the Authority-backed projection and exact durable Task snapshot, proves the Task/event facts did not change, and proves the target is not Completed. This is explicitly a real-daemon/production-controller/client seam test, not an automated Windows console, PTY, keyboard, or terminal-rendering E2E. The `w`, `Esc`, `r`, and `q` action handling remains covered by TUI component tests.

## Validation commands

```text
cargo test -p egopulse-tui
cargo check -p egopulse-tui
cargo clippy -p egopulse-tui --all-targets -- -D warnings
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u01b_real_daemon_production_controller_observes_without_task_mutation -- --exact --nocapture --test-threads=1
cargo fmt --all -- --check
git diff --check
```

## Evidence boundary

This is Task projection viewing, not the complete R-9B observation-streaming product. It does not prove a real Windows PTY/keyboard session, packaged-terminal behavior, long-duration reconnect reliability, concurrent old/new daemon operation, or terminal-rendering fidelity. No watch update advances Task, Collaboration, Context, Verdict, Provider, or Memory state.
