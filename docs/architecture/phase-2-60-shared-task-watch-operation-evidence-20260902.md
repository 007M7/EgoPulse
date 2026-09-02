# Phase 2-60 - Shared Task watch operation evidence

- Date: 2026-09-02
- Scope: shared Rust client operation and CLI compatibility
- Status: locally implemented and verified

## Scope and ownership

This slice moves Task projection watch ownership from the CLI into
`egopulse-client-operations`. `ClientAttachment::open_task_watch` now owns the
existing session metadata, `WatchTaskViews` RPC, tonic stream, and
`SnapshotStreamTracker`. The CLI owns only bounded presentation and recovery
messaging; it no longer constructs the protobuf watch request or applies Task
frames directly.

No Proto, Local API, Authority, persistence schema, Provider, Desktop, or TUI
UI behavior changes are part of this slice. TUI adoption remains a separate
follow-up slice.

## Verified behavior

The shared operation:

- classifies applied snapshots, exact replays, heartbeats, and reset barriers
  with the existing tracker rather than duplicating its digest/order logic;
- preserves replays as returned updates and permits distinct entities at the
  same projection position;
- rejects unknown kinds, incomplete frame shapes, conflicting replay digests,
  epoch/order drift, malformed reset reasons, and transport errors;
- treats reset as a one-way barrier: it returns the reset update once and
  refuses any subsequent read on that watch;
- constructs session metadata exactly once when opening the stream and does
  not spawn a background reader.

The CLI retains its existing flags and JSON/text schema. It now explicitly
rejects `frames=0` and `frames>1000`, requires the resume epoch/sequence pair,
counts replay frames toward the requested bound, fails on EOF before the exact
requested count, and drops the watch immediately after reaching that count.
Transport, stream protocol, reset, and premature-EOF failures remain typed and
separately diagnosable before CLI presentation mapping.

## Anti-false-green evidence

- The production open path and its test share `open_task_watch_via`; a captured
  request proves the authenticated surface, client, session, negotiated
  contract, resume cursor, and exact RPC permission. A denied permission
  produces zero dispatch calls.
- The production `TaskWatch::next_update` and scripted tests share
  `next_task_watch_update_via`. After a reset, a second call returns the reset
  barrier without invoking the injected message source; EOF and transport
  failures are independently witnessed.
- The production CLI calls the same generic consume loop used by scripted
  tests. Poll and drop counters prove exact-N polling, zero/partial EOF,
  transport failure, no poll after reset, and source destruction at scope end.
- Reset-shape tests include missing, empty, over-128-byte, control-character,
  Unicode, snapshot-bearing, and misplaced-reason variants.

## Evidence boundary

This is a bounded Task projection snapshot stream wrapper. It is not complete
R-9B observation streaming, does not add run-result resume semantics, and does
not introduce `WorkSession` or `WorkRequest` contracts.
