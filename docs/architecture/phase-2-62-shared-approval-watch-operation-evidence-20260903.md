# Phase 2-62 - Shared approval watch operation evidence (2026-09-03)

## Scope

U-02a moves approval-watch protocol ownership from the CLI into
`egopulse-client-operations`. It does not change Proto, Local API, Authority,
database schemas, approval-decision commands, or the TUI.

## Production boundary

- `ClientAttachment::read_actionable_approval_queue` obtains one actionable
  baseline with
  `ListHarnessApprovalViews(actionable_only=true, page_size=100)` and follows
  every cursor before publishing any baseline result. The production method
  delegates authorization, one-time session metadata construction, every wire
  request, online item/cursor limits, and atomic compilation to one injectable
  async operation seam rather than maintaining a second pagination loop.
- The baseline rejects inconsistent positions, missing or repeated identities,
  empty/non-advancing/repeated cursors, incomplete pagination, malformed views,
  and more than 1,000 returned views.
- `open_approval_queue_from` consumes that opaque baseline and starts only at
  its private, non-replaceable position. The subsequent stream is always
  `WatchHarnessApprovalViews(actionable_only=false)`. This preserves a governed
  update when an approval loses actionability.
- Explicit CLI resume uses the separate, stream-only
  `open_approval_watch_resume`; CLI without resume uses the separate
  current-tail stream. Neither path carries an initial queue map.
  `ApprovalWatch` privately owns the tonic stream and
  `SnapshotStreamTracker`. An applied view containing the explicit
  `DECIDE_HARNESS_APPROVAL` action is upserted by `approval_request_id`; an
  applied, valid view without it removes that ID. Unknown action kinds fail
  closed before changing the queue. A queue session rejects position rollback
  and an epoch change without reset, while accepting processor-classified
  applied frames for different approval IDs at the same projection position.
  The tracker rejects a conflicting digest for the same ID and position.
  Replay and heartbeat frames do not change queue facts, and reset is a
  terminal refetch barrier for that watch.
- `ActionableApproval` has no public constructor and exposes the complete
  daemon-authored view only by immutable reference, plus read-only guided
  decision binding getters.
- The CLI renders the shared `ApprovalWatchUpdate` while retaining its existing
  JSON and text fields. It no longer owns the generated watch client, raw
  approval frames, or a stream tracker.

## Anti-false-positive evidence

The focused tests cover two-page completion and deterministic ordering, the
1,001st-item hard failure, position/cursor/identity drift, unknown-action
failure without removal, leaving-filter removal, replay/heartbeat non-mutation,
same-position multi-entity application with same-entity conflict rejection,
position rollback rejection, reset no-extra-poll, EOF/transport state
preservation, and CLI output/error compatibility. The production baseline seam
is directly exercised for permission-before-dispatch, exact two-page request
cursor chaining, position drift, repeated/empty cursors, the online 1,001st-item
barrier, API errors, and transport errors; every failure returns without an
opaque baseline value. These are read-model RPCs only; the operation contains
no command RPC and cannot advance Task or approval Authority state.

## Boundary not claimed

This slice does not add a TUI approval experience, guided decision execution,
automatic retry, cross-process recovery orchestration, or a new observation
stream contract. An explicit historical resume is intentionally not a complete
actionable queue; callers needing that claim must consume an opaque baseline
through `open_approval_queue_from`.

## Verification

Run:

```text
cargo test -p egopulse-client-operations
cargo test -p egopulse-cli --bin egopulse approval_watch -- --test-threads=1
cargo check -p egopulse-client-operations -p egopulse-cli
cargo clippy -p egopulse-client-operations -p egopulse-cli --all-targets -- -D warnings
cargo fmt --all -- --check
pnpm run check
git diff --check
```
