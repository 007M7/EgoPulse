# U-03c real governed task-result review evidence

- Date: 2026-09-03
- Scope: real daemon, CLI, TUI, Authority durability and restart evidence
- Status: locally verified
- Parent flow: U-03 Result Review

## Outcome

U-03c proves that the shared U-03a result-review operation and the U-03b TUI
surface work against a real Windows `agentosd` child process over the production
local IPC and session path. The successful fixture is not a static read-model
fixture. It creates Task, Collaboration, Artifact, Claim, Evidence, ArtifactSet,
Verification and Founder Verdict facts through their production Authority
commands, applies a real Rework verdict and then waits for production projection
convergence.

The reviewed Task is `Rework`, not `Completed`. CLI and TUI review are read-only:
the Task and all five owning stores remain canonically row-for-row and
count-for-count stable before and after review. Review never issues a Verdict, changes a Task,
accepts Memory, dispatches Harness work or interprets an observation as
completion.

## Production defect found and corrected

The real chain exposed an invalid U-03a integrity assumption. A Founder Verdict
has an immutable issue `version`, while its state has an independently advancing
`revision`. Verdict consumption advances the state revision from one to two but
does not rewrite the issued Verdict version. The shared client operation had
incorrectly required the projection source revision to equal both values, making
every consumed Verdict impossible to review.

The correction keeps all identity, scope, ArtifactSet, Verification and
acceptance-contract checks. It now binds the Founder Verdict projection source
revision to the current Verdict state revision while independently requiring a
non-zero immutable Verdict version. Regression tests prove that issue version 1,
state revision 2 and source revision 2 are valid; source/state drift and a zero
issue version still fail closed. No Proto, Authority or read-model ownership
semantics changed.

## Genuine governed fixture

The successful path uses production commands to establish:

1. Task creation and activation;
2. Collaboration Run, Step and Attempt lifecycle;
3. Artifact, Claim, Evidence, sealed ArtifactSet and receipted ReturnHandoff;
4. Verification request, run, criterion result, discrepancy, unverified item and
   Verification artifact;
5. Task transition through `VerificationPending` to `VerdictPending`;
6. an explicit assertion that `VerdictPending` has no `founder_verdict_id`;
7. Founder Verdict issue followed by Task `ApplyFounderVerdict(REWORK)`;
8. durable Verdict consumption and final Task state `Rework`.

The fixture uses production projection sources. It does not insert SQL rows,
construct a successful `TaskResultReview`, use a mock Local API or bypass Task
Watch selection with a caller-supplied success identity.

## Real CLI and TUI evidence

The CLI is launched as the real `egopulse.exe` process with
`task review <task-id> --json`. It is protected by a hard timeout, kill-on-drop
and bounded kill/reap fallback. The output is checked for Task, ArtifactSet,
Verification, criterion, discrepancy, unverified and Rework Verdict facts, and
for the absence of principal, proof, workspace, native and raw Harness canaries.

The TUI evidence uses the production `ClientAttachment`, `TaskWatchController`
and `ResultReviewController`. Task Watch must discover and select the real Task;
the test does not inject a fixed Task ID into the success path. TUI and CLI expose
the same governed identities and safe facts. Attachment, controller start,
baseline acquisition and first selection share a five-second total budget.
Failure first cancels the controller and then performs bounded daemon shutdown,
kill and reap.

## Strict read-only durability oracle

The U-03c oracle lives in the existing fault-conformance boundary. Each of the
five Authority databases is opened with SQLCipher read-only flags and
`PRAGMA query_only=ON`. Every store is read inside a deferred transaction.

The caller supplies the exact expected store epoch, schema profile ID and schema
profile hash for Task, Collaboration, Artifact, Verification and Founder
Verdict. A wrong profile has an explicit fail-closed regression.

For each database, a fixed table allowlist must exactly match the discovered
table set, including `sqlite_sequence`. Missing or newly introduced tables fail
closed. Every row and column in every table is canonically encoded, stably
ordered and hashed. The snapshot also retains the governed business blobs and
event, idempotency, outbox and consumption-receipt counts. This detects object,
event, receipt, ACK, outbox, idempotency, migration and in-place row changes; it
does not merely compare selected projections.

## Restart and failure evidence

The restart test uses two distinct daemon PIDs with the same DataRoot and IPC
instance. D2 deliberately executes the same production fixture-seeding commands.
Authority exact replay, together with unchanged complete-store digests, proves
that the second start adds no durable writes. Both CLI and production TUI review
return the same governed result after restart.

The missing, permission and stale cases fail closed through real clients:

- missing: Task-stage Local API `NOT_FOUND`, non-retryable;
- permission: Evidence-stage client-kernel permission rejection;
- stale: Task-stage integrity rejection with the frozen not-ready/current detail.

Each case verifies the shared structured error, the CLI operation/category/code
mapping and the exact safe TUI category. Failures contain no partial governed
review data and no protected canaries. Authority snapshots remain unchanged.

## Automated evidence

```text
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u03c_ -- --nocapture --test-threads=1
  3 passed; 0 failed; 24 filtered

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture -- --test-threads=1
  27 passed; 0 failed

cargo test -p egopulse-client-operations task_result_review --lib -- --test-threads=1
  6 passed; 0 failed

cargo test -p egopulse-tui result_review -- --test-threads=1
  library and binary: 4 passed; 0 failed

cargo test --manifest-path contracts/toolchain/fault-conformance/Cargo.toml --lib
  17 passed; 0 failed

cargo clippy -p egopulse-agentosd -p egopulse-tui -p egopulse-client-operations --all-targets -- -D warnings
  passed

cargo clippy --manifest-path contracts/toolchain/fault-conformance/Cargo.toml --target-dir target --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
cargo fmt --manifest-path contracts/toolchain/fault-conformance/Cargo.toml -- --check
pnpm run check
git diff --check
  passed
```

The controlled contract manifest remains version `0.1.0-draft.19` with 249
artifacts and 185 fixtures. Its final manifest SHA-256 is
`243da94ae7744cccfc35320de8e4d3c92ab2430638abcf4f81dd281e38d9278e`.
Independent implementation/test review returned `GO` with P0=0, P1=0 and P2=0.
Independent architecture review also returned `GO` with P0=0, P1=0 and P2=0.
No EgoPulse C5 child process remained after the tests. The only environment
warning was the known non-blocking Windows OpenSSL `ossl_static.pdb` LNK4099
debug-symbol warning.

## Evidence boundary

U-03c proves graceful same-root restart, exact-replay stability, real local IPC,
real CLI process execution, production TUI controllers, complete Authority-store
read-only comparison and fail-closed result review. It does not claim hard-kill
restart for this slice, an interactive PTY, a real Provider/Harness execution,
artifact-byte viewing, packaged-install execution, Desktop support or Task
completion caused by review.
