# U-05d real-daemon execution and recovery read evidence

- Date: 2026-09-04
- Scope: real daemon, Windows IPC, CLI and production TUI Task Watch read evidence
- Status: locally verified
- Parent flow: U-05 user-readable execution and recovery review

## Outcome

U-05d exercises the U-05a governed Task baseline/session through an independent
fixture daemon and the existing Windows IPC transport. It reuses the U-03c
production Authority fixture and its strict SQLCipher read-only conformance
oracle. No production runtime, Proto, Local API, Authority, database schema,
permission profile or fixture mode changed.

After D1 reports ready, and before constructing any `ClientAttachment` or
starting a CLI/TUI read, the conformance oracle opens the Task store with
`SQLITE_OPEN_READ_ONLY` plus `query_only`, validates its metadata/profile,
event sequence and fixed table-set digest, requires exactly one durable Task,
and discovers that non-empty Task identity. The complete five-Authority
durability baseline is captured from that identity before the first client
observation.

The fixture's formal Authority commands establish one Task in Rework with a
Returned Run, Step and Attempt. The production TUI `TaskWatchController` uses a
real `ClientSurface::Tui` attachment, publishes its safe baseline, opens the
consume-bound session and reaches Live. Its safe DTO preserves the Task, Run,
Step and Attempt identities, revisions and typed statuses. In particular, the
Returned execution tree never causes the Rework Task to be presented as
Completed.

The real `egopulse.exe` subprocess executes:

```text
egopulse task watch --frames 1 --json
```

with a 30-second hard timeout and bounded kill/reap fallback. Its NDJSON output
contains exactly one complete baseline followed by one live Heartbeat. The
baseline contains the same Rework/Returned fact tree; the Heartbeat carries no
Task. Both records use `egopulse.cli.task-watch/v1`. Output checks exclude the
fixture's principal, proof, workspace and raw-content canaries plus native and
session sentinels.

## Disconnect and same-root restart

The D1 Task Watch controller remains active while D1 shuts down gracefully.
Within eight seconds it exhausts the fixed reconnect schedule, reaches
FatalStopped and shows exactly `Task Watch stopped after bounded reconnect
attempts`. The last safe Task facts remain unchanged, and the stop message
contains neither the fixture root path nor any sensitive sentinel. Controller
shutdown and process reap are bounded.

D2 then starts as a distinct PID with the same data root and IPC instance. The
fixture deliberately invokes the same production Authority seeding commands;
Authority exact replay, rather than absence of those calls, is evidenced by
unchanged fixed-table counts and digests. A new production TUI controller
reaches Live and returns the same Task, Run, Step and Attempt identities,
revisions and statuses as D1.

After D2 reports ready, the same strict discovery and complete five-Authority
oracle are run again before the second attachment/controller is created. They
prove the sole Task identity and full durable state already equal the D1
pre-client baseline.

Before and after the CLI read, D1 disconnect, D2 production replay, D2 read and
final shutdown, `read_governed_result_durability` reports identical snapshots
and deterministic table counts/digests for the Task, Collaboration, Artifact,
Verification and Founder Verdict Authority stores. The oracle opens SQLCipher
read-only/query-only transactions and owns no write or migration capability.

## Collaboration and change boundary

Approximately 30 percent of this slice's C5 compatibility groundwork was
prepared on the isolated ZCode branch and integrated as `3208429` (47 added and
6 removed lines), including bounded CLI process support and existing C5 Task
Watch compatibility work. The remaining U-05d real-daemon scenario, safety
assertions, disconnect/restart evidence and this document were completed on the
main worktree after that integration. The resulting product change remains
test-only.

Changed files for the complete slice are limited to:

- `apps/agentosd/tests/c5_00_daemon_fixture.rs`
- `contracts/toolchain/fault-conformance/src/u03c_result_review.rs`
- `docs/architecture/phase-2-74-u05-real-daemon-execution-recovery-evidence-20260904.md`

## Verification

Local verification completed with:

```text
cargo check -p egopulse-agentosd --test c5_00_daemon_fixture
  passed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u05d_real_daemon_tui_baseline_is_read_only -- --exact --nocapture --test-threads=1
  1 passed; 0 failed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture c5_03_real_cli_process_completes_owner_writes_and_awaits_projection -- --exact --nocapture --test-threads=1
  passed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u01b_real_daemon_production_controller_observes_without_task_mutation -- --exact --nocapture --test-threads=1
  passed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture u04c_production_tui_controllers_share_attachment_and_select_exact_confirmed_task -- --exact --nocapture --test-threads=1
  passed

cargo clippy -p egopulse-agentosd --test c5_00_daemon_fixture -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

Windows linking may emit the existing missing `ossl_static.pdb` LNK4099
debug-symbol warning. It does not change the successful command results.

## Explicit boundary

This evidence is a fixture-daemon graceful shutdown and same-root restart. It
does not prove a hard-kill crash window, packaged installation, PTY/keyboard
interaction, live ResetRequired rebasing, retention or compaction behavior,
coordinated Task/Approval cursors, or an active retry, resume or recover write
operation. Those remain R-9B or a separately frozen U-05R scope. It also does
not change the semantic RAG admission state or claim that U-05 supplies a
mutation surface.
