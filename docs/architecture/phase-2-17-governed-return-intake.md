# Phase 2-17 governed Harness return intake

- Status: technical intake, Attempt-return projection and Verification-gated
  Step completion implemented and re-proven through the real Windows x64
  user-owned Codex production runner; Task completion and Founder Verdict
  consumption remain outside this phase
- Date: 2026-08-27
- Scope: native terminal output through technical Artifact Authority receipt
- Not in scope: Task completion and Founder Verdict consumption

## Ownership-preserving flow

```text
native Harness driver
  -> TerminalOutputCandidate (provider-neutral, one-shot)
  -> Adapter Edge transaction
       terminal ExecutionCompleted observation
       + output outbox record
       + dispatch / fence / Task-work lineage binding
  -> governed return collector
  -> Artifact Authority commands
       blob put -> Artifact stage/seal
       -> truthful collector Claim + non-independent Evidence
       -> ArtifactSet create/seal
       -> ReturnHandoff
  -> technical ReturnReceipt
       evidence intake = true
       verification = false
       task completion = false
  -> exact-digest Adapter Edge acknowledgement
  -> Collaboration runner
       receipt digest + consumed terminal sequence + current fence/revisions
       -> Attempt RETURNED; Run/Step RETURN_PENDING
       -> when Verification proof is available, internal Collaboration writer
          retries CommitStepReturn with a separate principal
       -> Verification Authority / Sego result resolver
       exact sealed ArtifactSet + Receipted ReturnHandoff
       + exactly one matching accepted Verification artifact
       -> guarded CommitStepReturn
       -> Step/Run RETURNED
```

No component gains a second fact store writer. Collaboration supplies authoritative Task/work
lineage, Adapter Edge owns native evidence and delivery recovery, the collector is orchestration
only, Artifact Authority remains the sole writer of Artifact/Claim/Evidence/ArtifactSet and
ReturnReceipt facts, and the Collaboration runner remains the sole writer of Attempt/Run/Step
facts.

## Recovery and failure semantics

- Observation and terminal candidate publication are one Adapter Edge transaction.
- IDs and Authority idempotency keys derive from immutable dispatch/message identity.
- A crash before the receipt leaves the candidate pending; replay resumes the same Authority chain.
- A crash after Authority commit but before Adapter acknowledgement replays to the same receipt and
  then settles the candidate.
- A crash after `ReturnRecorded` but before Authority outbox acknowledgement replays the same
  idempotency key; the outbox is acknowledged only after the Collaboration event is durable.
- Reuse of a source identity with another digest and direct storage tampering fail closed.
- Verification-gated return additionally recomputes the Verification Authority canonical payload
  digest; a merely well-formed or stale SHA-256 field is not accepted.
- The production Harness runner now keeps the Artifact return outbox pending when the
  Verification-gated Step return is not yet provable; it retries the same deterministic command
  and only ACKs the Artifact outbox after Step/Run return is committed or replayed.
- Normal Sego/model review keeps the conservative meaning of zero findings: it maps to
  `Unverified`, not `Passed`. A zero-finding `Passed` result is available only through an explicit
  `positive_acceptance` configuration, and bootstrap validation requires the checker profile to be
  `Deterministic`. This is an acceptance-checker mode for a bounded deterministic contract, not a
  way for a model reviewer to self-certify its own output.
- The acceptance checker still has to emit the same structured review contract, match scope,
  diff-hash, reviewer, engine and review-mode, and bind its raw output to the collected Artifact
  Authority artifact. The resulting Verification artifact remains subject to the normal canonical
  payload, lineage, ArtifactSet and ReturnHandoff checks.
- Once the technical Attempt return is already durable, the retry path does not issue a second
  `RecordAttemptReturn` with changed CAS revisions; it proceeds directly to the Verification-gated
  Step return. This preserves both idempotency-key digest stability and single-writer ownership.
- Empty output, output over 16 MiB and policy rejection enter `held`; they do not create a fake
  artifact or silently disappear.
- The oversized record retains a 64 KiB preview for diagnosis plus full digest and original size.

## Local evidence

The focused gate covers Harness Adapter, Codex Adapter, DSH Adapter, Artifact Authority,
Collaboration Control and `agentosd` return-collector/projection composition:

```powershell
cargo test `
  -p egopulse-harness-adapter `
  -p egopulse-codex-adapter `
  -p egopulse-dsh-adapter `
  -p egopulse-artifact-authority `
  -p egopulse-local-ide-control `
  -p egopulse-agentosd --quiet
```

Result on Windows x64: all selected suites passed. The tests include atomic/reopen recovery,
idempotent replay, conflicting replay, storage tamper, bounded oversized output, empty-output hold,
collector replay, destination-specific Authority outbox acknowledgement, consumed-candidate
lookup and the real Collaboration dispatch ordering that persists an envelope before binding Task
lineage. Collaboration tests also prove unauthorized Harness return writes, ArtifactAuthority
return ownership, fence/sequence checks, Attempt idempotency and that Step/Task completion does
not occur at technical intake.

## Current boundary and next boundary

The shared CLI/TUI kernel now exposes the projected `ReturnPending`/`Returned`
counts. The real Windows C5 fixture proves that a daemon-backed TaskView with
`RUN_STATUS_RETURN_PENDING` is visible consistently through both processes.
The production runner now also invokes the Verification-gated Step return internally.
The local durable G4-03 suite proves the Collaboration write contract and the
`TaskActivationGuardSet` Verification delegation, while the C5 daemon fixture
proves the real Windows daemon/read path. The new G4-11 fixture additionally opens
the real Artifact Authority and Verification Authority stores, submits a sealed
ArtifactSet/receipted ReturnHandoff, completes an accepted VerificationArtifact,
and proves that the production resolver joins those authorities against the typed
Collaboration lineage. The daemon composition now exposes an explicit
`NativeHarnessDriver` injection boundary: Codex remains the default driver, while
deterministic fixtures can exercise the same production runner and collector without
  replacing any Authority or Collaboration writer. A real Rust Codex adapter E2E now
  probes the installed app-server, starts a real thread/turn, accepts Codex's optional
  startup warning as an informational diagnostic, and proves the terminal output
  candidate reaches `EGOPULSE_CODEX_E2E_OK`. This is provider/adapter evidence only;
  the daemon + Harness execution with a committed Verification artifact remains a
  separate settlement gate.
An agentosd composition test now proves that the real daemon background worker polls
an injected `HarnessDispatchRunner` and shuts down cleanly; this proves worker wiring,
not provider-specific Codex protocol behavior. The authenticated Windows x64 adapter
probe was re-run with the user-owned Codex executable and passed the real app-server
initialize/thread/turn lifecycle. The ignored `production_runner_g4_04` Gate then
passed on 2026-08-27 in 30.94 seconds with eight isolated Authority keys. It proved
Task activation, real Codex dispatch, terminal output collection, Task evidence
submission, Verification request intake, deterministic checker execution, Verification
write-back, and one Verification-gated Collaboration Step/Run return settlement.
The test now asserts `return_settlements == 1`; it does not infer `Returned` from a
quiet cycle or from a technical Artifact receipt.

The latest local evidence is:

```text
egopulse-agentosd library tests                 46 passed
collaboration_control_g4_03                    22 passed
c5_00_daemon_fixture                             7 passed
  return_settlement_g4_11                          1 passed
  cargo clippy --workspace --all-targets -D warnings passed
  real Codex app-server Rust E2E                   passed (user-owned Windows x64 Codex)
  real production runner + collector Gate          passed (30.94s; return_settlements=1)
  Sego default zero-findings semantics              passed (Unverified)
  Sego deterministic acceptance mode               passed (Passed + Complete)
```

The earlier unprivileged sandbox run that returned `CODEX_APP_SERVER_EOF` is retained as
environment-diagnostic evidence only. Re-running the same user-owned executable with the
required Windows process access passed; the EOF was not a Codex protocol defect. The
production fixture also exposed and fixed three real contract defects before acceptance:
Task handoff lineage advances one revision after evidence submission, checker assurance is
bound to the attested profile, and an Artifact output must not be mislabeled as Evidence.

Continue the next side without widening collector authority:

1. close the separately governed Task verification-to-Verdict path;
2. add the Founder Verdict acceptance/rejection vertical and its CLI/TUI projections;
3. keep the second Harness candidate outside production until it meets the same provider,
   recovery, Artifact, Verification and Return gates.
