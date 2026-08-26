# Phase 2-17 governed Harness return intake

- Status: implementation complete; local focused gate passed
- Date: 2026-08-26
- Scope: native terminal output through technical Artifact Authority receipt
- Not in scope: verification verdict, Attempt return decision, Step commit or Task completion

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
```

No component gains a second fact store writer. Collaboration supplies authoritative Task/work
lineage, Adapter Edge owns native evidence and delivery recovery, the collector is orchestration
only, and Artifact Authority remains the sole writer of Artifact/Claim/Evidence/ArtifactSet and
ReturnReceipt facts.

## Recovery and failure semantics

- Observation and terminal candidate publication are one Adapter Edge transaction.
- IDs and Authority idempotency keys derive from immutable dispatch/message identity.
- A crash before the receipt leaves the candidate pending; replay resumes the same Authority chain.
- A crash after Authority commit but before Adapter acknowledgement replays to the same receipt and
  then settles the candidate.
- Reuse of a source identity with another digest and direct storage tampering fail closed.
- Empty output, output over 16 MiB and policy rejection enter `held`; they do not create a fake
  artifact or silently disappear.
- The oversized record retains a 64 KiB preview for diagnosis plus full digest and original size.

## Local evidence

The focused gate covers Harness Adapter, Codex Adapter, DSH Adapter, Artifact Authority,
Collaboration Control and `agentosd` return-collector composition:

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
collector replay and the real Collaboration dispatch ordering that persists an envelope before
binding Task lineage.

## Next boundary

Implement the receipt-consumer side without widening collector authority:

1. project the Artifact Authority receipt outbox into a typed, digest-bound Collaboration input;
2. record the Attempt return exactly once under the active fence;
3. request Sego verification using sealed Artifact Authority references;
4. commit the Step only from the governed verification result;
5. expose the resulting state through the shared CLI/TUI kernel.
