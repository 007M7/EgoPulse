# Phase 2-22: DSH governed return settlement evidence

## Status

Implemented and locally verified against the configured Windows x64 DSH ACP
replay workspace. This phase proves the candidate output handoff and governed
return settlement path. It does not promote DSH to production and does not
claim native session recovery.

## Closed evidence path

```text
real DSH ACP replay
        |
        v
DshAcpDriver: session/prompt + end_turn
        |
        v
GovernedHarnessAdapter::pump_one
        |
        v
Adapter Edge terminal-output outbox
        |
        v
GovernedReturnCollectorRunner
        |
        +--> Artifact Authority blob
        +--> Artifact + Claim + Evidence
        +--> ArtifactSet + ReturnHandoff
        +--> technical return receipt
```

The DSH driver only exposes a `TerminalOutputCandidate`. Adapter Edge binds
the candidate to the terminal observation, dispatch envelope and task lineage;
the collector is the only component that creates Artifact Authority facts.

## Implementation

`apps/agentosd/tests/dsh_return_settlement.rs` is an ignored real-process
integration test. It uses the existing compiled DSH ACP replay fixture and:

1. prepares a dispatch and binds task lineage in Adapter Edge;
2. dispatches through `GovernedHarnessAdapter` using `DshAcpDriver`;
3. pumps the real terminal lifecycle and persists the output candidate;
4. opens a second Adapter Edge connection, as production composition does;
5. runs `GovernedReturnCollectorRunner`;
6. verifies one Artifact, Claim, Evidence, ArtifactSet, ReturnHandoff and
   technical return receipt, with no pending terminal candidate left behind.

The test also uses a bounded cleanup retry because Windows may hold the DSH
process workspace briefly after the supervised child exits. Exhausting the
retry remains a test failure.

## Verification evidence

The real local command was:

```powershell
$env:EGOPULSE_DSH_REPLAY_ROOT = 'D:\deepseek harness\deepseek-harness-git'
$env:EGOPULSE_DSH_NODE = 'C:\Program Files\nodejs\node.exe'
cargo test -p egopulse-agentosd --test dsh_return_settlement -- --ignored --nocapture
```

Result:

```text
1 passed, 0 failed
```

The test is intentionally `ignored` in the default suite because it requires
the user-owned DSH source and Node executable. Its successful run is real
candidate evidence, not an automatic capability attestation.

## Remaining admission boundary

DSH still reports native `session/load`/`session/resume` as unsupported, so a
restart cannot be represented as native recovery. Its capability profile also
does not yet satisfy the complete production Artifact/recovery contract under
the reviewed admission process. DSH therefore remains candidate-only. The
next admission decision still requires an explicit recovery policy/evidence
and capability attestation; this phase cannot be used to bypass either gate.
