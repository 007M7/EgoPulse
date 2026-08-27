# Phase 2-29: DSH ACP replay re-run

- Date: 2026-08-27
- Scope: Windows x64 local candidate evidence
- Production impact: none; Codex remains the sole production Harness
- Candidate: DeepSeek Harness ACP adapter

## Result

The configured local DSH replay matrix was re-run after the heterogeneous
multi-Harness composition change in `32e1605`. All three scenarios passed:

| Scenario | Result |
| --- | --- |
| terminal lifecycle / committed completion | passed |
| native `session/cancel` and interrupted terminal observation | passed |
| native permission request routed through governed decision | passed |

The replay uses the user-owned compiled DSH ACP fixture and does not make a
model/API call. It validates the provider-specific process and ACP seam, not
the EgoPulse production capability-attestation decision.

## Reproduction

```powershell
$env:EGOPULSE_DSH_REPLAY_ROOT = 'D:\deepseek harness\deepseek-harness-git'
$env:EGOPULSE_DSH_NODE = 'C:\Program Files\nodejs\node.exe'
cargo test -p egopulse-dsh-adapter --test replay -- --ignored --nocapture
```

Observed result:

```text
running 3 tests
test dsh_replay_driver_emits_terminal_lifecycle ... ok
test dsh_replay_driver_sends_native_cancel_and_observes_interruption ... ok
test dsh_replay_driver_routes_native_permission_through_governed_decision ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

The Windows linker emitted missing OpenSSL PDB (`LNK4099`) warnings while
building the test binary, but the process exited successfully and the test
result was unaffected. These are diagnostic-symbol warnings, not a runtime
or contract failure.

The application-level recovery-hold fixture also passed:

```text
cargo test -p egopulse-agentosd --test dsh_recovery_hold -- --test-threads=1 --nocapture
test dsh_unknown_recovery_is_durable_and_never_auto_redispatched ... ok
test result: ok. 1 passed; 0 failed
```

It starts no DSH process. It seeds an Adapter Edge delivery-unknown state,
invokes the real DSH driver's explicit unsupported-recovery finding, reopens
the Edge through a fresh governed adapter, and verifies that the same
`OutcomeUnknown` evidence is replayed. No second dispatch is created.

## Admission boundary remains open

This re-run does not provide any of the following missing evidence:

- authenticated model-backed DSH lifecycle;
- native `session/load` or `session/resume` recovery;
- an independently attested DSH protocol schema digest;
- a provider-native Artifact return contract.

The existing governed return-settlement test proves that a DSH terminal output
candidate can be passed through EgoPulse's Adapter Edge and Return Collector.
That is an EgoPulse-owned settlement path, not native DSH Artifact semantics.
Until the recovery policy and capability attestation are explicitly admitted,
DSH remains a candidate-only driver and cannot be selected by a production
`StepPlan`.
