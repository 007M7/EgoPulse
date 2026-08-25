# Phase 2-03 Windows x64 executable discovery

This is the first, zero-API-call slice of the candidate Harness probe. It only
checks that the locally configured command entry point exists and can report a
version. It is not a capability attestation and it does not authorize any
candidate for a reviewed `StepPlan`.

Probe date: 2026-08-26 (Asia/Shanghai)

## Observed command entry points

| Candidate | Local entry point | Version output | Result |
| --- | --- | --- | --- |
| Codex | `C:\Users\Administrator\AppData\Roaming\npm\codex.cmd` | `codex-cli 0.148.0-alpha.15` | Executable discovery passed; existing native app-server probe remains the reference |
| Kimi CLI | `C:\Users\Administrator\AppData\Roaming\npm\kimi.cmd` → `C:\Users\Administrator\.local\bin\kimi.exe` | `kimi, version 1.49.0` | Executable, ACP initialize and empty-session boundary probed; dispatch/lifecycle attestation pending |
| DeepSeek Harness | `D:\deepseek harness\dsh.cmd` | `0.1.0-rc.5` | Executable discovery and isolated CLI profile bootstrap passed; structured protocol probe pending |

The Codex version command emitted a non-fatal warning about cleaning stale
temporary argument-alias directories under the user's Codex directory. The
version command still exited successfully. This is an environment permission
observation, not a Harness capability result.

## What this proves and does not prove

This slice proves only local executable discoverability and version reporting.
It does not prove structured dispatch, approval routing, event ordering,
cancellation, restart reconciliation, artifact return or model isolation.
Those rows require the candidate's native protocol and must run through the
shared Probe Gate before any capability profile can become `ProbeVerified`.

## Next probe order

1. Keep Codex as the active reference and retain its existing app-server
   contract fixture.
2. Inspect Kimi CLI's machine-readable/non-interactive protocol boundary. If
   it exposes only terminal text, record it as process-only or unsupported
   rather than emulating lifecycle truth.
3. Inspect DeepSeek Harness's local CLI/runtime boundary and identify whether
   structured events, approvals and reconciliation are native or internal-only.
4. Run the first no-side-effect dispatch fixture only for a candidate whose
   protocol fingerprint can be independently recorded.
