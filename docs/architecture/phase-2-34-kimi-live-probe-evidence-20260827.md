# Phase 2.34 — Kimi live ACP probe evidence

Status: candidate-only; authentication required

## Probe result

The local Windows installation was probed through the existing Kimi ACP
adapter. The probe performed only ACP initialization and empty session setup;
it did not send a prompt and did not invoke model inference.

```json
{
  "candidate": "kimi-cli",
  "protocol": "agent-client-protocol",
  "prompt_sent": false,
  "model_call": false,
  "initialize": "passed",
  "session_disposition": "authentication_required"
}
```

The executable was the user-owned `kimi.cmd` installation. The probe used an
isolated temporary share directory and did not modify the EgoPulse Authority
stores.

## Reproduction

```powershell
$taskProbeDir = Join-Path $env:TEMP 'egopulse-kimi-probe-20260827'
New-Item -ItemType Directory -Force -Path $taskProbeDir
$env:EGOPULSE_KIMI_NATIVE_EXE = 'C:\Users\Administrator\AppData\Roaming\npm\kimi.cmd'
$env:EGOPULSE_KIMI_PROBE_DIR = $taskProbeDir
cargo test -p egopulse-kimi-adapter --lib `
  live_kimi_initialize_probe_is_reachable_without_promoting_capability `
  -- --ignored --nocapture
```

Observed result: `1 passed, 0 failed`.

## Admission decision

This evidence closes only the reachability/probe row. It does not admit Kimi
as a production Harness because the authenticated lifecycle is not available
in this environment. The following evidence is still required:

- authenticated session and model dispatch;
- provider-native approval routing;
- Artifact and Verification-bound return settlement;
- restart/recovery behavior;
- a reviewed capability profile and daemon composition binding.

Until those rows pass, Codex remains the sole production Harness. Kimi also
cannot be granted a Memory candidate producer handle merely because its ACP
process is reachable; its producer identity and scope must be configured only
after the provider lifecycle is admitted.
