# Phase 2-47 Provider capability evidence

- Date: 2026-08-27
- Scope: DeepSeek Harness, Kimi CLI, GLM/OpenCode
- Decision: extend candidate evidence; do not change production admission

## Current boundary

Provider configuration and Provider capability are separate facts. The
configured model catalog is an offline fallback and does not prove that a
Harness can execute the governed lifecycle. Only a profile with independent
protocol, model, approval, cancellation, Artifact return and recovery
evidence may enter the production composition.

| Provider | Local Harness fact | Evidence in this run | Admission |
| --- | --- | --- | --- |
| DeepSeek | DSH `0.1.0-rc.5` at `D:\deepseek harness\dsh.cmd` | Isolated no-API surface, ACP multi-turn replay, native cancel, explicit unsupported recovery probe | Held: native recovery unsupported |
| Kimi | Kimi CLI `1.49.0` | Existing isolated ACP initialize/session probe reached authentication-required; no prompt sent | Held: authenticated lifecycle and BYOK route unproven |
| GLM | OpenCode ACP adapter exists in EgoPulse; `opencode` is not installed in this environment | No live probe available | Held: executable, credential, exact-model lifecycle and recovery unproven |

## DeepSeek evidence

The following commands were run from the repository on Windows x64:

```powershell
./scripts/probe-dsh-windows.ps1
./scripts/probe-dsh-acp-replay-windows.ps1
./scripts/probe-dsh-acp-cancel-windows.ps1
./scripts/probe-dsh-acp-recovery-capability-windows.ps1
```

Observed evidence:

```text
surface: version=0.1.0-rc.5, isolated=true, permission_mode=read-only,
         api_calls=false, prompt_sent=false, passed
replay:  initialize=passed, session_new=passed, prompts=ONE/TWO,
         stop_reason=end_turn, stderr_empty=true, passed
cancel:  initialize=passed, session_new=passed, native_cancel=passed,
         stop_reason=cancelled, stderr_empty=true, passed
recovery: load_session_advertised=false,
          session_load=rejected_not_supported,
          session_resume=rejected_not_supported,
          restart_reconciliation=held_native_recovery_unsupported
```

The recovery result is a positive safety finding, not a production
capability: EgoPulse correctly refuses to claim restart reconciliation when
the native Harness cannot identify an interrupted dispatch outcome. The DSH
adapter therefore remains candidate-only and is not wired into the production
daemon runner.

The multi-turn replay prompts were Harness fixture prompts. No real Provider
API request or user prompt was sent.

## Kimi and GLM gates

Kimi's prior isolated probe established ACP initialize reachability and an
`authentication_required` session disposition without inference. The missing
rows remain:

1. authenticated exact-model prompt and terminal lifecycle;
2. provider-native approval and cancellation routing;
3. a user-owned BYOK authentication route for the selected Harness entry;
4. restart and dispatch-outcome reconciliation;
5. Artifact/Verification/Founder Verdict return settlement.

GLM uses the existing thin OpenCode ACP wrapper, which deliberately reuses
the shared ACP transport. It cannot be tested in this environment until the
user-owned OpenCode executable and Z.AI credential route are available. The
first probe must reject any OpenCode fallback model and record the exact
`zai/...` model returned by ACP.

## Admission decision

DeepSeek's fresh-session, replay and cancellation evidence is now stronger,
but it still lacks native recovery. Kimi and GLM lack authenticated lifecycle
evidence. No provider admission state is changed by this note; Codex remains
the only production Harness.

The next probe is now executable through
`scripts/probe-provider-authenticated-windows.ps1`. It requires explicit
inference authorization, an isolated provider executable, and an exact model;
see phase 2-49 for the evidence interpretation. A passing fresh prompt is not
by itself sufficient to promote approval, Artifact/Verification settlement, or
restart recovery.
