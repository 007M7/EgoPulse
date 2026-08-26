# Phase 2-09 DeepSeek Harness adapter boundary

## Status

Candidate adapter implemented and locally verified. DSH is not yet a
production Harness and does not receive a `ProbeVerified` capability profile.
No V-01 contract, generated binding or daemon provider selection changed.

## Implemented surface

`crates/dsh-adapter` provides the same provider-neutral `NativeHarnessDriver`
shape used by the Codex and Kimi candidates. Its locally verified candidate
slice includes:

- configurable absolute executable, argument list, working directory and
  environment overrides;
- native ACP `initialize` and `session/new` request/response probe;
- fresh-session native ACP `session/prompt` dispatch;
- supervised `session/update` parsing and terminal `stopReason` mapping;
- native ACP `session/cancel` delivery and cancelled terminal observation;
- opaque native session reference and SHA-256 evidence references;
- degraded readiness until a native schema digest is attested;
- approval/server-request handling remains fail closed;
- reconciliation remains `OutcomeUnknown` because native load/resume is absent.

The adapter does not promote a committed assistant message to a terminal
Verdict or Artifact. ACP content chunks are retained only as in-process
observations; the candidate currently emits terminal lifecycle evidence from
the native prompt response and does not claim artifact semantics. Those
transformations require the provider-neutral contract and independent
approval, artifact and recovery evidence.

## Why this integration shape

| Decision | Reason | Cost accepted |
|---|---|---|
| Native DSH ACP over the existing supervised process boundary | DSH's own source exposes an automation-only JSON-RPC stdio server; reusing the same process governance keeps executable, timeout and crash semantics uniform across models | DSH's compiled bundle and profile composition become runtime prerequisites; no direct in-process TypeScript reuse is available to the Rust daemon |
| Candidate-only adapter | Fresh prompt/cancel lifecycle is replay-attested, but approval routing, artifact semantics and native recovery are not | DSH cannot be selected by a reviewed `StepPlan` or write an authority store yet |
| Opaque native ids and evidence hashes | Prevents provider-specific ids or raw protocol payloads from becoming EgoPulse truth | The adapter needs later correlation logic before it can produce provider-neutral lifecycle facts |
| Configurable command arguments and environment | Supports the installed DSH launcher and the compiled keyless replay composition without hard-coding a machine path | Deployment configuration must pin the executable, profile, version and environment policy explicitly |

## Evidence

- DSH `0.1.0-rc.5` executable discovery passed.
- Isolated `DSH_HOME` CLI profile dump/help passed in read-only mode.
- Compiled ACP composition returned successful `initialize` and `session/new`
  responses over stdio without a prompt or API call.
- Keyless `multi-turn` replay returned two committed assistant updates and two
  `end_turn` prompt responses over the same compiled ACP subprocess.
- Keyless `cancel` replay accepted native `session/cancel` and returned
  `stopReason=cancelled` before clean process exit.
- Rust candidate replay tests passed locally on Windows x64 against the real
  compiled ACP demo: fresh terminal lifecycle and native cancellation, both
  without a model/API call.
- DSH adapter Clippy with warnings denied: passed.

The keyless lifecycle evidence is now complete for the ACP operations DSH
actually implements: multi-turn prompt, committed update, and cancellation.
The recovery capability probe also confirms that DSH advertises fresh sessions
only: `session/load` and `session/resume` are rejected. The candidate therefore
remains held rather than being promoted; a restarted DSH process cannot be
treated as recovery of a prior native session. Any future adapter would need
EgoPulse-owned dispatch receipts and an explicit uncertain-outcome policy, not a
synthetic native recovery claim.
