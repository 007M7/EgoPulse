# Phase 2-44 — Four-provider admission baseline

- Date: 2026-08-27
- Scope: GPT, DeepSeek, Kimi and GLM
- Decision status: provider/Harness mapping selected; only GPT/Codex remains production-admitted

## Outcome

EgoPulse will support four model-provider families through one governed Rust
kernel and provider-owned Harness adapters. Provider support does not create a
second scheduler, policy engine, Memory authority or UI-specific execution
path.

| Provider family | Harness boundary | Current admission |
|---|---|---|
| GPT | OpenAI Codex app-server | Production-admitted for the frozen Codex capability profile |
| DeepSeek | DeepSeek Harness ACP | Candidate; native restart/reconciliation and Artifact semantics remain held |
| Kimi | Kimi CLI multi-session ACP | Candidate; native session resume and exact-model checks implemented, BYOK and dispatch-outcome evidence held |
| GLM | OpenCode ACP with an exact `zai/...` or `zhipuai/...` model route | Candidate; authenticated GLM lifecycle, schema and recovery evidence remain held |

OpenCode is selected for GLM because its official open-source Harness exposes
ACP over stdio, session operations, tools and permission handling while already
supporting provider/model selection. A low-maintenance third-party GLM chat CLI
would not provide sufficient governed lifecycle semantics.

Primary implementation references:

- <https://github.com/anomalyco/opencode>
- <https://github.com/anomalyco/opencode/blob/dev/packages/web/src/content/docs/acp.mdx>
- <https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/acp/config-option.ts>

## Stable architecture boundary

The following remains provider-neutral and shared:

1. Task activation and exact capability-profile routing;
2. Policy, Memory, Artifact, Verification and Founder Verdict authorities;
3. CLI/TUI command semantics;
4. dispatch, approval, cancellation, evidence and terminal-candidate contracts;
5. one scheduled composite Harness runner.

The following remains replaceable and provider-owned:

1. executable and arguments;
2. authentication mechanism and secret environment references;
3. native protocol fingerprint and capability attestation;
4. provider/model identifier;
5. Adapter and Collaboration stores;
6. native recovery implementation.

## Closed in this slice

### Multi-provider Policy routing

`LocalUserPolicyResolver` now accepts multiple independently owned Adapter
edges. It searches all configured provider stores and binds an approval to the
one store that contains the durable request. Zero matches returns `NotFound`;
more than one match returns `IntegrityFailure`. Adapter receipts are validated
against the store named by the durable request binding.

This prevents a second provider from being wired into dispatch while its tool
approval is still silently coupled to the Codex store.

### Exact ACP model routing

The shared ACP candidate driver can require an exact session model. It reads
the ACP `configOptions` entry whose id is `model` and rejects:

- a different `currentValue`;
- a missing model option;
- an empty required model.

The live OpenCode 1.18.23 no-inference probe demonstrated why this check is
required. `initialize` advertised ACP v1 with load, resume, session and
permission capabilities. With `zai/glm-4.7` configured but no GLM credential,
`session/new` selected `opencode/big-pickle`. EgoPulse must fail closed on that
fallback instead of reporting GLM support.

### Reused ACP implementation

`egopulse-opencode-adapter` is a thin provider-identity wrapper over the
existing ACP transport/parser implementation. It does not add another JSON-RPC
stack. It maps evidence and diagnostic namespaces to OpenCode and requires an
exact provider/model route.

### Kimi capability correction

The installed Kimi CLI 1.49.0 implementation was inspected and rerun through a
no-inference probe. Its multi-session ACP implements load, list and resume. The
Kimi adapter now requires those capabilities and validates the exact
`models.currentModelId` on both new and resumed sessions.

A successful native resume remains only session-reachability evidence. It does
not prove the outcome of the exact interrupted dispatch, so reconciliation
continues to return `OutcomeUnknown` with a hashed native resume receipt. The
inspected multi-session entry point also checks Kimi Code OAuth before session
creation; a supported user-owned API-key path remains an independent product
gate. See `phase-2-45-kimi-recovery-and-model-boundary-20260827.md`.

## Remaining GLM admission gates

1. pin and attest the OpenCode executable version and ACP schema digest;
2. complete an authenticated GLM prompt/tool/permission/cancel lifecycle with a
   user-owned API key;
3. verify `session/load` and `session/resume` after process restart, including
   working-directory identity and permission reply routing;
4. map committed output into the governed Artifact/Verification return path;
5. expose the provider in production bootstrap only after the previous rows
   pass.

The OpenCode adapter therefore remains candidate-only. Startup reachability or
declared capabilities are not sufficient for production admission.

## Local evidence

The following targeted tests passed:

```text
cargo test -p egopulse-dsh-adapter
cargo test -p egopulse-opencode-adapter
cargo test -p egopulse-kimi-adapter
cargo test -p egopulse-agentosd multi_provider_policy_routes_exactly_one_adapter_and_rejects_collisions --lib
```

The first run of the multi-provider Policy test timed out because the test
fixture retained a read lock while invoking the resolver. The fixture was
corrected to release the lock before resolution; the isolated test then passed.
No production lock path was changed to hide that failure.
