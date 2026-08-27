# Phase 2-46: Provider model catalog and exact selection

- Status: implementation baseline; live catalog adapters remain Gate work
- Evidence date: 2026-08-27
- Scope: GPT, DeepSeek, Kimi and GLM

## Correction

A Provider is not a model. One Provider profile owns a model catalog and one
explicitly selected model. A release must not hard-code a model as “latest”
because vendor catalogs and Harness aliases change independently of EgoPulse.

The production invariant is:

```text
official/Harness catalog -> redacted local snapshot -> user selection
                         -> exact dispatch model -> native receipt check
```

Catalog refresh never changes the selected model automatically. If a selected
model disappears, startup or dispatch is held for user action; it cannot fall
back to another model.

## Current official evidence

The following facts were checked against vendor-owned documentation on the
evidence date:

| Provider | Current family used by the example fallback | Authoritative refresh path |
| --- | --- | --- |
| GPT | `gpt-5.6` alias plus `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`; Codex-specific `gpt-5.3-codex` | OpenAI model API / Codex app-server model catalog |
| DeepSeek | `deepseek-v4-pro`, `deepseek-v4-flash`, experimental vision `deepseek-v4-flash-vision-exp` | DeepSeek `GET /models`, mediated by DSH where available |
| Kimi | managed Kimi Code alias `kimi-code/k3`; direct API catalogs may expose other models such as K2.5 | Kimi Code provider refresh and `GET /api/v1/models` |
| GLM | `glm-5.3`, `glm-5.3-flash` | Z.AI/OpenCode provider catalog |

Official references:

- <https://platform.openai.com/docs/api-reference/models>
- <https://platform.openai.com/pricing>
- <https://api-docs.deepseek.com/quick_start/pricing/>
- <https://api-docs.deepseek.com/updates/>
- <https://moonshotai.github.io/kimi-code/en/reference/server-api.html>
- <https://moonshotai.github.io/kimi-code/en/configuration/config-files>
- <https://moonshotai.github.io/kimi-code/en/configuration/env-vars.html>
- <https://opencode.ai/docs/providers>
- <https://docs.z.ai/llms.txt>
- <https://docs.z.ai/guides/llm/glm-5.3>

The JSON `models` values are therefore an editable, offline fallback
snapshot, not an architectural source of truth and not an admission claim.
Each entry keeps `harness_model_id` separate from `provider_model_id`; dispatch
uses the former while official catalog reconciliation and evidence retain the
latter.

## Frozen configuration semantics

Each `provider_profiles[]` entry carries:

1. stable Provider and replaceable Harness identity;
2. admission state independent from configuration presence;
3. a non-empty `models` fallback catalog with Harness and provider identities;
4. one `selected_model` that must exist in that catalog;
5. an executable reference;
6. either Harness-account authentication or an API-key environment reference;
7. a machine-readable hold reason when admission is held.

Only environment-variable names are stored. Secret values are resolved at
startup and passed only to the selected child process. They are excluded from
status, logs and serialized configuration.

## Remaining implementation gates

The configuration baseline now accepts and redacts an optional
`catalog_snapshot` containing source, fetched-at time, Harness version and a
canonical evidence digest. The example profiles carry explicit
`offline-fallback` provenance and `not-probed` Harness versions. This is
configuration provenance only; it does not imply a live catalog refresh or
Provider admission.

The remaining gates are:

1. Add a provider-neutral model-catalog read contract and local refresh
   projection without changing selected-model semantics.
2. Implement Harness-native refresh in this order: Codex app-server, DSH,
   Kimi Code, OpenCode. Direct Provider API calls are fallback adapters, not a
   second Agent framework.
3. Add the same `provider list`, `model list` and `model select` capability to
   CLI and TUI through the shared Rust client kernel.
4. Bind dispatch to `(provider profile, exact model)` and reject unavailable,
   unselected or silently substituted models.
5. Run authenticated lifecycle E2E separately for each admitted model family;
   catalog visibility alone never proves tool, recovery or return semantics.
