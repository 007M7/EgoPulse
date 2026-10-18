# ADR 0005: Phase-one Personal Agent intent entry

- Status: accepted for the phase-one additive contract
- Date: 2026-09-08
- Decision owner: Founder
- Authority reference: `conversation:2026-09-08:founder-authorized-phase-one-personal-agent-intent-entry`

## Decision

Add `LocalCommandGatewayService/InterpretIntent` as the Personal Agent entry for untrusted natural-language text and bounded conversation history. The response may contain a user-facing reply and one `IntentWorkCandidate`; that candidate is a proposal, not an Authority fact.

The operation reuses the existing `local.work.prepare` permission. It does not add a permission, Authority, database or Task command. Before any Task can exist, the selected candidate must pass the existing authenticated `PrepareWork` validation, produce the governed preview, and receive explicit confirmation through `ConfirmWork`.

The request may name one public admitted work-capability choice or leave it empty so the existing future-work default is resolved. There is no silent Provider, Harness or model fallback. Conversation text and model output cannot author a capability route, Context snapshot, permission, confirmation or execution fact.

## Scope

This decision records the Founder authorization given on 2026-09-08 for the current phase-one Personal Agent intent entry. Earlier frozen architecture establishes the U1 natural-language responsibility, but this ADR does not rewrite that historical record or claim that this exact RPC, prompt or implementation had already been approved.

The additive contract covers:

- current user text and ordered untrusted conversation messages;
- a clarification reply with no work candidate when required information is missing;
- a proposed intent, work type, target scope and explicit source requests;
- a safely projected admitted work-capability view;
- mandatory revalidation by the existing Prepare/Confirm path.

It does not freeze a separate Director model process, a prompt, a scoring algorithm, a UI framework, unrestricted chat, automatic Task creation or automatic confirmation. It does not add another Harness or model/tool execution loop.

## Security and recovery boundary

- Session authentication and current `local.work.prepare` authorization are checked for every call; a client surface does not grant authority.
- Conversation history remains untrusted input and cannot be replayed as an Authority event.
- An `IntentWorkCandidate` cannot be sent directly to Task Authority or dispatch. `PrepareWork` owns normalization, source resolution, route admission, Context compilation and gate evaluation.
- Clarification and interpretation create no Task, Context, Artifact, Verification or Verdict fact.
- Unknown RPCs and unknown permissions continue to fail closed. Older generated clients may ignore the additive messages, but session negotiation remains exact against the current candidate contract.
- Recovery of Prepare or Confirm continues to use their existing sealed recovery commands; repeating natural-language interpretation is not a substitute for exact mutation replay.

## Compatibility and versioning

This additive protobuf revision is `0.1.0-draft.24`. The immutable accepted `draft.11` import and frozen `draft.12`/`draft.13` baselines remain unchanged. The client-kernel compatibility profile advances its minimum to `draft.24` and advertises `personal_agent_intent_interpretation`. Interpretation reuses `local.work.prepare`; the same candidate revision also includes the existing-permission Rework continuation described in [ADR 0006](0006-rework-continuation.md).

Generated Rust, TypeScript and Python bindings and repository-level digest pins must be regenerated from the manifest-controlled contract. Those generated artifacts are implementation evidence; they do not expand this decision.

## Acceptance conditions

- unauthenticated or ungranted calls fail before interpretation;
- clarification returns no actionable candidate and creates zero governed facts;
- a proposed candidate cannot bypass `PrepareWork` source, scope, route, Memory or policy validation;
- an empty capability choice uses only the configured future-work default, while an explicit choice must be currently admitted;
- changed or stale candidate data is rejected by preparation rather than trusted from the interpretation response;
- CLI and TUI use the same generated Local API contract and shared client operation;
- generated bindings, current profiles, manifest provenance and fixed external digest anchors agree on `draft.24`;
- real user acceptance remains separate from contract compilation and must prove startup, conversation, clarification, preview cancellation, confirmation, real execution, visible evidence and verification, user verdict, a second task and relevant recovery paths.

## Review triggers

Re-open this decision if interpretation is allowed to create or mutate governed facts, selects an unadmitted route, needs a new permission/Authority, persists a new conversation store, or introduces a second model execution loop outside the existing Harness boundary.

## Bounded cognition implementation (2026-10-14)

The implementation now uses the provider-neutral `ReadOnlyTurnDriver` capability
in `harness-adapter`. Each interpretation uses one fresh native session, the
already admitted profile and exact selected model, a 120-second time budget and
a 64 KiB assistant-output budget. Profile or native-model mismatch fails closed.
Codex uses its checked read-only policy. OpenCode uses a disposable empty
workspace/config root, disables project and Claude configuration inheritance,
denies all tools, and rejects any ACP tool or permission request. ACP frames are
bounded to 1 MiB and the turn has a total event/output bound. Unsupported harnesses
report capability unavailable; there is no model or harness fallback.

Conversation remains only a proposal. CLI `ask --cancel` exits before attachment
or RPC. An interactive `ask` candidate can enter the governed preview, while
non-interactive use requires explicit `--confirm` to create work. Selecting a TUI
candidate automatically prepares its preview; confirmation remains an explicit
Founder action. Neither surface supplies low-level snapshot or authorization
bindings. Existing confirmed routes and persisted Task facts are unchanged.

OpenCode support is restricted to the source-checked 1.18.31 configuration
contract. Pure mode suppresses external plugins; an isolated home/config/cache,
state and native database prevent inheriting user agents or active organization
settings. Existing credential-file metadata is bounded and checked without
retaining credential fields: remote `wellknown` configuration and unknown types
are refused. Managed native configuration and caller configuration overrides
are also refused before any native process starts. Such configurations need
separate read-only capability evidence; production dispatch admission is retained.

The versioned upstream sources establish the configuration precedence and
isolation controls: [config](https://github.com/anomalyco/opencode/blob/v1.18.31/packages/opencode/src/config/config.ts),
[global paths](https://github.com/anomalyco/opencode/blob/v1.18.31/packages/core/src/global.ts),
[plugin pure mode](https://github.com/anomalyco/opencode/blob/v1.18.31/packages/opencode/src/plugin/index.ts).
