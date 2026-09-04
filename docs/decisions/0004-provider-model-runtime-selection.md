# ADR 0004: Provider/model setup and governed work-route selection

- Status: `pending_founder_decision`
- Decision owner: Founder
- Scope: Stage 3 Provider/Harness/Model user-facing capability
- Evidence baseline: commit `48b4bfb86c3cd9504b9fb5a5978cace1380337a0`
- Affected boundaries: user configuration, Local API, Work preparation,
  reviewed workflow routing, CLI and TUI

This file is a decision package, not an accepted architecture or a frozen
contract. It replaces the earlier assumption that one restart-based
`SelectProviderModel` operation would also solve work-level multi-model
selection.

## Decision that must be made

EgoPulse needs to support two different user actions without conflating them:

1. **Setup preference**: inspect configured Provider/Harness/model data and set
   the default capability proposed for future work.
2. **Work-route choice**: explicitly choose, or accept an approved policy's
   choice of, one admitted exact execution route for a particular work item.

The first action is mutable user configuration. The second becomes an
immutable governed workflow fact. A global JSON edit cannot safely stand in
for both.

## Confirmed facts

The following are code or frozen-contract facts at the evidence baseline:

- `provider_profiles[]` already separates Provider, Harness and model
  identities, exposes a redacted catalog, and stores one `selected_model` per
  profile.
- `agentosd --check-config --json` is a read-only preflight. It does not open
  Authority stores, authenticate a Harness or prove production admission.
- Codex is the only production-admitted Harness. DeepSeek/DSH, Kimi and
  GLM/OpenCode are visible held candidates.
- The active Codex model is duplicated in
  `provider_profiles[].selected_model` and the compatibility field
  `codex.default_model`; startup rejects drift between them.
- `PrepareWork` deliberately does not select a Provider or model. Its Context
  snapshot records this as a non-goal.
- The frozen multi-Harness routing rule binds Task activation and dispatch to
  an exact capability-profile reference `(contract_id, version, sha256)`.
  UI state, prompt text, provider availability and model output cannot choose
  or rewrite that route.
- The current production Work facade activates a configured run identity. It
  does not yet persist a user capability preference into a reviewed
  RunPlan/StepPlan.
- A route change must not alter an in-flight or recoverable Task's model,
  capability evidence, Adapter Edge or native receipt expectation.

## Architectural classification

This is an architecture decision, not a UI or framework choice. It determines
the single writer for user configuration, the owner of a work's route fact,
cross-surface semantics, recovery behavior and the long-lived Local API
boundary.

## Non-negotiable constraints

- Provider identity, Harness identity and exact model identity remain
  separate.
- Candidate or held configuration never becomes a dispatchable route without
  independent admission evidence.
- Catalog refresh never changes a default or an existing work route.
- There is no silent model fallback or provider substitution.
- Credential values never cross Local API responses, logs, evidence or
  serialized read projections. Only secret references may be stored.
- CLI and TUI use one Rust client operation and one daemon semantic. Desktop
  may consume it later but is not a first-release blocker.
- A confirmed work route is immutable for the Task/recovery lifetime.
- Configuration concurrency fails closed instead of overwriting a newer user
  choice.

## Candidate A: mutate one profile's selected model and restart

Add a daemon-owned configuration service:

```text
ListProviderProfiles
  -> redacted profiles + config_revision

SelectProviderModel(profile_id, exact_harness_model_id,
                    expected_config_revision)
  -> configuration receipt + restart_required=true
```

The daemon atomically updates the complete user configuration. For the active
Codex compatibility profile, it must update both `selected_model` and
`codex.default_model` in one write.

### Why it is viable

- It is the smallest extension of the current bootstrap format.
- One daemon writer gives CLI and TUI the same concurrency, redaction and
  backup behavior.
- Restart keeps the active runtime deterministic and avoids mid-dispatch hot
  mutation.

### Cost and sacrifice

- It changes a route behind a stable profile ID. Recoverable work created
  under the prior model may no longer have a matching composed runner after
  restart.
- It only changes a global default; it does not implement explicit per-work
  multi-model selection.
- It preserves the duplicated Codex model fields and their synchronization
  burden.
- Safe use requires either blocking changes while any affected work is
  recoverable or retaining old route generations. Either rule adds lifecycle
  semantics that the apparently small API does not expose.

Candidate A is no longer recommended as the complete Stage 3 solution.

## Candidate B: immutable admitted routes plus future-work preference
   (recommended)

Treat a production execution route as an immutable, versioned configuration
record. A route binds:

```text
route identity
  + Provider profile identity
  + Harness identity
  + exact Harness and provider model identities
  + exact capability-profile reference
  + catalog/admission evidence references
  + native composition generation
```

A mutable default is only a pointer used when preparing **future** work. A
work request either names one public admitted capability choice or requests
the configured default. The daemon resolves that preference, presents the
resolved Provider/model in the Founder preview, and confirmation binds the
exact immutable route into the reviewed workflow. Existing work retains its
route even if the future-work default changes.

The user-facing semantic is:

```text
ListWorkCapabilities
  -> redacted configured profiles
  -> admitted immutable route choices
  -> held/candidate diagnostics
  -> current future-work default + preference revision

SetDefaultWorkCapability(choice_id, expected_preference_revision)
  -> preference receipt
  -> affects future preparation only

Prepare work(explicit choice | approved default policy)
  -> daemon resolves an admitted route
  -> preview shows Provider + Harness + exact model aliases
  -> Founder confirmation binds the exact route/profile digest
```

Clients never supply a native executable, credential, capability digest,
Adapter store or dispatch route. A public `choice_id` is a lookup key, not the
authoritative route fact; the daemon resolves and binds the latter.

### Why this option

- It preserves the already frozen exact-profile activation and dispatch
  boundary instead of creating a competing UI/config routing path.
- It supports actual per-work multi-model use, not merely a global model
  toggle.
- Default changes cannot rewrite in-flight or recoverable work.
- Candidate visibility and production eligibility remain separate.
- The same operation naturally supports CLI, TUI and a later Desktop surface.

### Cost and sacrifice

- The bootstrap schema needs an explicit immutable route collection and a
  separate mutable future-work preference.
- Work preparation/confirmation and the reviewed workflow must persist the
  resolved route reference; generated Rust, TypeScript and Python bindings
  change additively.
- Composition must retain every route generation referenced by active or
  recoverable work, or fail it closed with an explicit unavailable-route
  recovery state.
- A newly downloaded catalog model is not immediately selectable. It must
  first obtain route-specific admission evidence.
- This costs more before the second Provider is released, but avoids a later
  migration from global mutable state to governed per-work routing.

## Candidate C: arbitrary dispatch-time model selection and hot reload

Allow each work or dispatch to provide any model currently visible in a live
catalog and update active runners without restart.

### Why it is viable

- It offers the fastest model switching and the broadest visible catalog.
- It minimizes up-front route records.

### Cost and sacrifice

- Catalog visibility would become dangerously close to admission.
- In-flight retries and recovery could observe a different model or runner
  generation.
- It introduces separate concurrency domains for configuration, active
  runtime, Task route and dispatch route.
- It expands the blast radius of provider drift and weakens reproducible
  evidence.

Candidate C conflicts with the frozen deterministic routing and recovery
quality attributes and is not recommended for the first release.

## Comparison

| Dimension | A: mutable profile + restart | B: immutable route + work choice | C: hot arbitrary route |
| --- | --- | --- | --- |
| Preserves existing exact-profile rule | partial | strong | weak |
| True per-work multi-model | no | yes | yes |
| In-flight/recovery stability | requires extra blocking/versioning | strong | weak |
| First implementation effort | low/medium | medium/high | high |
| Candidate cannot masquerade as admitted | medium | strong | weak |
| CLI/TUI semantic parity | strong | strong | strong |
| Long-term migration burden | high when multi-model arrives | lower | high |

## Recommendation

Recommend Candidate B.

The stable architecture point is not a particular model catalog or Harness.
It is the distinction between mutable setup preference and immutable governed
work route. Provider catalogs, exact models and adapter implementations remain
replaceable data and technology choices behind that boundary.

For the first implementation:

- list all configured profiles, but expose work choices only for admitted
  immutable routes;
- held/candidate profiles remain visible with exact blockers and cannot be
  selected for a real work dispatch;
- make the default affect future work only;
- do not implement live reload;
- keep Codex as the compatibility route while the schema migration is
  introduced;
- admit DeepSeek, Kimi or GLM routes only after their independent real-process
  evidence closes.

## Migration and rollback candidate for B

1. Read the existing v2 configuration without changing current behavior.
2. Derive one immutable Codex compatibility route from the matching
   `provider_profiles[]` entry and `codex.default_model`; reject any drift as
   today.
3. Add a versioned route/default representation and an explicit migration
   preview. Do not mutate the user file during daemon startup.
4. On confirmed migration, write a complete temporary file, flush it, retain
   the prior file as a bounded backup and atomically replace the target.
5. Existing active/recoverable work continues to reference its original route
   generation. A route cannot be deleted while such references exist.
6. Rollback restores the prior complete configuration and returns to the
   single Codex compatibility route. Authority stores are not migrated by
   this configuration change.

The exact v3 JSON shape, backup retention count and Windows replacement API
are implementation details to freeze in the contract unit after Candidate B
is approved; they are not silently accepted by this recommendation.

## Verification gates if B is accepted

- Local API compatibility and regenerated Rust/TypeScript/Python bindings;
- owner-only list, preference mutation and work confirmation;
- no credential value in projections, logs, errors, fixtures or evidence;
- unknown, stale, held and candidate choice rejection for work routing;
- stale preference revision and concurrent writer rejection;
- catalog refresh preserves defaults and all existing work routes;
- Founder preview displays the resolved aliases before confirmation;
- confirmation binds the exact route/profile reference and model identity;
- dispatch receipt matches that route without fallback;
- changing the default does not alter active, interrupted or recoverable work;
- Windows atomic-write interruption, backup restore and migration rollback;
- shared CLI/TUI E2E over the same client operation;
- real authenticated lifecycle evidence for each newly admitted route.

## Required Founder response

```text
Architecture: A / B / C
Default affects future work only: yes / no
Held/candidate profiles visible but not selectable for work: yes / no
Live reload in first release: yes / no
Introduce the route/default configuration migration before second-provider
admission: yes / no
```

Recommended response:

```text
Architecture: B
Default affects future work only: yes
Held/candidate profiles visible but not selectable for work: yes
Live reload in first release: no
Introduce the route/default configuration migration before second-provider
admission: yes
```

Until the Founder response is recorded, the repository may retain the
redacted read-only preflight and candidate probes, but must not add a mutable
runtime selection API or claim per-work multi-model support.

## Review triggers

Re-open this decision only if one of these facts changes:

- route generations cannot be retained within the local resource budget;
- a Provider cannot reproduce an exact selected model in its native receipt;
- the frozen workflow can no longer persist the exact capability reference;
- a real user workflow proves restart-only setup is preferable to per-work
  choice;
- live route replacement becomes a Founder-approved product requirement.

## Decision status

- Founder-confirmed decision: none yet.
- Current state: `recommended_pending_founder`.
- Evidence gap: Founder choice and second-provider authenticated admission.
- No production contract or runtime behavior is changed by this ADR draft.
