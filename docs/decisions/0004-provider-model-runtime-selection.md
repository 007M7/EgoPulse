# ADR 0004: Provider/Model runtime selection ownership

- Status: `pending_founder_decision`
- Date: 2026-08-27
- Decision owner: Founder
- Scope: Stage 3 Provider/Model user-facing read and selection capability
- Affected surfaces: CLI, TUI, Desktop, `agentosd` bootstrap and native dispatch

This ADR is a decision package, not a contract freeze. It records the
remaining choice before the frozen Local API can be extended.

## Decision to make

How should a user inspect configured Provider/Model profiles and change the
exact selected model used by the next AgentOS daemon startup?

The current implementation already has a typed, redacted configuration
profile and `agentosd --check-config --json`. It does not yet expose a
runtime client operation. The daemon loads the user-owned JSON at startup,
and the current production route rejects unapproved Provider admission. A
successful model selection must therefore never imply Provider promotion,
live authentication success or silent fallback.

## Confirmed constraints

- Provider identity, Harness identity and Model identity remain separate.
- Dispatch must bind an exact Harness model identifier.
- Candidate and held profiles may be listed and selected as configuration,
  but cannot become production routes without independent admission evidence.
- Credential values must never cross a Local API response, log or serialized
  configuration projection.
- CLI, TUI and Desktop must converge on one selection semantic and one
  optimistic-concurrency rule.
- A stale selection must fail closed rather than overwrite a newer choice.
- A model catalog refresh must not silently change `selected_model`.
- The frozen Local API contract is the only machine-contract source; any
  extension requires generated bindings, compatibility evidence and a new
  revision authority.

## Candidate A — daemon-owned configuration service (recommended)

Add an additive `LocalProviderConfigurationService` to the Local API:

```text
ListProviderProfiles
  -> redacted profiles + config_revision + restart_required=false

SelectProviderModel(profile_id, exact_harness_model_id, expected_config_revision)
  -> accepted/rejected + new_config_revision + restart_required=true
```

The daemon is the single writer for the user-owned provider configuration.
Selection validates that the profile and exact Harness model exist, checks the
expected file revision, writes a complete temporary file, flushes it and
atomically replaces the user file. The daemon returns a configuration receipt;
the new selection becomes active only after a controlled daemon restart. The
existing startup validator remains the final authority before composition.

Read projection fields should include only:

- profile ID;
- Provider and Harness IDs;
- admission state and hold reason;
- Harness/provider model ID pairs;
- selected exact Harness model;
- executable reference;
- credential mode and optional source environment-variable name;
- configuration revision and restart-required state.

The operation must not include resolved secrets or claim that an executable
or credential is reachable unless a separate authenticated probe has proved
it.

Why this option: one writer gives all three surfaces the same ownership,
concurrency and redaction semantics. Restart-required behavior is explicit,
so startup composition remains deterministic and no live route is mutated in
the middle of a Task.

Cost and sacrifice:

- adds a Local API service and generated bindings;
- adds Windows atomic-replace, crash-recovery and file-lock tests;
- model changes are not instant and require a daemon restart;
- the daemon becomes responsible for a user-owned settings file, so backup,
  permissions and migration behavior must be maintained;
- a later live reload feature would require a separate decision rather than
  being inferred from this operation.

## Candidate B — each surface edits the user JSON directly

CLI, TUI and Desktop share a small Rust configuration editor. Each acquires a
file lock, checks a revision, writes atomically and asks the user to restart
the daemon.

Why it is viable: no Local API extension is needed and setup can work while
the daemon is stopped.

Cost and sacrifice:

- configuration ownership is spread across three clients and setup tools;
- every client must reproduce lock, encoding, migration, permissions and
  recovery semantics;
- a client can show a state different from the daemon it is attached to;
- future remote/local session policy cannot govern the operation uniformly;
- a fourth surface or installer creates another writer unless the editor is
  treated as a hidden shared service.

This option is cheaper for the first implementation but creates a global
consistency boundary outside the existing governed local API.

## Candidate C — hot-reload selection into the running daemon

Add a configuration authority and live route registry. A successful selection
would update the active Provider route without restart, subject to an idle
Task boundary and route-version fencing.

Why it is viable: model changes appear immediately and the UX is strongest.

Cost and sacrifice:

- requires defining what happens to in-flight Tasks, retries and recovery;
- expands the authority/state machine and the audit surface;
- creates a second concurrency problem between config revision and active
  dispatch revision;
- increases the blast radius of a bad model selection;
- delays the first multi-Provider release and is not needed for local BYOK
  configuration.

This is not recommended for the initial release.

## Comparison

| Dimension | A: daemon service | B: client file editor | C: hot reload |
|---|---|---|---|
| Single configuration writer | strong | weak unless carefully shared | strong |
| CLI/TUI/Desktop semantic parity | strong | medium | strong |
| Frozen-contract impact | additive API | none | additive API plus runtime state |
| Restart/recovery complexity | medium | medium in every client | high |
| In-flight Task risk | low, restart fence | low if restart enforced | high |
| First-release suitability | high | medium | low |
| Future live reconfiguration | explicit follow-up | migration required | built in |

## Recommendation

Recommend Candidate A for Stage 3. Keep the first implementation restart
based, daemon-owned and exact-model-only. Treat selection as a configuration
mutation, not as Provider admission and not as an authority fact such as a
Task or Memory record. Keep catalog refresh separate from selection, and keep
all candidate/held profiles non-dispatchable.

## Required Founder response

```text
Decision: A / B / C
Live reload in first release: yes / no
Candidate/held profiles selectable as configuration: yes / no
```

Until this response is recorded, the repository may implement redacted
preflight and admission probes, but must not freeze or silently add the
runtime Provider/Model selection contract.

## Verification and rollback if A is accepted

- contract compatibility and regenerated Rust/TypeScript/Python bindings;
- owner-only session authorization for list and select;
- unknown profile/model rejection;
- held/candidate selection accepted only as configuration, never dispatch;
- stale `config_revision` rejection;
- concurrent writer rejection;
- crash/interruption atomic-write recovery;
- restart loads the exact selected model;
- dispatch receipt matches the selected Harness model;
- no API key value in output, logs, files or evidence;
- restore the previous complete configuration from the last accepted backup;
- local CLI/TUI/Desktop E2E evidence over the shared client semantics.
