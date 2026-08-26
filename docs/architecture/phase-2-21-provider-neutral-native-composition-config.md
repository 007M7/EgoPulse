# Phase 2-21: Provider-neutral native Harness composition config

## Status

Implemented and locally verified. This phase removes a Codex-named type from
the reusable native Harness assembly boundary. It does not admit a second
Harness and does not change the user-owned Codex JSON configuration shape.

## Boundary closed

The generic daemon assembly path previously accepted
`CodexHarnessCompositionConfig`, even when the supplied driver was not Codex.
That made common governance inputs appear to be provider-owned and forced a
future provider to supply a misleading Codex executable field.

The typed composition boundary is now split as follows:

```text
user-owned Codex JSON (unchanged)
              |
              v
CodexHarnessCompositionConfig
  - NativeHarnessCompositionConfig
  - codex_executable
              |
              +----> CodexAppServerDriver
              |
              v
NativeHarnessCompositionConfig
  - authority/adapter store inputs
  - input bundle and workspace roots
  - reviewed workflow
  - lease policy
  - governed return collector
              |
              v
profile-bound native Harness composition
```

`with_native_harness_driver` and
`with_profiled_native_harness_driver` accept only
`NativeHarnessCompositionConfig`. The Codex wrapper validates and consumes its
own executable before delegating to that provider-neutral boundary.

## Invariants

- Common governance inputs do not carry a provider executable or provider
  identity.
- Provider identity and observed protocol remain bound by
  `NativeHarnessCompositionProfile`, not by process configuration.
- An empty Codex executable fails with a Codex-specific configuration error.
- Invalid lease, key, epoch or return-path values fail as native composition
  errors before storage is opened.
- Existing user-owned bootstrap JSON remains compatible; the separation is at
  the typed daemon boundary.
- Kimi and DSH remain candidates. This refactor is not capability admission,
  authentication evidence, recovery evidence or dynamic task routing.

## Cost and deferred work

- The Codex bootstrap file is still the only production provider file because
  Codex remains the sole admitted Harness.
- A second admitted provider will need its own process configuration and
  bootstrap parser. Those provider-specific values must wrap, not duplicate,
  `NativeHarnessCompositionConfig`.
- Dynamic multi-model selection remains a governed workflow-routing contract;
  it cannot be inferred from the availability of multiple drivers.

## Verification evidence

The regression test
`native_harness_composition_is_independent_from_provider_executable_config`
proves that the common native config validates without an executable and that
native and Codex-specific failures remain distinguishable.

Local Windows x64 verification:

```text
cargo fmt --all -- --check                                      passed
cargo clippy -p egopulse-agentosd --all-targets -- -D warnings passed
cargo test -p egopulse-agentosd --lib                           49 passed
git diff --check                                                passed
```
