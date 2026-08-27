# Phase 2-50: Redacted Provider/Model configuration preflight

- Date: 2026-08-27
- Status: implemented and locally verified
- Scope: Provider profile visibility before Local API model-selection contract
- Admission impact: none; Codex remains the only production Harness

## Delivered behavior

`agentosd --check-config --json` now parses the user-owned production
configuration without opening Authority stores and emits a redacted catalog
for setup tools and diagnostics. The report includes:

- Provider identity;
- replaceable Harness identity;
- `production`, `candidate` or `held` admission state;
- both Harness and provider-native model identities;
- the exact configured selected model;
- executable reference;
- credential mode and, for API-key profiles, only the source environment
  variable name;
- the hold reason when a profile is held.

The report never resolves or serializes secret values. A successful preflight
does not prove that a native executable is installed, that authentication
works, or that the profile has passed Provider admission.

The bootstrap profile now also exposes a pure catalog-refresh preview for the
next Harness-native adapter layer. The preview accepts a typed, provider-
neutral model list, canonicalizes its order, rejects empty/invalid/duplicate
Harness model identifiers, and reports whether the existing exact selection
is still present. If it is absent, the preview sets
`requires_user_action=true` and `selection_changed=false`; it never chooses a
replacement and never mutates the user configuration.

## Boundary decision

This unit intentionally does not add a Local API message or mutate the frozen
CLI/TUI contract. It is a setup/configuration-plane read. Runtime clients
still use the shared Rust Client Kernel and local daemon for governed facts.
The user-facing `provider list`, `model list` and `model select` operations
remain a separate contract decision because they affect all three surfaces,
configuration ownership, restart semantics and exact dispatch routing.

## Evidence

```text
cargo test -p egopulse-agentosd --test config_check -- --nocapture
4 passed, 0 failed

cargo fmt --all -- --check
passed

cargo clippy -p egopulse-agentosd --all-targets -- -D warnings
passed

cargo test -p egopulse-agentosd --lib provider_catalog_refresh -- --nocapture
3 passed, 0 failed

The complete local CI also passed for the implementation commit
`11fcad83c8edfce58dd480e0a183186566a3b58d`:

```text
status=passed
stages=8/8
failed=0
duration_ms=54071
```

agentosd.exe --check-config --json
configuration=passed
stores_opened=false
four configured Provider profiles emitted
credential values absent
```

The exact implementation is in `apps/agentosd/src/bootstrap.rs` and
`apps/agentosd/src/main.rs`. The report is derived from the same typed
bootstrap profile used by daemon startup, so setup output cannot invent a
second Provider/Model identity model.

## Remaining stage-three work

1. Prepare and obtain Founder approval for the contract-compatible runtime
   Provider/Model read and selection surface.
2. Preserve exact-model dispatch and reject silent fallback.
3. Run authenticated lifecycle evidence for each candidate Provider before
   changing its admission state.
