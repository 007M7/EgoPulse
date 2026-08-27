# Phase 2-23: Exact multi-Harness profile routing

## Status

Implemented and locally verified. This phase closes the shared-dispatch
routing contract for multiple provider runners. It does not dynamically select
a model from a UI request and does not promote Kimi or DSH.

## Problem closed

Filtering a shared Collaboration outbox by `capability_profile_id` alone can
send a dispatch from one reviewed profile revision to a runner configured for
another revision with the same ID. A multi-model runtime must treat the
profile reference as an immutable routing key.

## Frozen routing rule

```text
DispatchEnvelope.capability_profile_ref
          |
          | exact equality: contract_id + version + sha256
          v
one GovernedHarnessDispatchRunner
          |
          v
its own Adapter Edge + native driver + evidence path
```

`GovernedHarnessDispatchRunner::with_capability_profile_ref` is the only
profile-bound constructor. Both pending-envelope registration and dispatch
selection use the same exact predicate, so a runner cannot activate one
profile and dispatch another. Missing profile references do not match an exact
route. The former ID-only constructor was removed while the repository is
still pre-release; an ID without version and SHA is not a supported production
routing key.

## Invariants and costs

- A profile version drift is rejected before the envelope reaches the runner.
- A profile digest drift is rejected even when ID and version are unchanged.
- A DSH route and a Codex route can share Collaboration storage without
  consuming each other's dispatches, provided each uses its exact reference.
- The cost is that every production route must carry and persist the reviewed
  profile version and digest; callers cannot use a short ID as a complete
  routing decision.
- Routing is still envelope-bound. This phase does not infer a model from
  prompt text, UI state, cost heuristics or provider availability.

## Verification evidence

The `local-ide-control` regression suite covers:

- exact Codex/DSH separation;
- missing profile rejection;
- exact match acceptance;
- version drift rejection;
- SHA-256 drift rejection.

Local Windows x64 verification:

```text
cargo fmt --all -- --check                                      passed
cargo clippy -p egopulse-local-ide-control --all-targets -- -D warnings passed
cargo test -p egopulse-local-ide-control --lib                 7 passed
git diff --check                                                passed
```

The route contract is now ready for a future second admitted Harness, but
admission still requires that provider's attestation, lifecycle, Artifact and
recovery evidence.
