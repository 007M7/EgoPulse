# Phase 2-20：Profile-bound native Harness composition

## Status

Implemented and locally verified. Codex remains the only active production
Harness. This phase closes the post-attestation composition boundary; it does
not admit Kimi, DSH or any other second provider.

## Problem and boundary

The multi-Harness design needs one reusable daemon assembly path, but a daemon
assembly function must not become a second capability-admission authority.
Provider-specific adapters own native protocol evidence; capability binding
and attestation establish whether a profile may be selected; `agentosd` only
assembles the already-admitted driver into the existing governed runtime.

```text
workflow StepPlan + required profile reference
                    |
                    v
capability binding + Active/ProbeVerified attestation
                    |
                    v
observed native protocol fingerprint must equal declaration
                    |
                    v
NativeHarnessCompositionProfile
                    |
                    v
GovernedHarnessAdapter + Adapter Edge + Collaboration Control
                    |
                    v
provider-neutral dispatch / evidence / return path
```

The composition boundary never receives an Authority database handle from a
provider adapter and never selects a model from a UI request.

## Frozen implementation

`apps/agentosd/src/lib.rs` now provides:

- `NativeHarnessCompositionProfile`, whose fields are private to prevent
  callers from constructing an apparently admitted profile from arbitrary
  strings; it retains the complete capability `ContractReference`, not only
  the profile ID;
- `from_attested_capability`, which invokes the shared capability-binding
  validator and requires an active, probe-attested, workflow-bound profile;
- an exact equality check between the admitted declaration protocol
  fingerprint and the current observed fingerprint;
- an exact equality check between the profile reference carried by composition
  and the workflow's required profile reference before any Authority storage
  is opened;
- `with_profiled_native_harness_driver`, which binds the resulting identity to
  `GovernedHarnessAdapter` and the existing durable return path;
- `with_native_harness_driver` as the compatibility wrapper for the current
  Codex production composition.

The profile constructor fails before Adapter Edge or Collaboration storage is
opened when identity, protocol evidence, attestation, workflow binding or
protocol equality is invalid.

## Why this design

It gives future model families the same composition seam while preserving the
architecture boundary: a provider can supply a driver only after its own
capability evidence has been admitted, and the daemon does not need a new
provider-specific governance path. The shared profile validator remains the
single interpretation of workflow-to-capability binding.

## Cost and explicitly deferred work

- Phase 2-21 separates the provider-neutral native composition inputs from the
  Codex executable. A later second-provider vertical may add an explicit
  provider process config or provider config enum, but it must reuse the common
  native composition contract instead of copying the Codex wrapper.
- The profile constructor does not perform provider admission, model
  selection, authentication or native recovery. Those remain provider-owned
  evidence gates.
- `CompositeHarnessDispatchRunner` sequences already-bound runners but does
  not dynamically route a Task. Dynamic multi-model routing remains a later
  workflow contract and cannot be inferred from the presence of this seam.

## Verification evidence

The regression test
`native_harness_profile_requires_explicit_identity_and_protocol_evidence`
covers:

- construction from a valid workflow-bound, probe-attested capability;
- missing identity/protocol rejection;
- declaration/observation protocol drift rejection.

Local verification on Windows x64:

```text
cargo fmt --all -- --check                  passed
cargo clippy -p egopulse-agentosd --all-targets -- -D warnings   passed
cargo test -p egopulse-agentosd --lib       49 passed
git diff --check                            passed
pre_push_check                              passed
```

The authoritative next admission decision remains either an authenticated
Kimi lifecycle probe or completion of the DSH native recovery and Artifact/
Verification evidence. Until then Codex is the sole production Harness.
