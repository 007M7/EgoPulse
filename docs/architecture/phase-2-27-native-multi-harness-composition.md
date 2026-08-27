# Phase 2-27: Native multi-Harness composition

## Status

The daemon now exposes a provider-neutral composition entry for multiple
profile-bound native Harness units. This closes the missing production wiring
between the existing `CompositeHarnessDispatchRunner` and the native driver
assembly; it does not promote an unverified provider.

## Composition contract

```text
reviewed profile A + native driver A + isolated stores A
reviewed profile B + native driver B + isolated stores B
                         |
                         v
DaemonProviders::with_profiled_native_harness_drivers
                         |
                         +--> one shared TaskActivationSource
                         +--> one runner per exact profile route
                         +--> one Adapter Edge per provider unit
                         `--> CompositeHarnessDispatchRunner
                                      |
                                      v
                             one daemon scheduling hook
```

`ProfiledNativeHarnessComposition` carries one provider's reviewed workflow
configuration, attested composition identity and type-erased native driver.
`NativeHarnessDriver` is type-erased at the provider-neutral adapter boundary
so Codex, DSH and Kimi implementations can coexist without an enum in the
control plane.

The builder enforces the following before opening provider stores:

- at least one composition is supplied;
- every composition validates its native settings and profile identity;
- profile ID, version and SHA-256 exactly match the workflow reference;
- Collaboration database paths are distinct across provider units;
- Adapter database paths are distinct across provider units;
- a Task activation source exists and is shared by all child runners.

Each child still has its own Collaboration control, Adapter Edge, driver,
workflow resolver, and return collector. The composite only sequences child
cycles. It does not select a model from a prompt, cost, UI state or provider
availability, and it does not merge provider-owned facts.

## Why this is an architecture boundary

The stable decision is the ownership and isolation rule: multiple providers may
be composed under one daemon scheduler while Task authority remains shared and
provider execution state remains isolated. The concrete driver type is a
replaceable implementation detail. A provider can therefore be replaced or
added without changing Task, Collaboration, Artifact, Verification or client
contracts, provided its exact profile and lifecycle evidence satisfy admission.

The cost is explicit configuration and duplicated per-provider local stores.
That consumes more disk and opens more bounded worker state, but prevents one
provider's adapter lifecycle, profile route or recovery state from being
silently reused by another provider. A single shared Adapter Edge path is
rejected rather than treated as an optimization.

## Admission boundary

This phase does not admit DSH, Kimi or any other second Harness. The caller must
still construct `NativeHarnessCompositionProfile` from the attested capability
path. Candidate adapters remain outside daemon provider selection until their
authenticated lifecycle, Artifact/return semantics and recovery evidence are
complete.

## Verification

The multi-unit builder reuses the existing exact profile validation and
provider-neutral runner contracts. The local test matrix now includes two
admitted test profiles sharing one `TaskActivationSource`, each with isolated
Collaboration/Adapter stores, and a duplicate-store-path rejection before edge
opening. One child uses the real `DshAcpDriver` type without starting a DSH
process; this verifies heterogeneous type erasure only. Provider admission
remains a separate gate.
