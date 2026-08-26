# Phase 2-38: Production Memory candidate-producer composition

- Status: implemented locally; candidate-only runtime bridge
- Evidence date: 2026-08-27
- Decision owner: Founder

## Purpose

The Memory candidate-producer registry was already a valid process-local
boundary, but production bootstrap did not previously install any bindings.
This slice closes that composition gap without turning runtime output into
accepted memory.

## Composition contract

The user-owned production bootstrap file may contain an optional
`memory_candidate_producers` list:

```json
"memory_candidate_producers": [
  {
    "producer_id": "harness:codex",
    "principal_id": "harness:codex",
    "principal_kind": "Harness",
    "scope_ref": "scope:founder"
  }
]
```

At daemon composition time, each entry is converted to a validated
`MemoryCandidateProducerBinding` and installed into the Memory candidate
registry. A provider integration then receives only the handle for its own
route. The handle supplies the fixed scope and fixed authenticated principal;
the proposal carries content, provenance and idempotency only.

```text
user config
    |
    v
validated producer binding
    |  fixed producer_id + principal + scope_ref
    v
agentosd composition -> producer registry -> single-route handle
                                             |
                                             v
                                  explicit submit_proposal()
                                             |
                                             v
                                     Memory Authority
                                             |
                                             v
                                          candidate
                                             |
                              Founder accept / Governance revoke
```

The configuration parser admits only `Agent`, `Model` and `Harness` producer
identities. `Founder`, `FounderAuthority`, `GovernanceKernel` and
`RecoveryCoordinator` remain governance identities and cannot be registered
as candidate producers. Invalid identifiers, unsupported kinds and malformed
entries fail closed before the authority is opened.

Omitting the optional list leaves the candidate registry empty. This preserves
compatibility with older local configurations while keeping the safe default:
no runtime receives a candidate-writing capability unless the installation
explicitly configures one.

## What this closes

- The production composition root now owns installation of fixed producer
  bindings instead of leaving the registry as a test-only capability.
- The example configuration documents the first admitted route shape without
  claiming that every terminal transcript is a memory.
- Bootstrap tests cover valid identity binding, governance/unknown identity
  rejection and invalid route rejection.

## What this does not close

This is not automatic transcript ingestion. A provider runner still needs an
explicit, reviewed integration that decides when a user-visible proposal is
created and calls its bound handle. The candidate remains subject to Founder
acceptance, and Python retrieval continues to read accepted snapshots only.
The Codex cross-component test remains the evidence for that explicit
candidate handoff; Kimi and DSH remain candidate-only provider evidence.

## Verification

```powershell
cargo fmt --all -- --check
cargo test -p egopulse-agentosd --lib bootstrap::tests -- --nocapture
cargo test -p egopulse-agentosd --lib memory_mutation::tests -- --nocapture
```

The example JSON was also parsed successfully on Windows x64.
