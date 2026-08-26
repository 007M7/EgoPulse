# Phase 2-24: Exact profile routing at Task activation

## Status

Implemented and locally verified. This phase closes the activation-side
counterpart of Phase 2-23. It does not admit a second Harness or enable
dynamic model selection.

## Problem closed

Filtering only the Collaboration dispatch outbox is too late for a parallel
multi-Harness composition. If two provider runners read the same Task
activation handoff, both can attempt to create the same workflow before their
later dispatch filters separate the envelopes.

## Frozen routing rule

```text
Task activation handoff
        |
        v
configured workflow profile reference
        |
        +-- exact match --> this provider runner may acknowledge and start
        |
        `-- mismatch ----> leave handoff pending for another provider
```

`GovernedTaskActivationRunner` now accepts the exact
`ContractReference` through `with_capability_profile_ref`. The check is made
after the runner's resolver produces the reviewed workflow configuration but
before workflow creation or activation acknowledgement. The same exact
reference is then used when registering and dispatching the resulting
Collaboration envelopes.

The production native composition binds this filter from its frozen workflow
configuration and first verifies that the composition profile carries the
same complete reference. It cannot be inferred from a prompt, UI selection,
model availability or a provider response.

## Invariants and costs

- A runner cannot acknowledge a workflow whose profile has a different ID,
  version or SHA-256 digest.
- A mismatching activation remains pending; no duplicate workflow or false
  acknowledgement is produced by that runner.
- A matching workflow cannot later be sent through a different profile-bound
  dispatch route because registration and selection use the same reference.
- The cost is that each parallel provider composition must carry a distinct,
  reviewed resolver/configuration pair and exact profile reference. There is
  no implicit fallback route.
- The unfiltered constructor remains for the existing single-runner test and
  compatibility path; production multi-Harness composition must install the
  exact filter.

## Verification evidence

Local Windows x64 checks for this phase:

```text
cargo fmt --all -- --check                                      passed
cargo clippy -p egopulse-local-ide-control --all-targets -- -D warnings passed
cargo clippy -p egopulse-agentosd --all-targets -- -D warnings  passed
cargo test -p egopulse-local-ide-control --lib                 7 passed
cargo test -p egopulse-agentosd --lib                          49 passed
git diff --check                                                passed
```

The existing single-runner tests retain their behavior without a filter;
the production assembly now installs the exact workflow profile filter.

Second-Harness admission remains a separate provider evidence decision.
Codex remains the sole active production Harness; DSH and Kimi remain
candidate-only.
