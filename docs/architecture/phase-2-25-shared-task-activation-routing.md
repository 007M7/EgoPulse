# Phase 2-25: Shared Task activation routing

## Status

The provider-neutral workflow resolver now explicitly distinguishes an
activation that belongs to another reviewed route from a resolver failure. The
local multi-Harness scheduling seam can therefore share one Task activation
source without the first runner blocking later provider runners on a normal
route mismatch.

This is a composition prerequisite. It does not admit DSH or Kimi and does not
make provider availability a routing decision.

## Frozen resolution contract

```text
Task activation handoff
        |
        v
provider workflow resolver
        |
        +-- NotApplicable --> do not create, do not dispatch, do not ACK
        |
        +-- Resolved ------> exact profile check --> governed workflow
        |
        `-- Error ---------> fail the runner cycle; retain source handoff
```

`SingleHarnessWorkflowResolution` has two successful outcomes:

- `NotApplicable` means the handoff is valid but belongs to another reviewed
  workflow route. It is not an operational error.
- `Resolved` carries the reviewed `SingleHarnessWorkConfig`. The runner still
  applies the exact `ContractReference` filter before any workflow write or
  acknowledgement.

The existing resolver errors retain their fail-closed meaning. An unavailable
resolver or invalid configuration still fails the cycle and cannot be
silently converted into a route miss.

## Invariants and costs

- Only the runner that resolves and exactly matches a workflow may acknowledge
  its Task activation handoff.
- A non-applicable activation remains pending for another provider runner.
- A route miss does not prevent the current runner from processing later
  matching handoffs in the same bounded cycle.
- Workflow routing still comes from reviewed run identity and exact capability
  references, never prompt text, UI state, model response or provider
  availability.
- The resolution payload is boxed because `SingleHarnessWorkConfig` is large;
  a route miss does not allocate or carry the full workflow value.
- The composite currently sequences child cycles. This phase does not claim
  concurrent provider execution or second-Harness production admission.

## Verification evidence

The integration regressions
`task_activation_runner_leaves_other_routes_pending_and_dispatches_its_match`
and
`two_profile_bound_runners_share_activation_source_without_cross_ack_or_dispatch`
use a deterministic shared source and separate encrypted Adapter Edge stores.
Together they prove that the runner:

- observes both handoffs;
- starts, dispatches and acknowledges only the matching handoff;
- leaves the foreign handoff pending;
- continues its terminal-observation cycle without converting the foreign
  route into a resolver failure;
- lets two independently profile-bound runners consume their own handoffs in
  sequence, with each Adapter Edge containing only its own exact profile
  dispatch.

These fixtures do not yet replace the source with a real durable TaskAuthority
outbox, and they do not prove simultaneous process-level polling or crash
recovery. Those are the next persistence and lifecycle evidence slice.

Local Windows x64 verification:

```text
cargo fmt --all -- --check                                      passed
cargo clippy -p egopulse-local-ide-control -p egopulse-agentosd --all-targets -- -D warnings passed
cargo test -p egopulse-local-ide-control --lib                 7 passed
cargo test -p egopulse-local-ide-control --test collaboration_control_g4_03 -- --test-threads=1 23 passed
cargo test -p egopulse-agentosd --lib                          49 passed
```

The next multi-model composition slice must replace the deterministic source
with the real durable TaskAuthority activation outbox and prove concurrent
polling, compare-and-ack behavior, restart replay and recovery without
cross-ack, cross-dispatch or cross-write Adapter Edge state. Provider
admission evidence remains a separate gate.
