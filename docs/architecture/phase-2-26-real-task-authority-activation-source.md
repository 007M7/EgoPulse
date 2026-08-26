# Phase 2-26: Real TaskAuthority activation source

## Status

`AuthorityCommandPorts` now has a tested production path from a committed
`TaskAuthority` activation to the shared `TaskActivationSource` contract.
The source is the encrypted TaskAuthority SQLCipher store; the runner does
not receive a second queue, shadow task record or model-generated activation.

## Frozen source contract

```text
TaskAuthority transition commit
        |
        +--> task_cross_authority_outbox
        |       destination = collaboration-control
        |       payload      = encoded Activated TaskEvent
        |       digest       = SHA-256(payload)
        |
        v
AuthorityCommandPorts::pending_task_activations
        |
        +--> destination filter
        +--> payload digest verification
        +--> protobuf decode and Activated/snapshot/run invariants
        |
        v
TaskActivationHandoff
        |
        v
AuthorityCommandPorts::acknowledge_task_activation
        |
        `--> conditional update(message_id, digest, pending) -> consumed
```

The source-side acknowledgement is intentionally a compare-and-ack operation:

- a wrong digest returns `false` and leaves the handoff pending;
- the matching digest changes exactly one pending row to `consumed`;
- a repeated matching acknowledgement returns `false` because the row is no
  longer pending;
- a resolver route miss does not call this source acknowledgement.

The TaskAuthority reader also rejects malformed or semantically inconsistent
payloads before the handoff reaches Collaboration. This keeps source integrity
validation in the owning authority rather than duplicating it in each client
surface or Harness adapter.

## Recovery evidence

`activation_source_port_reads_and_acknowledges_real_task_authority_outbox` in
`apps/agentosd/src/owners.rs` performs the following bounded scenario:

1. Create and activate a Task through a real `TaskAuthority`.
2. Read the resulting activation through `AuthorityCommandPorts`.
3. Reject a wrong digest without consuming the row.
4. Drop the composed ports before acknowledgement, reopen the encrypted
   TaskAuthority and compose fresh ports.
5. Read the same message ID and digest again.
6. Acknowledge it once, reject the repeated acknowledgement, and verify the
   source is empty.

This proves durable replay after a consumer interruption, exact digest binding
and the actual owner-to-source composition boundary. The test runs with the
real TaskAuthority transition commit and real SQLCipher-backed store; only the
policy/verdict authorities are deny fixtures because this slice concerns Task
activation source ownership.

## Explicit limits

This phase does not claim simultaneous process-level polling or lease/claim
semantics. The current V-01 design has one TaskAuthority instance behind the
`Arc<Mutex<TaskAuthority>>` process-local single-writer boundary. Durable
compare-and-ack prevents a second acknowledgement after the first commit, but
the system intentionally does not yet promise distributed worker leasing.
That is a later multi-process lifecycle requirement, not a hidden property of
the current local runner.

## Local verification

```text
cargo fmt --all -- --check                                      passed
cargo test -p egopulse-agentosd activation_source_port_reads_and_acknowledges_real_task_authority_outbox --lib -- --test-threads=1
                                                               1 passed
cargo test -p egopulse-agentosd --lib                          50 passed
```
