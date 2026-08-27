# G4-07 daemon consume-pump evidence

Status: closed for the current local daemon composition (2026-08-27).

The Founder Verdict -> Task handoff is now evidenced at both levels:

1. `production_verdict_g4_07` executes the real Task Authority and Founder
   Verdict Authority against SQLCipher stores. It proves that an issued
   Founder Verdict moves a Task from `VerdictPending` to its terminal state,
   creates exactly one durable cross-authority consume message, and that the
   configured consumer commits/replays the Verdict transition before ACKing the
   Task outbox.
2. The `agentosd` composition test
   `daemon_composition_polls_the_injected_founder_verdict_consumer` starts the
   real `DaemonComposition::serve()` path, observes the injected consume worker
   run from the background worker set, and verifies clean shutdown.

The runtime ownership remains unchanged:

```text
TaskAuthority -- durable consume outbox --> ConfiguredFounderVerdictConsumeWorker
                                                     |
                                                     v
                                      FounderVerdictAuthority.Consume
                                                     |
                                                     v
                                      Task outbox ACK after commit/replay
```

The worker is an application coordinator. It does not write Task state except
for the outbox acknowledgement and does not become a second Verdict writer.
The public CLI/TUI Task operations continue to use the same Local API and
read-model projection; the daemon background pump is an internal lifecycle
concern rather than a new client surface.

Focused evidence:

```text
cargo test -p egopulse-agentosd --lib daemon_composition_polls_the_injected_founder_verdict_consumer -- --nocapture
1 passed, 0 failed

cargo test -p egopulse-agentosd --test production_verdict_g4_07 -- --nocapture
1 passed, 0 failed
```

