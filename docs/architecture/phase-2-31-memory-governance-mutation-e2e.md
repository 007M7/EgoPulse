# Phase 2-31: Memory governance mutation E2E

## Status

`M-11 closed`: the governed Memory mutation path is verified over the real
Windows local IPC boundary. CLI and TUI use the same Local API command
gateway; neither surface opens the Memory database or performs an Authority
transition locally.

## Verified path

```text
CLI: memory candidate
        |
        v
LocalCommandGatewayService/ExecuteMemoryMutation
        |  session + oneof permission + configured memory identity
        v
Rust Memory Authority / SQLCipher / single writer
        |
        +--> candidate, revision 1
        |
TUI: memory-accept
        |
        +--> accepted, revision 2
        |
CLI: memory retrieve
        |
        +--> accepted reference visible; content remains redacted
        |
TUI: memory-revoke
        |
        +--> revoked, revision 3
        |
CLI: memory retrieve
        |
        `--> revoked reference absent
```

The real fixture also binds both surfaces to the same authenticated local
principal and configures the fixture's Memory identity as
`MemoryPrincipalKind::Founder`. The production composition has the same
shape through `identity.memory_kind`; an absent or incompatible mapping still
fails closed.

## Acceptance evidence

The authoritative test is:

```powershell
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture `
  m11_real_cli_and_tui_share_governed_memory_mutations_over_local_ipc `
  -- --exact --nocapture --test-threads=1
```

Observed result on Windows x64:

```text
test m11_real_cli_and_tui_share_governed_memory_mutations_over_local_ipc ... ok
test result: ok. 1 passed; 0 failed
```

The test proves:

- a CLI candidate mutation receives a durable candidate receipt at revision
  `1`;
- a TUI accept mutation receives an accepted receipt at revision `2`;
- the accepted record is returned by the existing read-only retrieval path;
- retrieval exposes the memory ID and content digest but not raw content;
- a TUI revoke mutation receives a terminal revoked receipt at revision `3`;
- the revoked record is excluded from a later retrieval over the same scope.

## Implementation correction captured by this gate

The E2E test found that CLI memory mutations were using `require_rpc` for a
`per_command_oneof` RPC. The client therefore rejected valid mutations before
they reached the daemon. CLI now resolves the mutation branch to
`submit_memory_candidate`, `accept_memory` or `revoke_memory` and performs the
same command-level authorization precheck already used by TUI.

The fixture also explicitly wires the shared Memory Authority into both the
retrieval and mutation ports. Leaving the mutation port at its default
fail-closed implementation is now detectable by the real-process test.

## Boundary preserved

This gate does not make Agent, Model or Harness identities Founder-capable.
The fixture uses Founder only as a reviewed test identity. Production
candidate producers still need an independently configured principal kind and
the appropriate future in-process producer boundary. Python RAG remains
read-only and receives accepted snapshots only.

## Next slice

M-11 closes the initial user-facing Memory governance path. The next Memory
slice is not another surface-specific implementation: it is the reviewed
producer admission path for Agent/Model/Harness candidate submissions, with
separate identity bindings, evidence, replay and scope tests. Semantic RAG
promotion remains behind the existing offline evaluation gate.
