# R-9C governed Harness content core-closure evidence

- Date: 2026-09-05
- Status: R9C.5 core closed / locally verified
- Decision authority: `conversation:2026-09-04:founder-froze-r9c-d01-d12-and-phase-2-82-section-7`
- Parent plan: `phase-2-82-r9c-implementation-readiness-plan-20260904.md`
- Scope: one governed Harness content path through the real Windows daemon, Local API, shared Client Kernel, CLI and TUI

## Outcome

The frozen R9C-D01 through R9C-D12 invariants are closed as one product
capability, not as twelve independent feature units. A Provider-native Codex
assistant message now crosses the existing Adapter safe-content ledger and
outbox, the existing Local Read Model and Local API, and reaches the real CLI
and ConPTY TUI through the same shared Rust client operation.

The C5 implementation uses the production Codex content mapper and production
daemon composition. The fixture supplies deterministic native events and a
release barrier only; it adds no RPC, Authority, database, alternate client
state machine or test-only production endpoint.

## Route identity correction

The first real-process run exposed a pre-existing incomplete route-binding
seam. `ConfiguredSingleHarnessWorkflow` derived a trusted Provider/model route
and the command-side dispatch fingerprint included it, but Collaboration's
Authority-side envelope reconstruction received route-free dispatch material.
The Authority correctly rejected the mismatch with
`DISPATCH_FINGERPRINT_MISMATCH`.

The correction keeps the existing contract boundary:

- the configured workflow inserts the immutable route binding into
  `SingleHarnessWorkConfig.material` before reference-guard binding;
- command construction and Authority reconstruction consume that same trusted
  material;
- the Authority validates the canonical route digest and capability-profile
  identity before commit;
- the original dispatch envelope and its fingerprint contain the route before
  Adapter preparation or native send;
- no Proto revision, post-persistence enrichment or relaxed fingerprint check
  was introduced.

A focused regression test proves that the separately returned workflow route
and the route stored in trusted dispatch material are byte-for-byte equal.

## Real-process C5

`r9c_real_daemon_cli_and_tui_share_one_governed_harness_content_stream` proves
the complete path with three distinct processes: daemon, CLI and ConPTY TUI.
The scenario:

1. prepares and Founder-confirms one governed Task through the real CLI;
2. waits for the governed dispatch and attaches `content watch` to an empty
   baseline before releasing native content;
3. maps two APPEND mutations and one FINALIZE mutation through the production
   Codex mapper;
4. observes a live safe record in the CLI and the finalized text in the TUI;
5. proves both surfaces expose the same safe-message identity and immutable
   Provider/model/role/Attempt source labels;
6. scans CLI stdout/stderr and TUI output for a raw native canary and finds no
   disclosure;
7. proves the Task remains Active and read-only Task/Policy Authority table
   digests remain unchanged;
8. reopens the Adapter Edge after daemon shutdown and verifies one dispatch,
   four observations, three candidates, three safe-ledger records, zero
   pending/quarantined candidates, zero pending projections and valid database
   integrity.

## Verification

The accepted candidate passed:

```text
cargo test -p egopulse-local-ide-control
  8 unit tests + 47 integration tests passed

cargo test -p egopulse-agentosd --lib \
  tests::configured_workflow_carries_one_route_binding_in_trusted_dispatch_material \
  -- --exact
  1 selected test passed

cargo test -p egopulse-agentosd --test c5_00_daemon_fixture \
  r9c_real_daemon_cli_and_tui_share_one_governed_harness_content_stream \
  -- --nocapture
  1 selected test passed

pnpm run ci:local
  exit code 0; all repository stages passed
  serial c5_00_daemon_fixture: all 37 tests passed
```

The local CI covered repository integrity, contracts and generated bindings,
TypeScript, the Rust workspace, Python foundation/contract bindings,
Memory/RAG checks, Windows package integrity and deterministic process cleanup.
Desktop was explicitly skipped by the phase-one CLI/TUI scope. The existing
Windows OpenSSL missing-PDB linker warning remained non-blocking.

An exploratory parallel C5 invocation produced resource contention in the
existing U-04c post-commit-unavailable scenario; its exact rerun passed. The
repository's authoritative C5 invocation is intentionally serial and passed
all 37 tests in local CI.

## Explicit boundary

This closes R9C.5 for the already admitted Codex path. It does not promote
DeepSeek, Kimi or GLM admission, claim Provider-native mapping for those
families, add Memory/RAG behavior, implement Desktop, create a second client
kernel, or claim a signed/public Early Access package. Those remain subsequent
product deliverables on top of the frozen kernel.
