# Phase 2-02 / C5 implementation status

- Status: C5 CLI/TUI E2E closed; Phase 2-02 composition root remains in progress
- Evidence date: 2026-08-26
- Decision owner: Founder

## Closed evidence

The first governed single-Harness vertical now has one process-local writer path:

```text
Task Authority activation handoff
        |
        v
TaskActivationGuardSet binds the activated Task revision
        |
        v
Collaboration Control commits the reviewed SingleHarnessWorkConfig
        |
        v
Adapter Edge + Codex App Server driver dispatch
        |
        v
Task activation acknowledgement
```

The production composition entry is `DaemonProviders::with_codex_harness` and accepts an explicit
`CodexHarnessCompositionConfig`. It does not derive a plan, model, workspace, bundle or authority
from an untrusted Task payload.

C5 real-process evidence is in `apps/agentosd/tests/c5_00_daemon_fixture.rs`. The authoritative
local invocation is:

```powershell
cargo test -p egopulse-agentosd --test c5_00_daemon_fixture -- --test-threads=1 --nocapture
```

The serial run passed all six tests:

- daemon opens a session over real local IPC;
- CLI attaches and preserves authority rejection;
- CLI owner writes and projection await complete;
- CLI fails closed across daemon restart and reconnects;
- malformed await/stale approval do not partially commit;
- the child daemon fixture lifecycle exits cleanly.

The `--test-threads=1` constraint is required because each test starts a child daemon and owns a
separate Windows Named Pipe instance. Running this fixture group in parallel caused a test-process
lifecycle timeout even though every test passes independently and in serial mode.

## Remaining Phase 2-02 work

The normal `agentosd` binary now loads the reusable `ProductionBootstrapConfig`
from `EGOPULSE_USER_CONFIG` (default `egopulse-data/agentos-config.json`). It
supplies the following as reviewed configuration:

- authority database paths, epochs and non-zero keys;
- local OS-principal allowlist and authority-principal mapping;
- Task/Policy/Verdict reference guards;
- Codex executable, input bundle root, workspace root and workflow configuration.

The reusable identity part of that boundary is now implemented in
`apps/agentosd/src/security.rs`: `AllowlistedPrincipalResolver` matches only the
platform-derived peer fingerprint against explicit grants, while
`ConfiguredAuthorityPrincipalResolver` maps an authenticated session principal to
owner kinds independently for Task, Policy and Verdict. Missing mappings fail
closed; no OS identity or request field is promoted to Founder implicitly.

`ProductionBootstrapConfig::build` provides the typed full composition API: it
opens all four Authority stores, shares Task and Verification owner handles,
injects the concrete Task/Policy/Verdict guards, and installs the Codex
composition. Secret keys are resolved only from environment variables named by
the user-owned file. Identity configuration cannot be mistaken for evidence
validation or Harness configuration.

The first concrete production-side guard is now `LocalUserPolicyResolver`.
It resolves approval requests from the Adapter Edge's durable projection,
restricts requested scopes to an explicit reviewed set, and validates the
Adapter-owned approval receipt on consumption. Founder Verdict still requires
its own evidence-backed resolver.

Task creation now has the concrete `ConfiguredTaskCreationGuard`, which binds
the first vertical to reviewed work types, input snapshot IDs, target scopes,
and exact acceptance/budget contract references. It is an explicit composition
input and does not make the normal daemon serving by itself.

Founder Verdict now has `ConfiguredFounderVerdictResolver`. It reads a
committed Verification artifact through an Authority-owned read boundary,
checks scope/conclusion consistency, requires an allowlisted Founder
confirmation proof, and bounds the verdict expiry. Task commit receipt
consumption is fail-closed by default, while the typed production composition
supplies its Task Authority evidence source. The consumption resolver contract carries the stored verdict scope
into receipt validation, binding the check to the exact task and revision.

`with_codex_harness` and `ProductionBootstrapConfig::build` remain explicit
production composition APIs and not implicit unsafe defaults. Verification
remains deny-by-default for unreviewed external references until Sego/checker
composition is supplied.

## Next unit: Phase 2-03

Phase 2-03 adds a second official Harness integration and the multi-model collaboration policy. It
must preserve the same `NativeHarnessDriver` / `GovernedHarnessAdapter` boundary, but each adapter
owns its native protocol, capability profile, approval routing and recovery evidence. Model choice
is a governed workflow fact; it is not inferred by the UI, Memory/RAG layer or a provider response.
