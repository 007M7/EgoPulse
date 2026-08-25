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

The Verification side now has the owner-backed reference resolver and the
agentosd `ArtifactAuthorityReferenceSource` adapter. It proves that a request
references one sealed ArtifactSet with matching manifest and lineage, and that
all Claim/Evidence/Artifact members remain inside that set. The resolver cannot
obtain an Artifact store or write handle. The implementation is pushed as
`df37f09`.

The production bootstrap now opens the Artifact Authority with the configured
`ConfiguredArtifactAdmissionGuard`. Its user-owned configuration contains the
artifact blob/database locations and explicit workspace, artifact-type,
transformation, retention, claim, and evidence contract allowlists. The same
owner handle is shared with the typed Artifact projection source. This closes
the artifact admission prerequisite, but does not yet authorize Verification
requests or Sego output.

The read boundary now also exposes digest-reverified content bytes through the
separate `ArtifactContentSource` contract. It returns bytes only; no Artifact
database, blob path, or write handle crosses into Verification. This is the
content-plane prerequisite for the supervised Sego runner and is covered by
the Artifact G4-05 read-boundary test.

The local G4-06 verification suite currently passes all 15 tests, including
Sego mapping, stale profile/input binding, checker policy rewrite rejection,
timeout, crash, and output-limit probes. The existing supervisor and mapper
are therefore reused rather than duplicated.

`GovernedSegoRunner` now composes those two existing primitives into one
provider-neutral attempt boundary. It preserves a successful checker receipt
for Artifact admission, maps invalid/untrusted output to an explicit checker
error result, and maps timeout/crash/output-limit/spawn failures without
silently producing a pass. It owns no Authority store and performs no Task or
Verdict write; those remain the next explicit composition step.

Task Authority now emits a digest-bound `verification-authority` outbox message
when `SubmitTaskEvidence` commits. `pending_task_verifications()` validates the
event kind, task/revision/work-revision binding, `VerificationPending` state and
Artifact set presence before exposing the handoff. The verification worker must
ACK that exact message digest after it durably accepts the handoff; it does not
receive a direct Task database or repository handle. This closes the durable
Task-to-Verification trigger without pretending that the full Sego production
composition is complete.

`with_codex_harness` and `ProductionBootstrapConfig::build` remain explicit
production composition APIs and not implicit unsafe defaults. Verification
remains deny-by-default for unreviewed external references until Sego/checker
composition is supplied. The remaining integration is not a path in the JSON
file: agentosd still has no Local API Verification command port, and the new
Task outbox trigger is not itself a Verification request or run. A real Sego
production path must therefore consume that handoff and compose the Artifact
owner read boundary, supervised runner, mapper, Verification Authority
commands, and system-only Task verification write-back as one unit. Until that
vertical exists, `DenyVerificationReferences` stays active.

## Next unit: Phase 2-03

Phase 2-03 adds a second official Harness integration and the multi-model collaboration policy. It
must preserve the same `NativeHarnessDriver` / `GovernedHarnessAdapter` boundary, but each adapter
owns its native protocol, capability profile, approval routing and recovery evidence. Model choice
is a governed workflow fact; it is not inferred by the UI, Memory/RAG layer or a provider response.
