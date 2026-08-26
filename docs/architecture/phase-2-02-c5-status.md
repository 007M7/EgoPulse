# Phase 2-02 / C5 implementation status

- Status: C5 CLI/TUI E2E closed; Phase 2-02 composition root configuration closed
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

The CLI and TUI now consume the same `client-operations::ClientAttachment`
boundary for session metadata, permission revalidation, command authorization,
and bounded Task/Approval projection snapshots. Their remaining differences
are command-line parsing, terminal interaction, rendering, and user-facing
error presentation. The shared client snapshot path and the real Windows IPC
fixture both pass locally; no surface-specific write authority was introduced.

The TUI command surface now also exposes the read-only `evidence.get` operation
through `GetEvidenceGraph`, matching the CLI's Evidence Graph boundary. It
returns only redacted graph counts and references; it does not add an evidence
write path or bypass the read-model permission check. Local TUI tests cover the
form-to-operation mapping. The real Windows C5 fixture additionally invokes
the TUI command against a missing graph and verifies the typed `NOT_FOUND`
failure, proving that this path reaches the daemon read model and fails closed.

## Composition root boundary

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

The local G4-06 verification suite currently passes all 16 tests, including
Sego mapping, stale profile/input binding, checker policy rewrite rejection,
timeout, crash, and output-limit probes. The existing supervisor and mapper
are therefore reused rather than duplicated.

`GovernedSegoRunner` now composes those two existing primitives into one
provider-neutral attempt boundary. It preserves a successful checker receipt
for Artifact admission, maps invalid/untrusted output to an explicit checker
error result, and maps timeout/crash/output-limit/spawn failures without
silently producing a pass. `GovernedVerificationExecutionCoordinator` now
composes that runner with the Verification Authority start, criterion-record
and immutable-artifact-completion commands. It is deliberately limited to one
reviewed criterion and replays a completed artifact instead of rerunning it.

The application boundary also now provides
`SystemTaskVerificationWriteBack`. It accepts only a completed artifact that
binds to the exact pending Task revision/work revision, and then submits the
Task mutation with a fixed `SegoVerification` system principal and deterministic
idempotency key. This closes the write-side owner primitive.

Task Authority now emits a digest-bound `verification-authority` outbox message
when `SubmitTaskEvidence` commits. `pending_task_verifications()` validates the
event kind, task/revision/work-revision binding, `VerificationPending` state and
Artifact set presence before exposing the handoff. The verification worker must
ACK that exact message digest after it durably accepts the handoff; it does not
receive a direct Task database or repository handle. This closes the durable
Task-to-Verification trigger without pretending that the full Sego production
composition is complete.

The internal `VerificationHandoffIntake` boundary now turns that handoff into a
deterministic, digest-bound `CreateVerificationRequest` command. Its reviewed
plan supplies only claim, semantic-profile, criterion and checker-profile
facts; the Artifact Authority read boundary supplies the sealed manifest and
lineage, which are checked against the Task revision before command creation.
The intake ACKs the Task outbox only after Verification commits or idempotently
replays. It is now composed into `ConfiguredVerificationWorker` together with
the reviewed profile, Sego coordinator, Verification recovery scan and Task
write-back. The user JSON bootstrap path now accepts the same worker through an
explicit `verification_worker` object. It decodes the handoff plan, complete
checker profile, checker request bytes, executable/workspace paths, Sego mapper
policy, deterministic ID prefixes and process limits. Invalid hex, unknown
enum values, non-SHA256 output addresses, or a worker without Verification
criteria fail before any daemon is built.

The user-owned worker contract is covered by the bootstrap unit matrix in
`apps/agentosd/src/bootstrap.rs`: one case proves every execution boundary is
decoded, and negative cases prove invalid request bytes and hash algorithms
are rejected. The worker remains optional; when omitted, Verification stays
deny-by-default and no background execution worker is started.

The field-level example is maintained at
`config/verification-worker.example.json`; it is merged as the
`verification_worker` property of the root production bootstrap JSON. It is a
configuration template, not a claim that the placeholder executable,
workspace, profile or artifact references are usable without replacement.

The G4-10 integration fixture in
`apps/agentosd/tests/verification_intake_g4_10.rs` now proves this boundary with
real local Authority stores: Task creation/activation/evidence submission emits
the durable handoff; an Artifact owner projection supplies a sealed set whose
claim, evidence, artifact digest and lineage are checked by
`ArtifactBackedReferenceResolver`; Verification attests the checker profile and
commits exactly one request; only then does Task ACK the original message. A
second intake poll observes no pending handoff, proving the committed-then-ACKed
path is idempotent. This fixture still covers only the Task-to-Verification
handoff. The same fixture now composes the worker and proves queued request
execution, checker failure mapping, immutable completion, Task transition to
`VerdictPending`, and a second-cycle artifact/write-back replay after the Task
revision has advanced. The separate G4-06 execution test continues to prove
the provider-neutral coordinator in isolation.

The repeatable targeted verification command is:

```powershell
cargo test -p egopulse-agentosd --test verification_intake_g4_10 -- --nocapture
```

Current Windows x64 result: `1 passed, 0 failed`. This closes the
application-level G4-10 handoff, verification-intake and replay evidence
represented by the fixture. It does not claim physical power-loss
qualification or blob-at-rest security; those remain separate
release/recovery obligations.

`with_codex_harness` and `ProductionBootstrapConfig::build` remain explicit
production composition APIs and not implicit unsafe defaults. Verification
remains deny-by-default for unreviewed external references. The worker may be
installed either through explicit `VerificationWorkerConfig` injection or the
equivalent user-owned JSON contract; neither path derives execution policy
from a Task, UI, Memory/RAG result or checker response. agentosd still has no
Local API Verification command port; execution remains a daemon-owned
background workflow rather than a client-injected command.

## Next unit: Phase 2-03

Phase 2-03 adds a second official Harness integration and the multi-model collaboration policy. It
must preserve the same `NativeHarnessDriver` / `GovernedHarnessAdapter` boundary, but each adapter
owns its native protocol, capability profile, approval routing and recovery evidence. Model choice
is a governed workflow fact; it is not inferred by the UI, Memory/RAG layer or a provider response.
