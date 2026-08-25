# Phase 2-02 production bootstrap boundary

## Decision

The daemon composition root separates three decisions that were previously easy
to conflate:

1. **OS peer authentication**: `AllowlistedPrincipalResolver` accepts a local
   IPC peer only when its transport-derived fingerprint appears in explicit
   configuration and its `PrincipalGrant` validates against the embedded
   authorization profile.
2. **Authority principal mapping**:
   `ConfiguredAuthorityPrincipalResolver` maps the authenticated session
   principal ID to Task, Policy and Verdict owner kinds independently. An absent
   mapping returns `Unavailable`; it is not inferred from the current Windows
   account, CLI/TUI surface, or command payload.
3. **Reference/evidence authorization**: Task creation, Policy approval and
   Founder Verdict resolvers remain injected Authority-owned guards. Identity
   configuration does not authorize a task reference, adapter receipt,
   verification conclusion or founder confirmation.

The Policy side now has a concrete first implementation:
`LocalUserPolicyResolver` reads the pending approval projection and later the
Adapter-owned approval receipt through provider-neutral `AdapterEdge` methods.
It permits only explicitly configured scope references and emits an authority
proof bound to the authenticated local principal, embedded authorization
contract, request observation and short expiry. A missing or divergent durable
record is rejected.

The Task Create side now has the corresponding `ConfiguredTaskCreationGuard`.
It accepts only explicitly reviewed work types, input snapshot IDs, target
scope references and exact acceptance/budget contract references. Its evidence
refs describe those reviewed inputs; it does not infer approval from the
client request or write a second Task record.

The Founder Verdict side now has `ConfiguredFounderVerdictResolver`. Its
Verification evidence source reads a committed artifact through the owning
Verification Authority's read API, then binds the verdict scope and observed
conclusion to that artifact. It also requires an explicitly allowlisted Founder
confirmation proof and a bounded expiry. Task commit receipt validation remains
a separate injected source; the typed production composition now supplies the
Task Authority receipt source. The Verdict resolver contract now receives the
stored verdict scope during consumption, so the Task source can validate the
receipt against the exact task ID and resulting revision rather than guessing
from a receipt string.

`ProductionBootstrapConfig::build` is now the reusable typed composition root.
It opens Task, Verification, Policy and Founder Verdict exactly once, shares
the Task handle with command ports and receipt validation, shares the
Verification handle with Verdict evidence reads and projection ACKs, then
installs the explicit identity policy and Codex Harness composition. There is
no test Allow resolver in this path.

The normal `agentosd` entrypoint remains fail-closed until a user-owned
configuration loader can supply the typed bootstrap, including the already
structured single-Harness workflow. This is deliberate: a daemon that
authenticates a user but silently guesses workflow facts or uses test guards
would be a governance regression, not a usable production mode.

Until the Sego/checker composition enters the Verification vertical, the
production bootstrap uses `DenyVerificationReferences`: Verification storage
and projection are available, but unreviewed external verification requests
cannot be accepted.

The first prerequisite for replacing that deny boundary is now available in
Artifact Authority: `read_artifact`, `read_claim`, `read_evidence`,
`read_artifact_set` and digest-reverified `read_blob` expose immutable
snapshots or bytes without exposing the private store, filesystem path, or a
write path. The Verification boundary models the content plane separately as
`ArtifactContentSource`; the next resolver/runner must consume only these
owner-backed methods, verify a sealed ArtifactSet/Claim/Evidence lineage, and
then invoke the separately supervised Sego checker. User configuration alone
remains insufficient to authorize evidence.

The agentosd composition now also contains
`ArtifactAuthorityReferenceSource`. It accepts only the shared
`Arc<Mutex<ArtifactAuthority<...>>>` owner handle and implements the
provider-neutral Verification read boundary. Storage failures are surfaced as
unavailability and decode/blob failures as corruption; neither is converted
into an empty or trusted result. Production bootstrap now opens Artifact
Authority with `ConfiguredArtifactAdmissionGuard` and the user-owned
workspace/contract allowlists, and shares that same owner with the projection
source. This establishes the artifact admission boundary without exposing a
store handle to Verification.

## Owner boundary

```text
Windows Named Pipe / Unix socket
        |
        v
LocalIpcListener + OsPrincipal fingerprint
        |
        v
AllowlistedPrincipalResolver  -- session grant only
        |
        v
Local API CommandPrincipal    -- authenticated principal ID + profile constraints
        |
        v
ConfiguredAuthorityPrincipalResolver
        |                 |                 |
        v                 v                 v
Task owner mapping   Policy owner mapping  Verdict owner mapping
        |                 |                 |
        +------ respective Authority-owned reference guards ------+
                                      |
                                      v
                         durable owner transaction / outbox
```

## Verification evidence

The agentosd unit suite covers:

- empty and malformed peer allowlists fail during construction;
- a task-only owner mapping does not grant Policy or Verdict authority;
- an empty cross-authority mapping is rejected;
- the existing real Windows Named Pipe C5 suite continues to pass in serial
  mode.

The normal binary now loads the typed composition through
`EGOPULSE_USER_CONFIG` (default `egopulse-data/agentos-config.json`). The
user-owned JSON contains paths, epochs, identity mappings, reviewed references
and workflow data; each SQLCipher/API key is named by an environment variable
and is never read from the JSON file. No test fixture Allow implementation is
reused; the three guards remain separate from identity mapping and from the
client surfaces.

The remaining Phase 2-02 obligation is the reviewed Sego/checker resolver
composition. `DenyVerificationReferences` still keeps Verification external
requests held while allowing its own store and projection boundary to be
composed; merely opening Artifact Authority must not turn that deny boundary
into an implicit Sego authorization.

The bootstrap now accepts an optional `verification.criteria` section. When it
is present, the composition root constructs `ArtifactBackedReferenceResolver`
over the same shared `ArtifactAuthorityReferenceSource` owner handle and
binds the configured criterion policy snapshots to Verification. When it is
absent, the deny resolver remains active. This section authorizes neither a
checker profile nor a Sego process: checker profiles still require an explicit
Verification Authority attestation command whose evidence artifacts pass the
same owner-backed resolver.

The application boundary now provides `SystemCheckerProfileAttestation`. It
fixes the principal to the local Verification Authority bootstrap identity,
derives a stable idempotency key from the profile identity and digest, and
accepts only a committed or replayed Authority result. A caller cannot inject
a Task, Harness, Model, or client principal into this path. The helper is the
attestation primitive; production configuration still has to explicitly supply
the reviewed profile candidate and the next vertical must wire this primitive
into its startup/recovery policy before declaring checker execution available.

Verification Authority also exposes decoded request and run snapshots as
read-only owner APIs. The execution coordinator uses these snapshots to resume
from the last durable revision after a crash; it does not reconstruct
revisions from a Task payload or a client-side cache.

The next application boundary is `GovernedVerificationExecutionCoordinator`.
It is intentionally limited to one reviewed criterion: it reads the durable
request/run snapshots, invokes the existing governed Sego supervisor and mapper,
records the criterion through the checker principal, and completes the artifact
through the Verification Authority principal. A process-output failure is still
recorded as an explicit non-passing result; a completed run is replayed from
the immutable artifact instead of being executed again.

`SystemTaskVerificationWriteBack` is the corresponding Task-side owner
boundary. Before issuing `RecordTaskVerification`, it reads the completed
artifact through Verification Authority, checks the artifact lineage against
the exact pending Task revision/work revision, then submits a deterministic
write using the fixed `SegoVerification` system principal. It does not accept
an API/client principal or an artifact ID whose lineage was not proven.
