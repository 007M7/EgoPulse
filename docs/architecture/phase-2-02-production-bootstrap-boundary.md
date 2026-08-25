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
composition. Until then `DenyVerificationReferences` keeps Verification
external requests held while allowing its own store and projection boundary to
be composed.
