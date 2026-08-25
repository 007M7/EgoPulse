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

The normal `agentosd` entrypoint remains fail-closed until all three decisions,
the encrypted Authority stores and the explicit Codex workflow configuration
are assembled as one reviewed bootstrap. This is deliberate: a daemon that
authenticates a user but silently uses test Allow guards would be a governance
regression, not a usable production mode.

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

The remaining bootstrap work is to provide reviewed configuration and the
Founder Verdict reference guard, then wire the explicit Codex composition into
the normal binary. No test fixture Allow implementation is reused for that
step; the Policy and Task guards are not substitutes for the still-missing
Verdict evidence guard.
