# G4-05 Artifact Authority implementation profile

- Status: implementation verified; Gate 4 governance evidence pending
- Date: 2026-08-24
- Frozen inputs: C-04 Artifact/Claim/Evidence/ReturnHandoff, C-08 Persistence/Recovery, D-02
- Scope: immutable Artifact, Claim, Evidence, ArtifactSet and technical ReturnReceipt intake

## Stable boundary

`artifact-authority` is an independent Rust owner module. It owns one SQLCipher metadata store and
the rules that make metadata eligible to reference a content-addressed blob. `agentosd` may host it,
but Harness, Collaboration, Sego, UI and Python workers receive commands and receipts only.

Consumers that need evidence resolution use the read-only `read_artifact`,
`read_claim`, `read_evidence` and `read_artifact_set` methods. These methods
decode immutable owner snapshots and do not expose the SQLCipher store, its
connection or any write capability. Verification can therefore bind Sego
inputs to sealed Artifact Authority facts without importing the private store
or allowing a checker to repair evidence.

```text
Harness / collector / supervised runner
             |
             | candidate bytes + provider-neutral provenance
             v
content-addressed blob data plane -- verified address --> Artifact Authority SQLCipher store
                                                        |
                                                        +--> ReturnReceipt outbox
```

The separate crate enforces fact ownership and avoids turning `cognition-runtime` into a shared
database or catch-all dependency. This packaging is an implementation choice; the difficult-to-
change architecture is the independent owner API, store, audit stream and recovery boundary.

## Blob-before-metadata

V-01 uses SHA-256 only. Bytes are written to a temporary file, flushed, atomically published under
their digest and re-read for digest/length verification. Only then may a metadata command create an
Artifact, Claim statement, Evidence coverage descriptor, canonical ArtifactSet manifest or return
handoff payload reference. A durable blob without metadata is an orphan and not an Artifact fact.
Metadata that references a missing or corrupt blob fails closed.

The cost is orphan collection, two data planes and explicit integrity recovery. It prevents a
committed Artifact from pointing at bytes that were merely queued in memory or identified by a
mutable workspace path.

## Truth and authority limits

- Claim lifecycle has no passed/accepted/completed state.
- Evidence integrity proves byte identity, not epistemic sufficiency.
- A producer cannot mark its own claim evidence as independent.
- A sealed ArtifactSet is immutable and binds one Task/work revision and Attempt fence.
- ReturnReceipt means technical evidence intake only; verification and Task completion flags remain
  false.
- Harness terminal observations do not seal Artifact metadata or advance Collaboration by
  themselves.

## G4-05 exit evidence

- verified digest and length before metadata visibility;
- immutable provenance and same-lineage/fence member checks;
- duplicate replay, idempotency conflict and stale CAS with zero extra writes;
- sealed-set canonical manifest validation;
- ReturnHandoff + technical ReturnReceipt + outbox in one owner transaction;
- orphan-blob reuse and process-abort replay after committed return;
- encrypted metadata-store reopen/integrity and private-store dependency boundary checks.

## Explicitly deferred production obligations

G4-05 does not claim that the blob data plane is encrypted at rest. The current implementation
encrypts authority metadata with SQLCipher and protects blob identity through digest verification;
the production key/ACL and blob-at-rest encryption profile remains a G4-08 security-composition
obligation. Startup-wide live-blob reconciliation, quarantine/tombstone workflows and physical
power-loss durability qualification remain G4-10 recovery work. These deferred obligations do not
weaken the frozen single-writer or blob-before-metadata boundaries.
