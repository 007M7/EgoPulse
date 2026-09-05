# U-03a shared governed task-result review evidence

- Date: 2026-09-03
- Scope: shared Rust read operation and CLI result-review surface
- Status: locally verified
- Parent flow: U-03 Result Review

## Outcome

U-03a adds one read-only task-result review operation to the shared Client
Kernel and exposes it as `egopulse task review <task_id> --json`. The caller
supplies only a Task identity. The operation first reads the bounded
`TaskView`, derives the ArtifactSet identity and projection position from that
trusted response, and only then reads the matching `EvidenceGraphView` through
the same authenticated `ClientAttachment`.

The operation does not accept caller-supplied ArtifactSet, Verification or
Founder-Verdict identities. It does not call a command gateway, read artifact
bytes, issue or consume a Verdict, or change Task state. No Proto, Local API,
Authority, schema, Provider, Memory, TUI or Desktop contract changes are part
of this slice.

## Staged authorization and consistency

- `local.task.read` is checked before `GetTaskView` dispatch.
- If the Task has no projected ArtifactSet, the operation returns the explicit
  partial result and performs no Evidence permission check or Evidence RPC.
- If an ArtifactSet is present, `local.evidence.read` is checked before
  `GetEvidenceGraph` dispatch.
- The second request's Task ID, ArtifactSet ID and minimum projection position
  are derived exclusively from the first response.
- Each response must be `READY`, non-stale and carry a complete projection
  position and source vector.
- Task, ArtifactSet, Verification, Founder Verdict/State and Evidence facts
  are checked for exact identity, binding, source-tuple and lineage coherence.
- Artifact, Claim and Evidence membership must be closed exactly; duplicate,
  missing, extra and dangling references fail closed.
- The two projections must use the same epoch. An Evidence graph sequence may
  legitimately be older than the Task projection when the bound facts and
  source tuple are unchanged; sequence equality is not used as a false
  consistency oracle.

## CLI information and privacy boundary

The JSON renderer uses explicit field-by-field allowlists. It presents the
safe governance metadata required to review:

- Task status and projection metadata;
- ArtifactSet identity, lifecycle, lineage and canonical manifest;
- Artifact, Claim and Evidence classification, integrity, content-address,
  relationship, limitation and lifecycle metadata;
- Verification binding, conclusion, coverage, criterion results,
  discrepancies, unverified items and safe provenance receipt identities;
- Founder Verdict scope, observed conclusion, risk acceptance, rework
  directive and Verdict state;
- redaction paths and safe reason codes from both projections.

Missing ArtifactSet, graph, Verification or Verdict stages remain JSON `null`
and render as `none`; they are never reclassified as passed, rejected or
complete. An active Task remains active even when governance evidence or a
Verdict is present.

The renderer deliberately excludes Founder and producer/verifier principal
identities, authority and confirmation proofs, workspace paths,
`raw_source_ref`, native execution/routing references, Provider or Harness raw
content, Claim statement bytes and Artifact bytes. Content addresses and
receipt Artifact identities are metadata references, not payload disclosure.

The text renderer summarizes Artifact and quarantine counts, Claim/Evidence
relationships, Verification conclusion and coverage, discrepancy and
unverified counts, and Founder Verdict decision/state/terminal reason. It is a
human-readable view over the same projected facts rather than a second source
of truth.

## Automated evidence

Implementation verification completed with:

```text
cargo test -p egopulse-client-operations
  35 passed; 0 failed

cargo test -p egopulse-cli
  19 passed; 0 failed

cargo clippy -p egopulse-client-operations -p egopulse-cli --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The independent stable-diff review repeated the focused gates:

```text
cargo test -p egopulse-client-operations task_result_review --lib -- --test-threads=1
  5 passed; 0 failed; 30 filtered

cargo test -p egopulse-cli --bin egopulse task_review -- --test-threads=1
  3 passed; 0 failed; 16 filtered

scoped Clippy, Rustfmt and diff checks
  passed
```

Independent architecture/privacy review and independent implementation/test
review both returned `GO` with P0=0, P1=0 and P2=0. The Windows linker emitted
the known non-blocking missing `ossl_static.pdb` LNK4099 debug-symbol warning.

## Evidence boundary

U-03a proves the shared production read seam, typed failure and integrity
semantics, safe CLI rendering and absence of a write entry in this operation.
It does not yet prove a real daemon process, real IPC CLI invocation, TUI
interaction, database snapshots before and after the read, same-root restart,
or packaged-terminal behavior. Those process and persistence claims belong to
U-03c and must not be inferred from this component slice.
