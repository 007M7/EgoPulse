# Phase 2.35 — Codex to Memory candidate E2E evidence

Status: locally verified on Windows x64; candidate-only Memory write

## What this closes

The authenticated Codex app-server runtime can produce a terminal output
candidate, and an explicitly invoked application policy can submit that
candidate through a fixed `Harness` producer handle into the Rust Memory
Authority. Founder acceptance remains a separate governance operation.

```text
real Codex app-server
        |
        v
Governed Codex driver
        |
        v
TerminalOutputCandidate
        |
        | explicit application/test policy only
        v
fixed harness:codex producer handle
        |
        v
Rust Memory Authority -> Candidate
        |
        v
Founder acceptance -> Accepted snapshot
```

The Codex driver does not infer a Memory scope, select a Memory principal,
choose a memory ID, or call accept/revoke. Ordinary terminal output therefore
does not become a Memory record. The explicit conversion in the E2E is the
policy seam that a later product workflow must replace with a reviewed
candidate-proposal interaction; it is not an automatic transcript importer.

## Real evidence

The test used the locally installed and authenticated Codex app-server binary
for version `0.148.0-alpha.15`, with the executable supplied through the
existing `EGOPULSE_CODEX_EXECUTABLE` test configuration. It verified:

- native `initialize` probe and exact protocol fingerprint;
- real `thread/start` and dispatch acceptance;
- real terminal lifecycle and terminal output candidate extraction;
- fixed `harness:codex` binding to principal `harness:codex` and
  `scope:founder`;
- candidate receipt in Memory Authority;
- separate Founder acceptance and final `Accepted` record;
- source provenance retained as the Codex native completion reference.

Focused command:

```powershell
$env:EGOPULSE_CODEX_EXECUTABLE = 'C:\Users\Administrator\AppData\Local\OpenAI\Codex\bin\f71e347eb70b3d24\codex.exe'
cargo test -p egopulse-agentosd --test codex_memory_candidate_e2e -- --nocapture
```

Result on 2026-08-27:

```text
running 1 test
test real_codex_candidate_can_only_enter_memory_as_explicit_candidate ... ok
test result: ok. 1 passed; 0 failed
```

## Boundary and non-goals

- This does not expose candidate submission through the public protobuf Local
  API.
- This does not give Codex, a model, or a Harness acceptance/revocation
  authority.
- This does not promote Kimi or DSH; both remain candidate-only.
- This does not promote semantic/vector RAG; lexical retrieval remains the
  release baseline.
- The test uses a temporary encrypted Memory Authority store and is not a
  release-time automatic memory import.
