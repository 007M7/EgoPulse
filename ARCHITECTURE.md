# EgoPulse implementation architecture

- Status: active foundation boundary
- Date: 2026-08-22
- Decision owner: Founder

## Source and responsibility

The historical `founder-agent-os` workspace remains the source for research, governance history and frozen architecture decisions. EgoPulse is the implementation repository for new product code, machine contracts, migrations and release artifacts.

No runtime code is copied automatically from the historical workspace. Reuse requires an explicit migration work package with provenance, tests and rollback.

## Dependency direction

```text
Desktop / CLI / TUI
        |
        v
local-api client boundary
        |
        v
Named Pipe / UDS (not implemented in the foundation scaffold)
        |
        v
agentosd deployment host
  +-- cognition-runtime authorities
  +-- local-ide collaboration control
  +-- artifact authority + content-addressed blob data plane
  +-- process supervision
        |
        v
Harness / Worker / Sego adapters (not implemented yet)
```

`agentosd` is a deployment host, not a shared fact owner. Authority and control modules must retain separate APIs, single-writer storage ownership and audit streams.

Artifact metadata and content-addressed bytes form an independent fact domain. The Rust
`artifact-authority` module owns metadata, immutable sets and technical return receipts; the blob
data plane stores bytes by verified digest. Harnesses and collectors may submit candidates, but
neither receives the Authority database handle nor may a terminal Harness event decide Artifact,
verification or Task completion.

## Language boundaries

| Runtime | Owns | Must not own |
|---|---|---|
| Rust | deterministic authorities, collaboration control, process supervision, local API, CLI/TUI and Tauri bridge | experimental model algorithms |
| TypeScript | Desktop UI, generated client, Agent SDK and bounded native Harness | global Run/DAG authority or Memory truth |
| Python | parsing, embedding, reranking, evaluation and experiments | Task/Memory/Policy/Verdict/Release facts |

## Contract boundaries

- Internal commands/events/API: Protobuf proto3, checked by Buf.
- Artifact and tool boundaries: JSON Schema 2020-12.
- Local client transport: Named Pipe on Windows and UDS on Unix; not implemented in this scaffold.
- Supervised Worker/Harness transport: framed stdio or an official native protocol adapter; not implemented in this scaffold.

## Repository rules

1. UI, Harnesses and Workers never connect to authority databases.
2. Framework types do not enter `domain-contracts`.
3. LangGraph.js remains inside `packages/native-harness`.
4. Python projects remain isolated and cannot become an authority backend.
5. `contracts/` is the only machine-contract source; generated output is never edited as truth.
6. A vertical feature starts only after the Foundation Gate passes.
