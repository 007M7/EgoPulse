# EgoPulse

> A local-first, Founder-controlled Personal Agent OS that places a deterministic governance kernel between the user and replaceable AI Harnesses.

EgoPulse is not another model wrapper or an unconstrained tool-running Agent. It is a local control system for personal Agents: the user owns the configuration, durable state, Memory lifecycle, approvals, execution evidence and release decisions, while model providers and Harnesses remain replaceable execution resources.

The first release slice is an unsigned Windows x64 engineering preview containing the CLI, TUI and `agentosd` daemon. Production admission is per Provider/Harness route: GPT through the Codex app-server Harness, and DeepSeek through the DSH, OpenCode or Codex app-server Harness, with at most one production profile configured at a time. Kimi, GLM, Desktop, and semantic/vector RAG remain explicitly gated.

This checkout carries the phase-one work-loop repairs plus the September and October 2026 verification work. **No Windows candidate has been built from this revision yet**: the current package entry is the local candidate whose exact commit and clean local CI evidence are recorded in its own `BUILD-METADATA.json`, and the newest built candidate predates this checkout. All release records so far are historical evidence — the published `v0.1.0-early-access.1` archive (`5c8a1e8`) and the September candidates do not contain the repairs described below.

- [Windows early-access guide](WINDOWS-EARLY-ACCESS.md)
- [Implementation architecture](ARCHITECTURE.md)
- [September 2026 release evidence (historical)](docs/release/windows-candidate-20260905.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Why EgoPulse exists

Most Agent products optimize the model-to-tool loop: give a model more tools, more context and more opportunities to act. That is useful, but it does not by itself answer the ownership questions that matter for a personal Agent:

- Who owns the durable facts about the user?
- Who may turn model output into accepted Memory?
- Which Provider, Harness and exact model executed a task?
- What was authorized, changed, verified and returned?
- Can an interrupted task be recovered without silently changing its execution route?
- Can the user replace a Provider without replacing the operating model around their Agent?

EgoPulse addresses those questions at the system boundary. Models propose and execute; deterministic Authorities decide what becomes durable truth. The project aims to make personal Agents governable, inspectable and replaceable without pretending that orchestration code creates human-like autonomy or that a local client hides requests from the selected model provider.

## Product principles

1. **The user is the owner.** “Founder” is the EgoPulse term for the authorized local owner who confirms work, governs Memory and issues final verdicts.
2. **Model output is never authority state.** An Agent, model, Harness or Python Worker may submit candidates and evidence, but it cannot directly write Task, Memory, Policy, Verdict or Release truth.
3. **Provider, Harness and model are separate identities.** A visible model catalog entry is not an admitted execution route.
4. **A confirmed work route is immutable.** Changing the future default cannot rewrite an active or recoverable task.
5. **Every surface uses one kernel.** CLI, TUI and Desktop consume the same Rust client operations and daemon-owned facts; a UI does not create a second control plane.
6. **Failures are explicit and recoverable.** Unknown routes, stale revisions, missing evidence and ambiguous terminal output fail closed.
7. **Research produces candidates, not silent upgrades.** New retrieval algorithms, Harnesses and self-improvement experiments must pass evidence gates before activation.

## Current capability status

| Area | Current status | What that means |
| --- | --- | --- |
| Windows CLI | Early-access package | Scriptable work, Task, approval, evidence, Memory, Context and governed-state operations |
| Windows TUI | Early-access package | Interactive natural-language Work Start, live Task/content views, approvals and governed state over the same kernel |
| Desktop | Source candidate only | Tauri 2 + React + TypeScript is attached to the shared kernel, but native GUI acceptance and packaging are not closed |
| GPT through Codex | Production-admitted route | Real Codex app-server adapter, exact profile binding, process supervision and governed return path |
| DeepSeek routes | Production-admitted routes | DSH, OpenCode and Codex app-server are admissible for DeepSeek; a recorded isolated run reached Task completion through DeepSeek/OpenCode |
| Kimi | Held candidate | Candidate ACP lifecycle exists; it is not selectable for production work |
| GLM | Held candidate | Representable in configuration; it is not authenticated or production-admitted |
| Memory governance | Implemented | SQLCipher Authority, candidate/accepted/revoked lifecycle, audit, idempotency and scoped snapshots |
| Lexical Memory retrieval | Admitted baseline | Read-only supervised Python Worker returns references from accepted Memory snapshots |
| Semantic/vector RAG | Evaluation candidate | Exact-vector and RRF experiment plumbing exists, but the accepted release path remains lexical |
| Windows signing | Not available | The current archive is unsigned and may trigger SmartScreen |

The distinction is intentional: **implemented**, **composed**, **authenticated**, **admitted** and **released** are different claims and require different evidence.

## How EgoPulse works

```text
User / Founder
      |
      +----------------------+----------------------+
      |                      |                      |
     CLI                    TUI              Desktop candidate
      +----------------------+----------------------+
                             |
                    shared Rust Client Kernel
                             |
             authenticated local Named Pipe / UDS
                             |
                     local API + agentosd
                             |
        +--------------------+--------------------+
        |                    |                    |
 deterministic          collaboration        evidence path
 Authorities             and recovery       Artifact evidence ->
 Task / Policy /         leases, dispatch,   Verification ->
 Memory / Verdict        cancellation        Founder Verdict
        |                    |                    |
        +--------------------+--------------------+
                             |
              replaceable Harness / Worker adapters
         Codex | DSH | OpenCode | Kimi candidate
                             |
                       selected AI Provider
```

The normal governed work path is:

```text
natural-language intent
  -> bounded source and accepted-Memory context
  -> exact Provider/Harness/model route resolution
  -> user-visible preview and explicit confirmation
  -> Task activation and supervised Harness dispatch
  -> source-labelled streamed content
  -> immutable Artifact/evidence intake
  -> deterministic scope/tests checks and model-assisted review
  -> task-bound Verification
  -> Founder verdict
  -> projected result, audit trail and recovery state
```

The Harness never talks directly to an Authority database. `agentosd` is the deployment host, while each Authority remains the single writer for its own facts.

## Memory and RAG governance

EgoPulse treats Memory as governed user data rather than an append-only model transcript.

```text
Agent / user proposal
        |
        v
candidate Memory  -- Founder accept -->  accepted Memory
        |                                      |
        |                                      v
        |                         scoped immutable snapshot
        |                                      |
        |                                      v
        |                         read-only retrieval Worker
        |                                      |
        +--------- revoke with evidence <------+
                               |
                               v
                         revoked terminal state
```

- Rust owns the encrypted Memory Authority, revisions, idempotency, scope checks and audit events.
- Models and Harnesses can only propose candidates.
- The Founder/governance path accepts or revokes a record with evidence.
- Python receives only a bounded snapshot of already accepted records and returns ranked references, not authority writes.
- Lexical retrieval is the release baseline. Semantic, vector and hybrid algorithms are replaceable experiments with evaluation and rollback requirements.

This boundary lets the retrieval technology evolve without allowing a fast-moving framework or model to redefine what the user has accepted as Memory.

## Provider, Harness and model governance

EgoPulse does not equate a Provider with a Harness:

- **Provider** identifies the model service.
- **Harness** owns the provider-facing execution protocol and tool loop.
- **Model** is the exact model identifier sent to that Harness.
- **Capability route** seals the Provider, Harness, model, profile digest and composition generation used by one work item.

`work capabilities` shows admitted choices and held diagnostics separately. A user may change the default proposed for future work, but confirmation copies one exact route into immutable Context and Task facts. There is no silent fallback to another model.

The repository contains Codex, DSH, Kimi and OpenCode adapter boundaries. The current package admits GPT through Codex app-server and DeepSeek through DSH, OpenCode or Codex app-server; admission is checked per route against the composition allowlist and at most one production profile may be configured at a time. Cross-Harness composition tests prove that the architecture can represent the same model identity through different drivers; they do not claim that every Provider is authenticated or safe to release.

## Windows x64 quick start

### 1. Prerequisites

Binary-package users need:

- Windows x64;
- the Codex CLI version required by the packaged capability profile, currently `0.148.0-alpha.15`;
- an authenticated Codex account that can use the configured exact model;
- CPython `3.14.x`;
- [uv](https://docs.astral.sh/uv/);
- PowerShell.

Check the environment before installation:

```powershell
codex --version
codex login status
python --version
uv --version
```

EgoPulse does not place Provider credentials in the repository or ordinary JSON configuration. A route may use a Harness-owned delegated login or an environment-variable secret reference, depending on the Provider profile.

### 2. Download and verify

Use the local Windows candidate supplied with this revision, including its ZIP and adjacent `.sha256` file; its exact source commit is recorded in `BUILD-METADATA.json` and must match this checkout. Until such a candidate exists for the current source, treat every earlier package — including [`v0.1.0-early-access.1`](https://github.com/007M7/EgoPulse/releases/tag/v0.1.0-early-access.1) — as historical release evidence, not as the package for the workflow below.

Verify the downloaded archive before extracting it:

```powershell
Get-FileHash .\egopulse-*.zip -Algorithm SHA256
Get-Content .\egopulse-*.zip.sha256
```

The archive is unsigned. A SmartScreen warning is therefore possible; a hash mismatch is a reason to stop, not bypass the warning.

### 3. Install

Extract to a short path such as `C:\EgoPulse`, then run the installer without launching the daemon yet:

```powershell
cd C:\EgoPulse
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-egopulse.ps1 `
  -RepositoryRoot 'D:\work\project' `
  -AcceptanceContractPath 'D:\work\project-acceptance.json'
```

The installer creates a user-owned data root under `%LOCALAPPDATA%\EgoPulse`, generates local Authority/session keys as user environment variables, installs the locked Memory Worker, migrates the configuration to the current schema, validates it and checks that the production Harness executable exists.

Keep the reviewed acceptance contract outside the execution checkout. Follow [repository setup](config/README.md#governed-repository-setup) and require `verification_preflight=repository_configured` before starting repository work. Omitting both repository parameters installs the base product only and reports `verification_preflight=not_configured`; it does not configure the real repository checkers.

### 4. Choose the work directory

A fresh installation creates `%LOCALAPPDATA%\EgoPulse\workspaces\default`, allows `scope:founder`, and uses `governed_repository_change` in the TUI. Place an actual context source such as the project's `README.md` in this directory for `--context-ref default/README.md`. Repository execution uses a detached worktree of the repository selected during setup; accepting a result preserves its governed artifacts and does not merge them into the source repository.

Existing installations retain their configuration. If upgrading an older preview, also check `task_guard.allowed_target_scope_refs` includes `scope:founder`; use `governed_repository_change` as the Work Type. Do not replace an existing configuration or its Authority keys to recover an unfinished task.

Before upgrading an existing data root, follow [upgrade and rollback](WINDOWS-EARLY-ACCESS.md#upgrade-and-rollback). A configuration backup is not an Authority database backup.

### 5. Start the governed local daemon

Open a new PowerShell window so the persisted environment variables are loaded:

```powershell
cd C:\EgoPulse
.\bin\agentosd.exe --check-config
.\bin\agentosd.exe
```

Keep that window running. In a second PowerShell window:

```powershell
cd C:\EgoPulse
.\bin\egopulse.exe status
.\bin\egopulse.exe work capabilities
```

Only a capability marked `admitted` and carrying a public choice ID can start governed work.

### 6. Start a natural-language work request

The following example assumes the default project directory contains `README.md`:

```powershell
.\bin\egopulse.exe work start `
  --intent "Inspect this repository and propose one safe documentation improvement" `
  --scope "scope:founder" `
  --work-type "governed_repository_change" `
  --context-ref "default/README.md" `
  --confirm
```

`--context-ref` is resolved beneath `codex.workspace_root`, so include the project directory name. Memory retrieval is enabled by default; add `--no-memory` when the task must not consume accepted Memory. With `--no-memory`, supply at least one real context source. In a non-interactive shell, `--confirm` is required.

The command returns a Task ID. Use it to inspect the governed projections and streamed Harness output:

```powershell
.\bin\egopulse.exe task watch --frames 1
.\bin\egopulse.exe content watch <TASK_ID>
.\bin\egopulse.exe task review <TASK_ID>
.\bin\egopulse.exe approval list
```

Use `Ctrl+C` to stop an unbounded content watch. Stopping the viewer does not imply that the Task was cancelled.

## TUI workflow

Start the terminal interface from a second window while `agentosd` is running:

```powershell
.\bin\egopulse-tui.exe
```

Dashboard shortcuts:

| Key | Action |
| --- | --- |
| `n` | Open natural-language Work Start |
| `w` | Open Task Watch |
| `a` | Open the approval queue |
| `g` | Inspect governed state |
| `c` | Open the command palette |
| `r` | Refresh the current projection |
| `Tab` | Change panel or form field |
| `q` | Quit |

The TUI is not a separate Agent runtime. It submits the same typed client operations as the CLI and displays daemon-owned projections. Task state, approvals and completion are never inferred from terminal text.

## Useful CLI operations

Inspect commands and machine-readable output with:

```powershell
.\bin\egopulse.exe --help
.\bin\egopulse.exe work --help
.\bin\egopulse.exe task --help
.\bin\egopulse.exe approval --help
.\bin\egopulse.exe memory --help
```

List or change the default capability for future work:

```powershell
.\bin\egopulse.exe work capabilities --json
.\bin\egopulse.exe work set-default <CHOICE_ID> <EXPECTED_REVISION>
```

Changing the default does not change active or recoverable work.

Retrieve accepted Memory references:

```powershell
.\bin\egopulse.exe memory retrieve `
  --query "project decision" `
  --scope "scope:founder" `
  --max-results 8 `
  --json
```

Memory mutation is intentionally explicit:

```powershell
.\bin\egopulse.exe memory candidate --help
.\bin\egopulse.exe memory accept --help
.\bin\egopulse.exe memory revoke --help
```

A candidate is non-authoritative until accepted. Revocation is a governed terminal transition with evidence and optimistic revision checks.

## Security and privacy boundary

- Authority stores are local SQLCipher databases with independent keys and single-writer ownership.
- Windows clients connect over owner-scoped Named Pipes; Unix support uses Unix Domain Sockets.
- The local session service binds requests to the OS account and policy-resolved logical principal. An SID/UID alone never implies Founder authority.
- Harness and Worker processes are supervised with bounded execution and fail-closed executable checks. On Windows, child process trees are assigned to a Job Object so cancellation and daemon loss terminate descendants.
- Provider API-key values are not serialized into configuration projections, logs or evidence.
- Prompt, Memory and Artifact bodies are not collected by EgoPulse cloud telemetry; the first release contains no cloud telemetry service.

Local-first does **not** mean that model requests stay offline. The selected external Provider receives the prompt and context sent through its Harness and applies its own account, retention and privacy policies. Review those policies before including sensitive data.

See [SECURITY.md](SECURITY.md) for reporting and unsigned-package guidance.

## Technology boundaries

| Runtime | Responsibility | Architectural cost |
| --- | --- | --- |
| Rust 1.98 | Authorities, local API/IPC, collaboration, process supervision, CLI/TUI and Tauri bridge | Longer compile times and explicit cross-process boundaries for scientific Python |
| TypeScript 7 | Desktop UI, generated client, Agent SDK and bounded native Harness | Framework churn must remain behind adapters; TypeScript never owns authority truth |
| CPython 3.14 + uv | Parsing, retrieval, embedding, reranking and evaluation Workers | Serialization, supervision and cancellation cross a process boundary |
| Protobuf + Buf | Internal commands, events and local APIs | Generated-code and compatibility maintenance |
| JSON Schema 2020-12 | Inspectable Artifact and tool payloads | A second schema system with separate validation rules |
| SQLCipher | Encrypted local Authority persistence | Native build prerequisites and explicit migration/backup responsibility |
| Tauri 2 + React | Later Desktop presentation over the Rust kernel | Platform-specific packaging and WebView behavior; not an authority dependency |

Frameworks such as LangGraph.js are permitted only inside replaceable Harness packages. They cannot define global Run state, Memory truth, policy or release decisions.

## Repository layout

```text
apps/
  agentosd/                 Rust deployment host and production composition root
  cli/                      Scriptable Rust client
  tui/                      Interactive Rust terminal surface
  desktop/                  Tauri 2 + React + TypeScript candidate surface

crates/
  domain-contracts/         Framework-neutral domain and profile types
  cognition-runtime/        Task, Context and Memory Authority implementations
  local-ide-control/        Collaboration control and governed workflow execution
  local-api/                Local read/command API gateway
  client-kernel/            Shared transport, profile and session semantics
  client-operations/        Surface-neutral user operations
  local-ipc-platform/       Named Pipe/UDS identity and transport boundary
  local-read-model/         Governed projections
  process-supervision/      Child-process lifecycle and framing
  harness-adapter/          Provider-neutral Harness boundary
  codex-adapter/            Production Codex app-server driver
  dsh-adapter/              DeepSeek-admitted DSH driver
  kimi-adapter/             Kimi candidate driver
  opencode-adapter/         DeepSeek-admitted OpenCode driver; GLM held
  artifact-authority/       Immutable Artifact metadata and blob receipts
  verification-authority/   Verification facts and artifacts
  founder-verdict-authority/ Founder verdict lifecycle
  policy-decision-authority/ Policy and approval decisions

packages/
  generated-client/         Generated TypeScript contract consumers
  agent-sdk/                AgentOS-native SDK boundary
  native-harness/           Bounded TypeScript/LangGraph.js Harness implementation

workers/
  contract-bindings/        Generated Python contract consumers
  foundation-probe/         Isolated Worker packaging pattern
  memory-rag/               Supervised read-only Memory retrieval and evaluation

contracts/
  proto/                    Protobuf source of truth
  json-schema/              Artifact and tool schemas
  profiles/                 Reviewed authorization/client capability profiles

docs/
  decisions/                Repository-local architecture decision records
  architecture/             Implementation plans and acceptance evidence
  engineering/              Build, CI/CD and repository policies
  release/                  Commit-bound release evidence
```

Historical research, Founder governance records and methodology remain outside this repository. Imports require an explicit migration package with provenance, tests and rollback.

## Build from source

Development prerequisites:

- Rust `1.98.0` through rustup, pinned by `rust-toolchain.toml`;
- Node.js `24.x`;
- pnpm `11.x`;
- CPython `3.14.x`;
- uv;
- Visual C++ build tools and Perl for the vendored SQLCipher/OpenSSL build on Windows.

Install locked JavaScript dependencies and run the fast repository gate:

```powershell
pnpm install --frozen-lockfile
pnpm run check
```

Build and test Rust through the repository wrapper:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-rust.ps1
```

Run the complete local CI reproduction when closing a development or release-candidate boundary:

```powershell
pnpm run ci:local
```

Generate a commit-bound unsigned Windows candidate only when a release artifact is required:

```powershell
pnpm run cd:local
```

If full CI already passed for the same clean `HEAD`, avoid duplicate work with:

```powershell
pnpm run cd:local:skip-ci
```

Contract sources live only under `contracts/`. After an approved contract change:

```powershell
pnpm run generate:contracts
pnpm run check
```

Do not edit generated Rust, TypeScript or Python bindings as the source of truth.

## Quality and release evidence

The published Windows candidate was bound to commit `5c8a1e8` and tag `v0.1.0-early-access.1`; September 2026 candidates were built at later commits, and this checkout has no candidate yet. Their historical local gate included:

- contract, repository-boundary and TypeScript checks;
- the complete Rust workspace;
- 38 serial real-process daemon fixture tests;
- 133 serial daemon library tests;
- all three Python Worker gates;
- hermetic installer and locked Memory Worker checks;
- CLI, TUI and daemon startup probes;
- archive and per-file SHA-256 verification for 55 packaged files.

Phase-one repair evidence includes two real repository tasks, CLI Accept/Rework, 24 TUI checkpoints including Reject, cancellation and same-database recovery. A candidate's exact commit and clean local CI evidence are packaged under its `BUILD-METADATA.json` and `manifests/local-ci-evidence.json`; the current source revision must be rebuilt locally to obtain them. Candidates are for local early-access testing, not signed production releases or admission of held Provider routes.

The repository retains GitHub Actions CI/CD definitions, but the current operational gate is the recorded local Windows CI/CD path while Actions capacity is unavailable. See [local CI/CD policy](docs/engineering/local-ci-cd.md).

## Roadmap

Near-term work follows the accepted six-stage delivery baseline:

1. remove the remaining first-run default mismatches and refresh the Windows CLI/TUI package;
2. independently authenticate and admit additional Provider/Harness routes without weakening exact-route governance;
3. continue Memory/RAG production evaluation while retaining deterministic lexical rollback;
4. complete Desktop-native automation and package it as another surface over the same kernel;
5. add signed Windows distribution when a code-signing certificate is available;
6. evolve research and RSI experiments through candidate, evaluation, Founder activation and rollback gates.

Cloud telemetry, enterprise identity and server-scale multi-tenant operation are not phase-one goals.

See [the six-stage delivery baseline](docs/architecture/six-stage-delivery-baseline-20260827.md) for evidence-based stage definitions.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) before changing the repository. The required sequence is:

1. identify the user outcome and non-goals;
2. confirm the owning Authority/module and dependency direction;
3. freeze affected contract, permission, failure and recovery semantics;
4. implement the smallest complete vertical change;
5. run risk-proportional checks;
6. record compatibility, migration and rollback impact.

Install the tracked fast pre-push hook once per clone or worktree:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install-git-hooks.ps1
```

Never commit credentials, runtime databases, model weights, personal data or private Founder-governance material.

## Further reading

- [Architecture and dependency direction](ARCHITECTURE.md)
- [Technology baseline ADR](docs/decisions/0002-foundation-technology-baseline.md)
- [Codex adapter ADR](docs/decisions/0003-codex-adapter-runtime.md)
- [Provider/model route selection ADR](docs/decisions/0004-provider-model-runtime-selection.md)
- [Windows early-access operations](WINDOWS-EARLY-ACCESS.md)
- [Local configuration](config/README.md)
- [Local CI/CD and repository classification](docs/engineering/local-ci-cd.md)
- [Windows candidate evidence](docs/release/windows-candidate-20260905.md)
