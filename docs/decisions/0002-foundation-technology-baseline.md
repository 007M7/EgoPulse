# ADR 0002: foundation technology baseline

- Status: accepted for Foundation F0
- Date: 2026-08-22
- Decision owner: Founder

## Decision test

A foundation technology is accepted only when it supports a frozen architecture boundary or a
repository-wide quality attribute. Ecosystem popularity and team familiarity are insufficient.
Frameworks inside replaceable adapters are dependencies, not architectural authorities.

## Rust 1.98 for the deterministic core

**Why:** Authority state transitions, collaboration control, local IPC ownership and process
supervision need one memory-safe, native, strongly typed runtime. Rust gives these modules explicit
ownership, exhaustive enums, predictable deployment and direct Tauri integration without a managed
runtime. Go would simplify build times but weakens type-level state modelling and duplicates the
desktop native bridge; C++ adds memory-safety and dependency-management risk; TypeScript would put
governance truth in the same runtime as replaceable Harness code.

**Cost:** Compile times, a steeper contributor learning curve and more deliberate async/error design.
Scientific Python libraries require process boundaries rather than direct imports. Pinning 1.98
also means toolchain upgrades become explicit maintenance work.

## Tauri 2, React and TypeScript for Desktop

**Why:** Tauri keeps the privileged native boundary in Rust while allowing one TypeScript UI and SDK
ecosystem. The architecture requires that boundary, not React specifically: Vue could satisfy it.
React is the replaceable implementation baseline because its component, testing and desktop-web
integration ecosystem lowers near-term delivery and integration risk; it receives no domain
authority. Electron would provide a more uniform Chromium runtime but duplicates a large privileged
Node and browser runtime and weakens the native boundary.

**Cost:** WebView behavior can vary by operating system, Tauri commands require an explicit bridge,
and native packaging remains platform-specific. React brings rendering/state complexity and gives up
Vue's integrated reactivity and single-file-component ergonomics. Browser-only preview cannot
exercise native commands. React may be replaced without changing Authority contracts.

## Node 24, pnpm 11 and TypeScript 7

**Why:** The workspace needs a reproducible TypeScript toolchain with strict package boundaries and
content-addressed installs. pnpm exposes undeclared dependency use more readily than a flattened npm
tree. Exact major versions make CI and local behavior comparable.

**Cost:** Workspace symlinks reveal tooling bugs on Windows, lifecycle scripts require an explicit
supply-chain allowlist, and TypeScript 7 may expose compatibility issues earlier than a conservative
compiler baseline. Version upgrades must be tested across every package.

## CPython 3.14 workers managed by uv

**Why:** Retrieval, embedding, reranking, evaluation and scientific experiments depend on Python's
specialist ecosystem. Process-isolated workers preserve that advantage without giving Python
ownership of Task, Memory, Policy, Verdict or Release truth. uv supplies a project-local lock and
fast environment reconstruction.

**Cost:** Serialization, supervision, cancellation and backpressure must cross an IPC boundary.
Cross-language debugging is harder, data copies can be expensive, and some scientific dependencies
may lag Python 3.14. A worker cannot silently grow into a second control plane.

## Protobuf with Buf, plus JSON Schema 2020-12

**Why:** Protobuf provides evolvable typed commands, events and local API messages; Buf enforces
structural lint and later compatibility checks. JSON Schema is retained for artifacts and tool
payloads that must remain inspectable and language-neutral. One format does not fit both boundaries.

**Cost:** Two schema systems require separate generation and compatibility tooling. Protobuf is less
human-friendly, JSON Schema does not provide transport semantics, and accidental duplication between
them must be rejected in review.

## LangGraph.js only inside the native Harness adapter

**Why:** It can express model-facing graph execution in the same TypeScript ecosystem as provider
Harnesses while remaining behind `agent-sdk`. The architecture depends on the adapter contract, not
LangGraph's graph or checkpoint types.

**Cost:** Framework churn, dependency weight and semantic mismatch with EgoPulse Authorities are
contained but not eliminated. Replacing it may require rewriting Harness workflows. It cannot own
global run state, Memory truth, policy decisions or release decisions.

## Consequence

Foundation F0 freezes language ownership, package boundaries, contract roots and reproducible
toolchains. It does not freeze internal retrieval algorithms, model providers, vector indexes or
Harness workflow libraries as architecture; those remain replaceable behind the frozen boundaries.
