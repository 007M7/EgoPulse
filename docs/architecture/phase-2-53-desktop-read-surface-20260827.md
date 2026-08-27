# Phase 2-53: Desktop shared-kernel read surface

- Date: 2026-08-27
- Scope: Tauri 2 + React + TypeScript Desktop surface
- Status: first shared-kernel read slice implemented and locally verified

## Boundary

Desktop now uses the same `egopulse-client-operations::attach` path as the
other client surfaces. It opens a session with `ClientSurface::Desktop`, then
reads the bounded `ProjectionSnapshot` through the Local API. The Tauri layer
projects only safe display fields for the frontend:

```text
Tauri command
  -> shared ClientAttachment
  -> authenticated Local API session
  -> read-model projection
  -> Desktop-only display DTO
```

The Desktop process has no database handle, Memory writer, Provider selector,
Harness authority, or alternate session protocol. `foundation_status` reports
the structured architecture and local transport facts; `dashboard_snapshot`
reports projection health, staleness, position, tasks and approval requests.

## User-facing behavior

- browser preview remains explicit and does not pretend to be attached;
- the user selects a validated local daemon instance, defaulting to `default`;
- a missing daemon or rejected projection remains visible as a safe error state;
- stale projections are marked `STALE` rather than presented as current;
- task and approval identifiers remain available for correlation, while no
  secret or provider credential is displayed;
- CLI, TUI and Desktop continue to share the same Rust client kernel and Local
  API contracts.

## Evidence

The following checks passed on Windows x64:

```text
cargo test -p egopulse-desktop                 passed
cargo clippy -p egopulse-desktop --all-targets -- -D warnings  passed
pnpm --filter @egopulse/desktop build           passed
```

The full local CI gate remains the release-level check. This slice is a
read-model completion step; it does not claim Desktop write workflows,
Provider/model selection, signed distribution, or final six-stage closure.
