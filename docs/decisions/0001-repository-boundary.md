# ADR 0001: independent implementation repository

- Status: accepted
- Date: 2026-08-22
- Decision owner: Founder

## Context

Sego product code, Founder-Agent OS governance records and experimental runtime code were colocated or tightly associated, making implementation ownership and governance boundaries difficult to distinguish.

## Decision

Use `007M7/EgoPulse` as a new implementation repository with no inherited Git history. Keep historical research, governance records and existing implementations in their original repositories. Migrate code only through explicit work packages.

## Why this instead of reorganizing the old repository

- A clean repository makes target architecture and dependency direction visible from the first commit.
- It avoids treating legacy directory placement as target ownership.
- Migration can preserve provenance and tests per module instead of copying an undifferentiated tree.

## Cost and what is given up

- Shared history, blame and one-command local access are not preserved automatically.
- CI, releases, issue tracking and contributor rules must be recreated.
- Reusable code needs explicit extraction and may temporarily exist in two repositories during migration.
- Cross-repository contract/version coordination becomes a real operating cost.

## Controls

- Every import records source commit, license/provenance, behavior tests and rollback.
- No old runtime is copied during Foundation F0.
- Frozen architecture concepts may be restated; historical governance machinery is not duplicated.
