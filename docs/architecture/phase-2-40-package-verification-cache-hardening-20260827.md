# Phase 2-40: Windows package verification cache hardening

- Status: locally verified; candidate regenerated
- Evidence date: 2026-08-27
- Decision owner: Founder

## Finding

The first verification attempt for the `4dddcdf` candidate failed while
installing the packaged Memory Worker because `uv` used the default user cache
at `C:\Users\Administrator\AppData\Local\uv\cache`, which was not writable
in the verification environment. The executable probes and archive SHA-256
had already passed. An explicit writable cache made the same candidate pass,
showing that this was an environment-permission failure rather than a package
or dependency failure.

## Change

`setup-memory-worker.ps1` now accepts `-UvCacheDir` and defaults to
`<package>/.cache/uv`. It restores the caller's previous `UV_CACHE_DIR` after
dependency setup. `verify-windows-package.ps1` passes the package-local path
explicitly, while users can override it when installation policy requires a
different writable location.

This change affects only dependency setup and verification ergonomics. It
does not change the Memory Authority, the read-only Python Worker boundary,
the retrieval contract, or the production exclusion of `fastembed`.

## Evidence

```text
commit: 294fe9bb712d8079503899513f91910f059f5f71
pnpm run ci:local: 8/8 stages passed
candidate: egopulse-0.1.0-294fe9bb712d-windows-x86_64-20260827T003543Z.zip
archive SHA-256: 006a0af71a912b83b3c5bdce3fe31e5e60015a334e5a7527a7ec1f7ffa41f2ba
package verifier with external UV_CACHE_DIR removed: passed, files=52
independent short-path extract audit with external UV_CACHE_DIR removed: passed
```

The independent audit created a fresh virtual environment and installed the
locked package dependencies. Both verification runs reported
`memory_worker_production_profile=passed`.

## Release disposition

The candidate remains unsigned Windows x64 early access. The cache failure is
closed as a release-verification defect. Semantic RAG admission and a second
production Harness remain separate Founder decisions; this fix does not
promote either capability.
