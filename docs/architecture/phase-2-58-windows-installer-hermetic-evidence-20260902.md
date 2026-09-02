# Phase 2-58 — Windows installer hermetic evidence

- Date: 2026-09-02
- Scope: repository Windows installer, real debug CLI/TUI/daemon binaries, configuration template, and isolated PowerShell process behavior
- Status: locally verified

## Evidence boundary

This slice verifies the repository `install-egopulse.ps1` behavior from an
isolated temporary package layout. The fixture copies the three real debug
binaries (`agentosd.exe`, `egopulse.exe`, and `egopulse-tui.exe`), the current
configuration template, and the installer into a test-unique sandbox. It does
not add a runtime bypass or replace the daemon's normal configuration checks.

The evidence is deliberately narrower than a release-install claim. It does
not prove:

- integrity or completeness of a produced release archive;
- execution after extracting a real packaged archive;
- Memory Worker installation or `uv` dependency setup;
- Authenticode, provenance, or any other release-signing property.

## Proven behavior

The hermetic test starts the installer in an independent PowerShell process
with a reduced `PATH`, a unique DataRoot and IPC instance, and process-only
Authority keys. It proves that:

- `IpcInstance` accepts only a non-empty 1–64 character ASCII token beginning
  with an alphanumeric character and otherwise containing only ASCII
  alphanumeric, dot, underscore, or hyphen characters;
- an invalid IPC token fails before the requested DataRoot is created;
- `-SkipMemoryWorker` succeeds while `uv` is unavailable and creates neither a
  worker virtual environment nor a worker cache;
- `-NoPersistEnvironment` preserves the inherited process-only Authority keys
  and leaves the complete User-scope `EGOPULSE_*` environment snapshot
  unchanged;
- the generated `agentos-config.json` exists only under the requested DataRoot;
- the real daemon reports `configuration=passed` without opening Authority
  stores;
- stdout and stderr do not contain the test Authority-key sentinel;
- installer output reports `environment=process-only` and the exact requested
  IPC instance;
- process-only guidance states that values do not survive the installer
  process and directs immediate daemon startup through `-Launch` or explicit
  environment propagation;
- every child process has a bounded wait/kill path, the parent process
  environment is restored, and recursive cleanup is limited to a validated
  test-unique temporary root.

The installer also starts `-Launch` with a hidden window and `PassThru`, and
prints only the resulting process ID rather than any key material. The
hermetic scenario does not start that long-running daemon; this launch branch
is therefore implementation-reviewed and covered by the repository gates, not
a packaged-daemon lifecycle proof.

## Verification

The focused installer evidence passed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-install-egopulse.ps1
```

Result: `installer_hermetic_test=passed` with a test-unique IPC instance.

The repository Rust gate passed on the final implementation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check-rust.ps1
```

That gate builds the debug CLI, TUI, and daemon before executing the installer
test, then runs the existing Rust test matrix. Its C5 fixture result remained
`22 passed; 0 failed`.

The repository boundary and whitespace gates also passed:

```powershell
pnpm run check:boundaries
git diff --check
```

This evidence establishes hermetic installer behavior for the tested source
layout. It must not be used as evidence for archive construction, extracted
package execution, Memory Worker setup, or release signing.
