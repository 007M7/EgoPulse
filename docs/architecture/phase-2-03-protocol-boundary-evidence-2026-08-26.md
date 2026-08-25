# Phase 2-03 protocol boundary evidence

This note records local, non-inference observations after executable
discovery. No model prompt, API key or paid inference was used.

## Kimi CLI 1.49.0

`kimi info` reports:

- Kimi CLI version: `1.49.0`;
- agent spec version: `1`;
- Wire protocol: `1.10`;
- Python: `3.14.4`.

The CLI exposes an `acp` subcommand described as an ACP server, and its normal
CLI also advertises `--input-format stream-json` and
`--output-format stream-json` for print mode. This makes Kimi the strongest
second-Harness candidate so far because there is a machine-readable protocol
surface to probe instead of only terminal text.

This is still not enough for promotion. The ACP/stream-json boundary must be
tested for stable session and execution references, structured lifecycle and
approval events, cancellation, restart reconciliation and independently
addressable output evidence. A machine-readable stream can still be only a
final-answer transport.

An isolated local ACP handshake was then performed with `KIMI_SHARE_DIR` set
to the repository cache (no user-home writes and no model prompt). The
`initialize` response succeeded with `protocolVersion: 1`, agent name `Kimi
Code CLI`, version `1.49.0`, and session capabilities for list/resume. The
following empty `session/new` request was rejected with `Authentication
required` and a terminal `login` auth method. Therefore the protocol boundary
is real and structured, but the next session/lifecycle probe requires an
explicitly authenticated user environment; no login was initiated by this
probe.

## DeepSeek Harness / DSH 0.1.0-rc.5

The local `dsh --help` entry point describes an ordered profile launcher with
`cli`, `web`, `headless`, `--dump-config` and plugin commands. The checked-in
local source documentation describes ACP under the subagent boundary, not yet
as a primary Harness dispatch contract. It also documents that the ACP
subagent provider exposes no optional start-time capabilities, collects only
committed assistant text for its parent result, and uses a fresh process per
run.

Additionally, attempting a profile-level local help probe failed before the
profile started because the launcher could not create its user-profile module
symlink under `C:\Users\Administrator\.dsh\profiles` (`EPERM`). This is a
real Windows packaging/permission finding, but it is not evidence that DSH's
native workflow semantics are unsupported. It must be fixed or isolated in a
dedicated probe workspace before a fair semantic comparison.

## Candidate decision at this point

Kimi is the next candidate for a no-side-effect structured-protocol probe;
DSH remains a source-study candidate until its profile bootstrap can run in an
isolated Windows workspace. Neither candidate receives an active capability
profile from this note. Codex remains the only production Harness.
