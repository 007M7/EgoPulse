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
probe. The 2026-08-26 isolated Rust probe emitted the following safe,
structured result:

```json
{"candidate":"kimi-cli","protocol":"agent-client-protocol","prompt_sent":false,"model_call":false,"initialize":"passed","session_disposition":"authentication_required"}
```

This result is evidence of a reachable and controlled authentication boundary;
it is not evidence of prompt execution, approval routing, cancellation or
restart reconciliation.

A second probe used the installed user's default Kimi profile without setting
`KIMI_SHARE_DIR`. The process closed its ACP stdout before returning the first
`initialize` response. EgoPulse now classifies that condition as
`KIMI_ACP_INITIALIZE_EOF` with `ProvenNotSent`, rather than misclassifying an
empty stream as invalid JSON. The probe therefore records `initialize: failed`,
`prompt_sent: false` and `model_call: false`; it did not reach `session/new`.
This is a default-profile startup/protocol failure observation, not evidence
that the user's authentication is absent or invalid, and it does not promote
or demote Kimi by itself.

The Rust candidate adapter now records this boundary through
`KimiAcpDriver::probe_session`. It preserves the `initialize` probe result and
classifies `session/new` as one of three controlled dispositions:
`Created` with an opaque native session reference,
`AuthenticationRequired` with non-secret auth method identifiers, or
`Rejected` with a safe detail code. Each session response is represented by a
SHA-256 evidence reference. This is probe evidence only: no prompt is sent,
no session is installed into a capability profile, and all execution,
approval, cancellation and reconciliation methods remain fail-closed.

The installed Kimi 1.49.0 package's local ACP integration notes further
record the native lifecycle names `session/prompt`, `session/update` and
`session/cancel`, plus the server request `session/request_permission`.
EgoPulse now has an isolated Rust codec for these message shapes. It preserves
unknown `session/update` kinds instead of converting them into completion, and
it has fixture coverage for message identity, permission requests and native
prompt/cancel method construction. This is protocol-shape evidence only; it
does not attest structured ACK, approval routing or recovery semantics.

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

The isolated follow-up probe now sets `DSH_HOME` to a temporary workspace and
uses `DSH_PERMISSION_MODE=read-only`. With that boundary, `dsh --profile cli
--dump-config` and `dsh --profile cli --help` both completed successfully. The
reproducible command is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/probe-dsh-windows.ps1
```

This upgrades DSH's result from “default profile bootstrap blocked” to
“isolated CLI profile bootstrap passed”. It still does not prove native
structured dispatch, approval, cancellation or reconciliation; no prompt or
API call was made.

A second no-model-call probe started the compiled `dsh-acp-demo` binary with
the local ACP composition and exchanged two JSON-RPC requests over stdio:

1. `initialize` returned protocol version `1`, agent identity
   `deepseek-harness-acp`, and baseline-only prompt capabilities;
2. `session/new` returned an opaque session id for an absolute workspace,
   with empty additional directories and MCP servers.

The process exited cleanly after stdin EOF and emitted no stderr. This is the
first DSH evidence for a native structured session boundary, not merely CLI
text. It still does not attest `session/prompt`, committed output ordering,
permission routing, cancellation or restart reconciliation. Those rows remain
held until a keyless replay fixture or an explicitly authenticated local run
can exercise them without changing the user environment.

The keyless replay lifecycle probe has now passed with the repository's
`multi-turn` fixture:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/probe-dsh-acp-replay-windows.ps1
```

It drove `initialize`, `session/new`, and two `session/prompt` calls over the
real compiled ACP subprocess. The observed committed updates were `ONE` and
`TWO`, each followed by `stopReason=end_turn`; stdout contained only JSON-RPC,
stderr was empty, and no model/API call was made. This proves a replayable
native prompt/committed-output boundary, but not live-provider semantics.

The native cancellation row also passes with the DSH `cancel` replay fixture:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/probe-dsh-acp-cancel-windows.ps1
```

The probe waits for the fixture's ready marker, sends `session/cancel` as a
native ACP notification, and receives the original prompt response with
`stopReason=cancelled`. The subprocess exits cleanly with empty stderr and no
model/API call.

The recovery capability probe now records the opposite result explicitly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/probe-dsh-acp-recovery-capability-windows.ps1
```

The compiled DSH ACP server does not advertise `loadSession`; native
`session/load` and `session/resume` requests are rejected as unsupported. This
is a known, fail-closed recovery disposition (`held_native_recovery_unsupported`),
not evidence that a new session is equivalent to recovery of an old session.
The server also logs the expected JSON-RPC "Method not found" diagnostics to
stderr and keeps its stdio loop alive after those requests, so the isolated
probe terminates the child explicitly after the assertions. This is recorded
as probe behavior rather than hidden as a clean shutdown. EgoPulse must
therefore retain the dispatch/attempt outcome in its own Authority and cannot
promote DSH to a production Harness on ACP lifecycle evidence alone.

## Candidate decision at this point

Kimi is the next candidate for an authenticated lifecycle probe. Its current
no-prompt disposition is `authentication_required`. DSH's isolated profile and
keyless ACP lifecycle evidence are now recorded, but its native recovery
limitation keeps it held. Neither candidate receives an active capability
profile from this note. Codex remains the only production Harness.
