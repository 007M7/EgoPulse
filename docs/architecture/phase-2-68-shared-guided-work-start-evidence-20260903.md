# U-04a shared guided work-start evidence

- Date: 2026-09-03
- Scope: shared Rust guided work-start operation and CLI interaction foundation
- Status: locally verified
- Parent flow: U-04 Guided Work Start

## Outcome

U-04a adds a shared guided work-start operation to `client-operations` and
exposes it through `egopulse work start`. It reuses the existing `PrepareWork`
and `ConfirmWork` Local API operations and the same authenticated
`ClientAttachment`; it does not introduce another work, Context or Task
kernel.

The caller supplies only high-level intent, work type, target scope and source
references. The daemon remains responsible for compiling Context and deriving
the immutable snapshot, state revision, confirmation binding and Task command
facts. `PreparedWork` and both recovery capsules have no public constructor,
setter or conversion path that lets CLI code forge those Authority-owned
values.

The existing lower-level `work prepare` and `work confirm` commands remain
available for compatible scripted use. No Proto, Local API, Authority,
database schema, agentosd production, TUI, Provider, Memory or Desktop change
is part of this slice.

## Preparation, confirmation and recovery

- Input validation and both required RPC permission checks happen before the
  first Prepare dispatch.
- Editing cancellation sends no RPC. Preview cancellation sends no Confirm or
  Task mutation; it does not claim that Prepare made no Context write.
- A daemon preview with blockers, inconsistent readiness, incomplete source
  facts or `ready_for_founder_confirmation=false` cannot be confirmed.
- Confirmation consumes `PreparedWork`, rechecks the authenticated principal,
  session, permissions and sealed binding, and cannot be issued twice from the
  same value.
- Prepare and Confirm each use a separate, stable idempotency key sealed before
  their first dispatch.
- A transport failure or an Error response can occur after the corresponding
  Context or Task commit. The shared operation therefore returns a distinct
  linear recovery capsule instead of reporting a definite rejection.
- Recovery replays the exact original request. It neither prepares replacement
  Context nor creates a new idempotency key. Session or principal drift fails
  before replay dispatch.
- A repeated uncertain Prepare or Confirm result is reported respectively as
  `PreparationOutcomeUnknown` or `ConfirmationOutcomeUnknown`. CLI output
  hides transport and gateway detail and tells the user not to prepare a
  replacement.
- Only a structurally valid Preview or an Accepted Task result is treated as a
  completed stage. Missing or unexpected response shapes fail closed as
  protocol errors.

## Safe preview and CLI interaction

The public preview is a bounded safety projection, not the daemon response.
It exposes normalized intent, work type, scope, source counts, readiness and
fixed UI-safe governance notices. It does not expose snapshot IDs, Context
revisions, compiled Context digests, confirmation bindings, principals,
idempotency keys, source paths, notice details or raw source content.

The preview accepts exactly the daemon's two ordered non-goals and four known
`CONTEXT_SOURCE_*` blockers through typed enums. Unknown, omitted, reordered or
duplicated non-goals, unknown blockers and any warning fail closed. Included
source facts require bounded non-control identity fields, `authority=project`,
a canonical SHA-256 digest and `included=true`; excluded facts and blockers
must match exactly, including the empty-source special case. The readiness
flags must agree and equal the derived included/excluded source state.

Interactive CLI confirmation uses the existing workspace crossterm dependency
with raw-mode RAII and a fixed deadline. Character input, Backspace, Enter,
Escape and Ctrl-C are handled without spawning an uncancellable stdin thread;
raw mode is disabled on every exit path. Non-interactive use requires an
explicit `--confirm` or `--cancel` and never defaults to confirmation.

Preview output is written to stderr. `--json` stdout remains one final result
envelope and does not include private Context bindings. Successful output
reports the created Task identity and a bounded next command rather than
starting an unbounded watch.

## Automated evidence

Implementation verification completed with:

```text
cargo test -p egopulse-client-operations --lib -- --test-threads=1
  40 passed; 0 failed

cargo test -p egopulse-cli -- --test-threads=1
  23 passed; 0 failed

cargo clippy -p egopulse-client-operations -p egopulse-cli --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The component tests cover opaque preparation, bounded input and preview
validation, fixed safe notice mapping, source-fact integrity, blocker and
permission rejection before Confirm, linear consume-once behavior, exact
Prepare and Confirm replay, idempotency preservation, session drift, response
shape failures, distinct unknown-outcome categories, CLI parsing and safe
rendering, explicit non-interactive choice, and cancellable confirmation-key
handling. The known non-blocking Windows LNK4099 missing OpenSSL debug-symbol
warning was emitted during test linking.

## Evidence boundary

U-04a proves the shared production operation and CLI component foundation,
including local input handling, safe preview projection, sealed confirmation
and exact replay semantics. It is not the complete U-04 product loop.

U-04c is now locally verified by
`phase-2-70-guided-work-start-real-daemon-evidence-20260904.md`. That evidence
adds a real daemon process, Windows IPC, production CLI/TUI seams, durable
Context/Task inspection and a normal ConPTY session without changing this
shared operation. Exact outcome-unknown replay is proven only inside the same
active client and attachment; packaged-binary behavior and recovery-capsule
persistence across a client-process restart remain outside the claim.
