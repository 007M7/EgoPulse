# U-02b shared guided approval decision evidence

- Date: 2026-09-03
- Scope: shared client operation and CLI approval decision surface
- Status: locally verified
- Parent flow: U-02 Approval Watch and guided decision

## Outcome

U-02b moves approval-decision preparation and dispatch out of the CLI and into
`egopulse-client-operations`. CLI and future TUI callers now provide only the
approval request ID, one of the three existing decisions, a non-empty reason,
and an optional confirmation proof reference.

The shared operation checks both read and command permissions before any RPC,
reads the latest daemon-authored approval view by ID, treats
`available_actions` as the only actionability authority, and binds the command
digest, observation identity and sequence, and request revision from that
latest view. Presentation surfaces cannot supply those concurrency fields.

No Proto, Local API, Policy Decision Authority, persistence schema, Task state,
or TUI behavior changed in this slice.

## Fail-closed and retry semantics

- Blank approval IDs, blank reasons, and present-but-blank proof references are
  rejected before either read or write dispatch.
- Missing, non-actionable, identity-mismatched, malformed, or unknown approval
  views never reach the decision RPC.
- The sealed command uses one internal idempotency key derived from a
  domain-separated SHA-256 of the approval request ID. Exact semantic retries
  retain the same key and canonical request digest; a changed decision or
  reason retains the key but changes the digest so the existing Authority can
  return `IdempotencyConflict`.
- Successful results must be committed, match the requested decision, carry a
  non-empty Authority reference, have revision greater than zero, and be in the
  exact `Issued` state.
- Deprecated unsanitized Authority results and malformed sanitized results are
  rejected as protocol integrity failures.
- If the Authority commit succeeded but projection-await token production
  failed, the committed receipt remains the result and the safe Local API error
  is surfaced as a projection warning. The client does not encourage a blind
  resubmission of an already committed decision.

## CLI change

`egopulse approval decide` no longer accepts the five `expected_*` binding
arguments. It delegates to the shared guided operation and preserves typed
permission, Local API, transport, Authority, and protocol failure categories.
The JSON success envelope includes the existing decision receipt plus an
optional redacted `projectionWarning`.

## Verification

Independent read-only review concluded GO with no P0 or P1 findings.

```text
cargo test -p egopulse-client-operations guided_approval --lib -- --test-threads=1
  5 passed; 0 failed

cargo test -p egopulse-cli --bin egopulse approval_decide -- --test-threads=1
  2 passed; 0 failed

cargo clippy -p egopulse-client-operations -p egopulse-cli --all-targets -- -D warnings
  passed

cargo fmt --all -- --check
  passed

git diff --check
  passed
```

The recurring Windows `ossl_static.pdb` linker warning is environmental and
did not affect the test or lint result.

## Remaining U-02 work

U-02b does not claim a complete TUI approval experience or a new real-daemon
acceptance path. U-02c must compose the already-shared opaque Approval Queue
session and this guided decision operation into the TUI, then prove the real
daemon transition and read-model convergence without adding a second control
plane.
