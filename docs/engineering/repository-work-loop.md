# Governed repository work and Founder decisions

Configure the real repository and its acceptance rules using the
[repository setup instructions](../../config/README.md#governed-repository-setup).
Keep the acceptance file outside the execution checkout. A successful setup
checks configuration; a Task still needs execution, sealed evidence,
Verification and an explicit Founder decision.

## Start and inspect work

With the daemon running under the intended user configuration:

```powershell
egopulse work start --intent 'Describe the requested change and constraints' `
  --scope scope:founder --work-type governed_repository_change `
  --context-ref default/README.md --no-memory --confirm --json
egopulse task get TASK_ID --json
egopulse content watch TASK_ID --frames 1 --json
egopulse task review TASK_ID --json
```

Use the actual configured scope and an available Context source. `--no-memory`
explicitly excludes Memory retrieval for this work. Review the returned Task
ID, final content, sealed ArtifactSet, criteria, discrepancies and unverified
items. The execution uses a detached worktree; accepted changes remain in the
governed artifacts until separately integrated. Acceptance does not merge a
patch into the source repository.

## Review execution approvals

When execution pauses for approval, use `egopulse approval list --actionable-only
--json` and `egopulse approval get APPROVAL_ID --json`. The operation summary
shows the bounded command preview and working directory, or the affected file
paths and change kinds. It excludes file contents and native routing details.

In the TUI Approval Queue, select the request and press Enter. Use PgUp/PgDn to
read the operation details before selecting a decision. AllowOnce is available
only for a complete, current summary. Missing, conflicting, redacted or legacy
details leave Deny and CancelAttempt available.

For an explicit CLI approval, pass `--reviewed-summary-digest` using the
`operationSummary.summaryDigestSha256` returned with the details you reviewed:

```powershell
egopulse approval decide APPROVAL_ID --decision allow-once --reason-code REVIEWED `
  --reviewed-summary-digest RETURNED_SUMMARY_DIGEST `
  --confirmation-proof-ref YOUR_APPROVED_PROOF_REF --json
```

The client checks that the latest operation is the one reviewed. The TUI carries
this binding automatically. No manual file hashing is required. A committed
Policy decision is distinct from its delivery to the running agent; an unknown
delivery remains unresolved and must not be replaced with a new native send.

On Windows, when ordinary PowerShell 7 is installed under Program Files,
EgoPulse prefers it in the native Codex child's PATH. This avoids Store shell
aliases inaccessible to the sandbox user and changes no global shell settings.

## Cancel work and inspect recovery

Read the current revision before requesting cancellation:

```powershell
egopulse task get TASK_ID --json
egopulse task cancel TASK_ID --expected-revision CURRENT_REVISION `
  --reason-code USER_REQUESTED --json
egopulse task get TASK_ID --json
```

`CancellationPending` confirms the request. A Ready task with no run is settled
from its own cancellation event. For a running task, delivery of the native
interrupt is only an intermediate receipt; `Cancelled` requires the committed
execution outcome. If a sealed return arrives first, its artifacts are retained
and the task becomes `Interrupted`. An unknown execution or approval-delivery
outcome also remains interrupted for reconciliation. These outcomes do not
automatically resume execution or resend an uncertain operation.

Keep the same data root and Authority keys when restarting the daemon. Inspect
the Task, Collaboration and approval details after restart. The daemon writes
safe, structured blockage codes to stderr when activation, approval delivery or
cancellation is held; repeated identical delivery holds are suppressed. Keep
these diagnostics with the task's evidence. Do not clear a failed database or
create a replacement decision to hide an unresolved outcome.

## Submit a decision

For a Passed result, Accept requires the reason and the confirmation proof
reference permitted by the local Founder policy:

```powershell
egopulse task decide TASK_ID --decision accept --reason-code REVIEWED `
  --confirmation-proof-ref YOUR_APPROVED_PROOF_REF --json
```

Reject uses the same command with `--decision reject`. Rework also requires a
Founder-authored directive:

```powershell
egopulse task decide TASK_ID --decision rework --reason-code CHANGES_REQUIRED `
  --confirmation-proof-ref YOUR_APPROVED_PROOF_REF `
  --required-changes-file 'D:\reviews\required-changes.txt' `
  --unverified-item-id CURRENT_ITEM_ID --json
```

Use only current discrepancy/unverified IDs from `task review`; repeat the
corresponding options when necessary. Files must contain the actual UTF-8
review text. Plain text options are also available, but file options avoid
putting review bodies in shell history.

Accepting a non-Passed result additionally requires `--risk-category`
(`quality`, `business` or `operational`), `--risk-rationale-file`, one or more
`--compensating-control-file` entries and complete coverage of the current
discrepancies and unverified items. The client creates and confirms real
supporting materials before sending the decision. Non-overridable findings
remain blocked. Model review with zero findings does not automatically supply
these user decisions or turn an unverified criterion into Passed.

New installations require the current `scope` criterion to have one complete
Passed result with evidence and no open discrepancy or unverified item.
Configure additional evidence-backed criteria with
`founder.non_overridable_criterion_ids`. The existing
`founder.non_overridable_gate_ids` setting still represents explicitly open
static blockers; a nonempty list blocks Accept. Development-stage G0–G3 gates
are not default runtime task blockers. Existing custom configuration is not
automatically rewritten.

The default decision lifetime is 240 seconds, generated after material
collection. Use `--expires-in-seconds` between 1 and 240 if the configured
Founder policy permits a shorter lifetime. `task decide` explicitly issues the
Verdict and then submits its application to Task Authority. Success confirms
both commits and returns the Task revision and status. Projection can lag;
inspect `task get` until Accept becomes Completed, Rework becomes Rework, or
Reject becomes Rejected. The low-level `verdict issue` command only issues a
Verdict and does not apply it to the Task.

## Recover an interrupted submission

Before a material or decision request is sent, the client saves a recovery
record. A storage error stops that request. On an unknown decision outcome,
retain the returned `recoveryPath` and run:

```powershell
egopulse task decide-recover 'PATH_RETURNED_BY_THE_CLIENT' --json
```

This explicitly resumes the original sealed Issue and its saved Apply with a
newly authenticated session. It preserves their identities, scope, decision,
proof and expiry so the Authorities can return the original committed results.
The Apply recovery record is saved beside the Issue record with an `.apply`
suffix before the Task request is sent. Keep both files. Do not manufacture a new decision
to resolve an unknown outcome. A current permission denial cannot establish
whether the earlier request committed; the record remains available.

The daemon does not automatically apply an issued Verdict after restart. If
Task application already committed before expiry, it can reconcile the durable
consumption receipt after expiry without applying the decision again. An
expired Verdict that was never applied cannot be used to complete a Task.
The production recovery worker obtains a separate durable authorization from
Policy Authority before expiring that unapplied Verdict. The Task remains
VerdictPending. Review the current result and explicitly submit a fresh decision
after expiry; the worker neither changes the original expiry nor automatically
accepts or rejects the Task. A per-item recovery failure remains pending and is
reported without stopping unrelated work.

For an interrupted material phase, pass each returned material record with
`--material-recovery PATH` to `task decide` using the same Task and decision.
Confirmed recovered materials can be combined with newly authored missing
roles. Rework accepts one recovered directive or one new directive. The client
validates all current bindings before issuing a new decision.

Windows records reside under
`%LOCALAPPDATA%\egopulse\client\founder-verdict-recovery` and use current-user
DPAPI protection. Keep them with the original Windows user and runtime data.
The records contain no saved session credentials; every send still checks the
current principal, permissions and projection store epoch. This storage
boundary does not isolate malicious programs running as the same OS user.
Records remain after confirmation for exact replay and diagnosis; do not edit
their contents or delete an unresolved record.
