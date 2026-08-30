# EgoPulse 产品交互基线（开发期）

状态：开发期基线，继承 Founder-Agent OS 冻结架构；不表示所有链路已经实现。

## 1. 产品交互的核心结论

EgoPulse 的交互对象不是“让模型自己运行到结束”，而是让 Founder 以自然语言提出意图，由系统把意图转换成可检查的工作预览，再由确定性治理内核决定哪些动作可以发生。

三种表面共享同一 Rust Client Kernel、Local API 和 Authority：

```text
CLI / TUI / Desktop
          |
          v
Client Kernel（会话、命令、流、错误）
          |
          v
Local API（认证、权限、投影、命令转达）
          |
          v
Governance Kernel（Task、Collaboration、Memory、Evidence、Verdict）
          |
          v
Harness / Model / Tool / Workspace / Compute adapters
```

表面只改变输入方式和展示方式，不拥有 Task、Memory、Approval、Verification、FounderVerdict 或 Release 的事实写入权。

## 2. Founder 的标准工作闭环

```text
自然语言意图
    |
    v
意图规范化
    |
    v
上下文包 + Work-Start Gate
    |
    +-- 阻断 --> 显示缺口，Founder 补充上下文或修订意图
    |
    v
事件包预览
    |
    v
Founder 确认
    |
    v
Task / CollaborationRun / Step
    |
    v
Harness 流式观察（观察不等于完成）
    |
    v
Artifact + Evidence + Sego VerificationArtifact
    |
    v
Decision Inbox：Accept / Rework / Reject / Recover / Release
    |
    v
Founder 裁决与受治理的 Memory 候选
```

必须保留以下语义：

- 用户从自然语言开始，不要求先填写内部协议字段。
- 每次只向 Founder 提出一个清晰决定；内部证据可以折叠，但阻断项不能隐藏。
- 流式输出是实时观察和进度投影，不能被当作成功或完成。
- 完成必须有返回制品、独立验证和 Founder 裁决。
- Agent 只能提交 Memory candidate；只有 Memory Authority 在 Founder 授权后才能 accept 或 revoke。
- 外部副作用结果不确定时先暂停并对账，不自动重复执行。

## 3. CLI、TUI、Desktop 的实际分工

### CLI

CLI 是脚本化和可复现入口，适合：

- `status`、任务和投影读取；
- `work plan --intent ...` 生成稳定 JSON 或文本预览；
- 受权限和幂等保护的命令提交；
- 在自动化环境中消费明确的错误类别、恢复动作和 await token。

CLI 不应要求用户直接构造 Task Authority 的所有内部字段作为正常产品入口；当前 `task create` 仍是底层开发/验收入口。

### TUI

TUI 是交互式治理工作台，使用同一套命令能力：

- Dashboard 显示 Task、Approval、Workflow 和 Memory 相关投影；
- 命令面板支持自然语言工作预览；
- 表单用于需要精确 revision、证据引用或 Founder 确认的治理动作；
- 后续应把 Harness 的实时观察投影到工作区，但仍必须区分观察、候选、验证和最终裁决。

### Desktop

Desktop 不是另一套业务内核。它只在 CLI/TUI 的权威状态和流式投影稳定后承接更丰富的布局、证据展开和恢复操作；当前不作为首期实现阻断项。

## 4. 当前代码实现状态

| 交互环节 | 当前状态 | 诚实边界 |
|---|---|---|
| CLI 自然语言工作预览 | 已实现 | 目前是本地只读 Director facade，不创建 Task |
| TUI 命令面板工作预览 | 已实现 | 与 CLI 共享 facade，仍不创建/派发 Task |
| Local API 会话、读模型和受治理写命令 | 已实现并有 Windows IPC 证据 | 入口是底层 typed command，不是完整自然语言确认链 |
| Task Authority 生命周期 | 已实现部分状态转移和持久化 | 新增的中断/挂起/恢复/取消结果尚未全部由生产者自动触发 |
| Harness Dispatch / Adapter Edge | Codex 主路径已有真实验证 | 多 Provider 的真实认证与生产准入仍按独立 Gate 推进 |
| 流式 Harness 观察 | Adapter/Collaboration 内部可接收 | CLI/TUI 用户可见的统一实时观察投影仍需补齐 |
| Artifact / Sego / Founder Verdict | 已有受治理边界和局部 E2E | 不能把单元测试或技术回执表述为产品最终完成 |
| Memory candidate / accept / revoke / retrieval | 已实现并有本地验证 | lexical 是默认；semantic/hybrid 仍受评估门禁和回滚约束 |
| 一键 Windows 安装 | 已有 unsigned early-access 路径 | 没有代码签名证书时保留 SmartScreen 风险声明 |

## 5. 开发顺序

首期只把 CLI 和 TUI 作为可用表面，按照同一个内核逐步闭环：

1. 完成自然语言预览到 ContextSnapshot/Task.Create 的权威合同接线；
2. 完成 Founder 确认后 Task、Run、Step 的真实创建与投影；
3. 把 Harness 观察以可恢复流投影给 CLI/TUI，并保持“观察不等于完成”；
4. 完成 Artifact、Sego 验证、Founder 裁决和 Memory candidate 的可见闭环；
5. 完成取消、恢复、外部结果对账和回滚证据；
6. 再做多 Provider 的真实准入、成本边界和本地发布验收。

任何一步如果缺少权威事实源或跨语言合同，都应停在阻断状态，不能用 UI 模拟、模型自述或默认值冒充完成。

Implementation note: the status table above is the original checkpoint
snapshot. The more specific status below supersedes its Prepare/Confirm rows:
the daemon-owned `PrepareWork` and `ConfirmWork` path is now implemented as a
candidate revision and locally tested, but remains pending Founder acceptance
of the contract revision. Full execution and user-visible streaming remain
open.

## 6. Implementation checkpoint: 2026-08-28

The interaction semantics and authority boundaries remain frozen. The current
implementation is a staged closure: the real Founder path now has a daemon-
owned preparation and confirmation boundary, while execution, evidence,
verdict, streaming projection, and release remain subsequent closure work.

- `work plan` implements the natural-language normalization, explicit source
  context pack, Work-Start Gate and event-packet preview. It is read-only and
  non-dispatchable.
- `work prepare` is the real Local API path for the first half of the frozen
  workflow. The daemon reads only explicitly referenced files below the
  configured workspace root, records source identity and content digests, and
  issues an immutable `ctx:` snapshot. The client receives an Authority-owned
  preview; it cannot author the snapshot, compiled context, source authority,
  or gate result.
- `work confirm` accepts only the exact snapshot and confirmation binding shown
  by the preview. The binding covers the compiled-context digest, source
  ledger, gate recovery state, owner principal, and the reviewed contract
  references; divergent governance descriptions for the same compiled content
  fail closed at issue instead. A successful confirmation
  delegates Task creation to Task Authority and returns a projection await
  token; it never returns a mixed success/error response. In a production
  composition with an admitted workflow, the daemon then settles the created
  Task through the fixed system-only `ActivateTask` path; the client never
  supplies that principal or operation.
- CLI and TUI expose the same Prepare/Confirm capability through the shared
  `ClientAttachment` and Local API contracts. TUI's palette and direct
  subcommands are presentation paths, not a second business kernel.
- `task create` remains a low-level diagnostic/acceptance command. It is not
  the normal Founder workflow because it accepts Task fields directly.
- The internal Rust Context Authority A' slice is implemented and pushed in
  `ef37e40` and `596d496`: immutable content-addressed snapshots, complete
  governance-description idempotency, SQLCipher persistence, scope/expiry/
  integrity checks, restart replay and fail-closed descriptor changes.
- The Authority-backed dispatch-material resolver, user-visible streaming
  observation, and full execution-to-evidence-to-verdict E2E remain the next
  implementation slices. Confirmation-to-activation is now wired for the
  reviewed production workflow, but dispatch material must still prove its
  Context Authority binding before this is called a complete product path.
  No client may bypass the preparation boundary by writing a snapshot,
  constructing a Task locally, or dispatching directly.

The product is therefore not yet declared fully normally usable. The truthful
first-half path is now executable locally, while the complete product path
remains:

```text
CLI/TUI natural language
  -> Local API PrepareWork
  -> Authority-owned preview
  -> Founder ConfirmWork
  -> Task Authority commit
  -> daemon-owned reviewed activation
  -> projection await/watch
  -> Harness observation and governed evidence
```

## 7. Implementation checkpoint: 2026-08-30

The next read-side Context-to-Harness binding slice is implemented as a
candidate and has passed its targeted local gates. A confirmed Task whose
`input_snapshot_id` is a canonical `ctx:<sha256>` is resolved again through
Context Authority with the Task scope before workflow activation. The resolved
digest binds both `StepPlan.input_bundle_ref` and dispatch material to the
immutable `ctx-<sha256>.json` bundle. Immediately before native Harness
dispatch, the daemon resolves the snapshot again and rejects missing,
malformed, expired, revoked, scope-inconsistent or byte-inconsistent context.
Static reviewed input bundles remain compatible and cannot be reached as a
fallback from a malformed `ctx-*` reference.

`RunPlan.digest_sha256` continues to identify the reviewed plan template or
configuration artifact. The current contract does not define it as a canonical
hash of an instantiated `RunPlan` message and provides no canonicalization or
content-consistency oracle. Dynamic Context binding is therefore protected by
the Authority snapshot, Task/Run reference guards, dispatch-material digest,
and the sealed `CreateRunCommand` request digest; this slice does not invent a
new plan-digest algorithm. Any future instance-content digest requires a
separately frozen calculation and verification contract.

This checkpoint does not declare the normal product path complete. Context
Authority still lacks a formal authenticated, idempotent and audited revoke
write command; current evidence only proves that dispatch rejects a snapshot
already governed into the revoked state. At this checkpoint a real dynamic
product E2E was also still required; the R-8A checkpoint below closes that
single-process happy path only. Formal revoke and recovery remain subsequent
closure work.

## 8. R-8A dynamic interaction checkpoint (2026-08-30)

The single-process dynamic happy path is now locally proven through the real
product and governance seams:

```text
CLI work prepare
  -> Local API / Context Authority snapshot
  -> TUI Founder work-confirm
  -> Task Authority Ready -> daemon-only Active
  -> activation outbox
  -> Collaboration Run / Step / Attempt / DispatchIntent
  -> Context Authority dispatch-time revalidation
  -> Adapter Edge
  -> one native-driver dispatch and one governed non-terminal acknowledgement
```

The evidence binds the same `ctx:<sha256>` snapshot to the immutable bundle
reference and bytes, the Task's activation run, and the resulting Run, Step,
Attempt and dispatch identities. CLI and TUI use the shared ClientAttachment
and Local API; neither surface constructs Task activation or dispatch fields.
The Task remains `Active` after the Harness acknowledgement. A delivery or
observation is not interpreted as Task completion, acceptance, verification,
Founder verdict or release.

R-8A closes only this single-process happy path. It does not close daemon
restart/replay recovery, resumable user-visible streaming, the reverse
TUI-prepare/CLI-confirm acceptance scenario, or the authenticated and audited
Context revoke write contract. Those remain explicit R-8B and R-9 work, so the
whole product path is still not declared normally usable.
