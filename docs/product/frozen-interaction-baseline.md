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

## 6. Implementation checkpoint: 2026-08-28

The interaction semantics and authority boundaries remain frozen. The current
implementation must be read as a staged closure, not as a claim that the
normal user path is already complete.

- `work plan` implements the natural-language normalization, explicit source
  context pack, Work-Start Gate and event-packet preview. It is read-only and
  non-dispatchable.
- `task create` remains a low-level diagnostic/acceptance command. It is not
  the normal Founder workflow because it accepts Task fields directly.
- The internal Rust Context Authority A' slice is implemented and pushed in
  `ef37e40` and `596d496`: immutable content-addressed snapshots, complete
  governance-description idempotency, SQLCipher persistence, scope/expiry/
  integrity checks, restart replay and fail-closed descriptor changes.
- The public `PrepareWork` / `ConfirmWork` surface, daemon-side preparation
  compiler wiring, Authority-backed dispatch resolver, and equivalent CLI/TUI
  commands remain the next implementation slice. No client may simulate these
  by writing a snapshot or constructing a Task locally.

The product is therefore not yet declared normally usable. The truthful exit
path remains:

```text
CLI/TUI natural language
  -> Local API PrepareWork
  -> Authority-owned preview
  -> Founder ConfirmWork
  -> Task Authority commit
  -> projection await/watch
  -> Harness observation and governed evidence
```
