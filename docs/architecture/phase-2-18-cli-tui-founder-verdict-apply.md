# Phase 2-18：CLI/TUI Founder Verdict 应用闭环

状态：已实现，待与 G4-07 daemon projection pump 做端到端验收

## 1. 用户动作与内核边界

```text
CLI: egopulse task apply-verdict ... ─┐
                                      ├─► Local API
TUI: egopulse-tui task-apply-verdict ─┘       │
                                              ▼
                                   TaskAuthority.ApplyFounderVerdict
                                              │
                           ConfiguredTaskTransitionGuard
                           读取 FounderVerdictAuthority 已签发状态
```

两端只是参数与呈现不同，实际写能力完全相同：都经过 Client Kernel session
handshake、Contract Profile command authorization、Local API 和 Task Authority。
两端不打开 Authority 数据库，也不自行解释 Founder decision。

## 2. 命令契约

CLI：

```text
egopulse task apply-verdict <task-id> \
  --expected-revision <task-revision> \
  --work-revision <work-revision> \
  <founder-verdict-id>
```

TUI：

```text
egopulse-tui task-apply-verdict <task-id> \
  --expected-revision <task-revision> \
  --work-revision <work-revision> \
  <founder-verdict-id>
```

交互式 TUI 命令面板也提供同一个 `Apply Founder Verdict` 表单。参数只有 Task
并发控制和 Verdict 引用；decision 不由端侧传入，而由 Task guard 从已签发 Verdict
读取。这避免客户端把“Accept”字符串伪装成 Founder 授权。

## 3. 公共 digest 规则

`crates/client-operations::set_task_digest` 现在覆盖全部 Task command oneof，
包括 `ApplyFounderVerdict`。CLI、TUI 和未来 Desktop 使用同一函数生成请求摘要，
与 Task Authority 清除 command id、issued_at、correlation id、causation id 和
request digest 后的 canonical protobuf 规则一致。

## 4. 返回与投影

成功返回统一包含：Task id、revision、Task status、Founder Verdict id、replayed
和可选 projection await token。当前 await token 的投影目标仍由 Local Read Model
决定；Founder Verdict Authority 本身没有被客户端伪造为 Task read model。

`Completed`、`Rework`、`Rejected` 由 Task Authority 的真实 decision 映射产生，
不是 CLI/TUI 的本地分支逻辑。

## 5. 当前验收范围

- CLI/TUI/Client Operations 编译通过；
- 公共 Task digest 回归覆盖 `ApplyFounderVerdict`；
- G4-07 生产组合测试覆盖已签发 Verdict → Task 终态和 Consume outbox；
- 本阶段仍需在真实 daemon 中运行 CLI 和 TUI 两端命令，并由 projection pump
  完成 Consume outbox 的 recovery/idempotency 观测，作为下一项 E2E 验收。

