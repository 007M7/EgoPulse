# G4-07 Founder Verdict → Task 终态提交

状态：已实现并通过本地生产组合测试（2026-08-27）

## 1. 解决的问题

G4-04 的真实 Harness/Artifact/Verification/Task 返还闭环结束在
`TaskStatus::VerdictPending`。此前 C-06 Founder Verdict Authority 已经具备
Issue/Consume 状态机和 Task commit receipt 校验，但生产 Task transition guard
仍然对 `ApplyFounderVerdict` fail-closed，因此 Founder Verdict 无法进入实际生产
组合。

G4-07 现在补齐的是“已签发 Founder Verdict 驱动 Task 终态提交”，不是把 Verdict
写入 Task，也不是让客户端自行声明决策。

## 2. 冻结的所有权边界

```text
Founder / CLI / TUI
        │ Local API ExecuteFounderVerdict
        ▼
FounderVerdictAuthority ── Issue ──► issued Verdict state
        ▲                                  │
        │                                  │ read-only exact proof
        │                                  ▼
TaskAuthority ◄── ApplyFounderVerdict ── ConfiguredTaskTransitionGuard
        │
        └── durable consume outbox ──► FounderVerdictAuthority.Consume
```

- FounderVerdictAuthority 是 Verdict 状态的唯一写者。
- TaskAuthority 是 Task 状态的唯一写者。
- `ConfiguredTaskTransitionGuard` 只读取 Verdict Authority，并返回
  `FounderDecision` 与 `founder_verdict_state_revision` 给 Task Authority。
- Task Authority 提交 Task 终态后，生成持久化 Consume outbox；后续 Consume
  由 Verdict Authority 自己完成 CAS 状态推进。
- CLI、TUI 和未来 Desktop 都只能复用 Local API，不能直接调用上述 Authority
  或打开其数据库。

## 3. Apply 前的精确证明

生产 guard 只有在下列条件全部成立时才放行：

1. Task 当前状态为 `VerdictPending`，Task id、expected revision 和 work
   revision 全部精确匹配。
2. Verdict 存在且当前状态为 `Issued`，状态 revision 非零。
3. Verdict scope 与 Task 当前快照精确绑定：task id、Task revision、work
   revision、artifact set id、verification artifact id 和 acceptance contract。
4. Verdict decision 可以无损映射到 Task 的 `Accept`、`Rework` 或 `Reject`。

缺少句柄、Verdict 不存在、状态已消费/撤销、scope 漂移或存储异常均保持
fail-closed，不产生 Task mutation。

## 4. 组合实现

生产启动采用一个受控的共享句柄解决 Task guard 与 Verdict resolver 的构造顺序：

```text
1. 创建空的 SharedFounderVerdictAuthority 句柄
2. 用该句柄创建 TaskAuthority transition guard
3. 创建 TaskAuthority
4. 用 TaskAuthority commit receipt source 创建 FounderVerdict resolver
5. 创建 FounderVerdictAuthority
6. 将唯一 Verdict Authority 放入共享句柄
7. Task port、Verdict port、projection pump 和 guard 共享同一句柄
```

这不是第二个 Authority 实例，也不是第二条数据库连接；句柄只解决构造期间的
循环依赖，并且在句柄为空时始终拒绝终态提交。

## 5. 验收证据

本地测试：

```text
cargo test -p egopulse-agentosd --test production_verdict_g4_07 -- --nocapture
1 passed
```

测试使用真实 TaskAuthority、真实 FounderVerdictAuthority、真实 SQLCipher store
和生产 `ConfiguredTaskTransitionGuard`。通过条件包括：

- Founder Verdict Authority 成功提交一条 Accept verdict；
- Task 从 `VerdictPending` 进入 `Completed`，revision 增加一；
- Task cross-authority outbox 中存在且仅存在一条指向
  `founder-verdict-authority` 的 Consume 消息；
- Task 没有访问 Verdict 私有存储的写接口。

该测试不宣称 Consume 已由后台投影泵完成；Consume recovery/idempotency 已由
现有 `task_verdict_recovery_g4_07` 覆盖，下一步需要把这一消费过程接入真实 daemon
owner projection pump，并补齐 CLI/TUI 的 Shared Task 终态回归。

