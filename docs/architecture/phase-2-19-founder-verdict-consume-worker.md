# Phase 2-19：Founder Verdict Consume worker

状态：实现完成，进入本地门禁。

## 目标

关闭 `ApplyFounderVerdict` 后的跨 Authority 闭环：

```text
CLI/TUI/Local API
        │ ApplyFounderVerdict
        ▼
Task Authority（唯一写者）
        │ Task commit + durable cross-authority outbox
        ▼
agentosd Founder Verdict Consume worker
        │ VerdictCommand::ConsumeFounderVerdict
        ▼
Founder Verdict Authority（唯一写者）
        │ durable consume / idempotent replay
        ▼
Task outbox ACK
```

worker 是 daemon/application 层的跨域编排器，不是第三个 Authority，也不持有任何 Authority 私有数据库连接。

## 冻结的执行合同

1. worker 只读取 Task Authority 的 `pending_cross_authority_outbox`。
2. 只接受目标域为 `founder-verdict-authority` 的消息。
3. 先对完整 protobuf payload 计算 SHA-256，并与 outbox 中的 canonical digest 比较；不一致直接阻断且不 ACK。
4. payload 必须解码为 `ConsumeFounderVerdict`，其他命令类型直接阻断且不 ACK。
5. 通过共享的 `FounderVerdictAuthority` owner handle，以固定的 `TaskAuthority` principal 执行 Consume。
6. 只有结果为 `committed=true` 或 `replayed=true` 时，才确认 Task outbox。
7. Verdict Authority 锁、存储、校验或执行失败时不 ACK，下一轮继续恢复。
8. Consume 已提交但 daemon 在 ACK 前崩溃时，下一轮使用同一 payload 和幂等键重放；成功重放后再 ACK。

锁顺序也被冻结：读取 Task 后释放 Task 锁，再获取 Verdict 锁；Verdict 提交后释放 Verdict 锁，再重新获取 Task 锁 ACK，避免跨 Authority 锁嵌套。

## 责任边界

| 部件 | 责任 | 不允许做什么 |
| --- | --- | --- |
| Task Authority | 写入 Task 状态、Task commit receipt、Consume outbox | 不直接写 Verdict store |
| Founder Verdict Authority | 校验证据、写入 Consumed 状态和 consumption receipt | 不直接 ACK Task store |
| Consume worker | 传递已持久化的命令、处理重放、在成功后 ACK | 不创建第二 Authority、不推断业务事实 |
| Projection Pump | 将各 Authority projection outbox 写入 read model | 不参与业务 handoff ACK |
| CLI/TUI | 提交同一个 `ApplyFounderVerdict` 命令并展示结果 | 不绕过 daemon worker 直接修复状态 |

## 已验证证据

`apps/agentosd/tests/production_verdict_g4_07.rs` 使用真实 Task Authority、真实 Founder Verdict Authority、真实共享 handle 和真实 worker，验证：

- Founder Verdict 被 Task 的精确 scope 接受；
- Task 完成并产生 Founder Verdict cross-authority outbox；
- worker 通过 `TaskAuthority` principal 执行 Consume；
- Verdict 状态变为 `Consumed`；
- Task 的 Founder Verdict outbox 被 ACK；
- 其他 Task cross-authority handoff 不被 worker 越权处理。

底层的 `task_verdict_recovery_g4_07` 继续覆盖“Task commit 后进程在 Verdict Consume 前退出”的重开和幂等重放语义；两者合起来构成 G4-07 的生产组合证据。

## 运行配置

daemon 新增可选环境变量：

```text
EGOPULSE_VERDICT_CONSUMPTION_INTERVAL_MS
```

默认 250ms，允许范围 10ms～60s。该间隔独立于 Harness dispatch 和 Verification worker，便于单独控制跨 Authority 恢复节奏。
