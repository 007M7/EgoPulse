# EgoPulse 一期实现缺陷与闭环缺口清单

更新时间：2026-09-05（Asia/Shanghai）
依据：当前工作区代码、2026-09-05 本机安装与真实 Codex 试跑。
用途：后续修复与验收的工作清单。本文不代表一期验收通过。

2026-09-06 追记：第 1—6 节保留首次实测原貌；当前修复和验收状态见第 7 节。原记录中的 Sego 默认审查要求已被用户后续“默认不主动触发”指令及当前 AGENTS.md 的 opt-in 规则替代。

## 1. 当前结论

环境已具备运行条件，固定版本 Codex 已通过现有账号真实返回回答。当前主要阻塞是项目实现缺陷和验证接入缺口，继续安装依赖不能解决这些问题。

一期已经有 Authority、Harness、Artifact、Verification、Founder Verdict 等实现和局部测试，但尚未证明以下用户流程能够连续完成：

> 安装 → 创建工作 → 真实模型执行 → 应用展示返回 → 证据入库 → 验证 → 用户验收 → 任务终态 → 再次创建工作。

截至本次记录，最新试跑的后台再次退出。此前“可实际使用”的判断过于乐观，应调整为：核心工程能力已实现一部分，但首次使用与连续任务闭环尚未验收。

### 状态定义

- **未修复**：已有明确缺陷证据，尚无通过验收的修复。
- **已修改，局部验证通过**：工作区已有改动及相关测试通过；不等于完整流程通过。
- **接入缺口**：已有底层机制，但实际可用配置、执行入口或证据链未接齐。
- **待核查**：有失败现象或风险证据，尚不能定性为已确认根因。

优先级：P1 为阻断真实使用；P2 为影响恢复、诊断或验收覆盖。本清单没有将普通功能故障升级为安全事故。

## 2. 实现缺陷

| 编号 | 优先级 | 项目 | 当前状态 | 用户影响 |
|---|---|---|---|---|
| D01 | P1 | 工作流命令 ID 未按独立运行隔离 | 未修复 | 多任务可能触发唯一键冲突，后台退出 |
| D02 | P1 | 不同任务复用模板 Step ID | 已修改，局部验证通过 | 多任务无法可靠共存 |
| D03 | P1 | Codex 两类事件重复映射为执行开始 | 已修改，局部验证通过 | 后续返回内容被前序事件阻塞 |
| D04 | P1 | 原生 Harness 的协作投影未接入 | 已修改，局部验证通过 | 应用无法展示真实协作状态 |
| D05 | P1 | 安装模板的权限合约摘要过期 | 已修改，安装检查通过 | 配置检查通过仍可能在实际调用时失败 |
| D06 | P1 | 安装器生成无效 Windows 工作目录引用 | 已修改，安装检查通过 | 模型派发前无法解析工作目录 |
| D07 | P1 | 默认任务范围与工作类型不匹配 | 已修改，局部验证通过 | 用户按默认入口提交工作时被拒绝 |
| D08 | P2 | 后台错误链路缺乏足够诊断信息 | 部分改善 | 定位只能反复重建、追查底层状态 |

### D01：命令 ID 未按独立运行隔离

- **代码证据**：[single_harness_workflow.rs](../../crates/local-ide-control/src/collaboration_control/single_harness_workflow.rs) 的 `metadata()` 使用 `command_id: format!("egopulse-{command_id}")`。不同 Run 的同一操作会生成相同命令 ID。
- **约束证据**：[store.rs](../../crates/local-ide-control/src/collaboration_control/store.rs) 的 `collaboration_events.command_id` 有全局 `UNIQUE` 约束。`idempotency_scope` 虽按运行区分，并不能消除该独立约束的冲突。
- **实测现象**：修复 Step ID 后，再创建任务仍出现 `task activation workflow failed: collaboration control operation failed`，后台退出。
- **证据边界**：命令 ID 与数据库约束的冲突已由代码确认；最新崩溃的底层 SQL 错误尚未直接展开，不能声称所有运行时失败都已唯一归因于此。
- **修复要求**：命令身份按运行/操作确定性生成；同一操作重试保持原身份，不同任务不冲突。评估已有部分提交 Run 的重放兼容，不能只改生成规则后忽略旧数据。
- **验收条件**：同库连续至少两个独立任务成功执行；同任务重试不产生重复副作用；重启后不会因命令身份变化产生幂等冲突。

### D02：Step ID 复用

- **证据**：[lib.rs](../../apps/agentosd/src/lib.rs) 原先只为 Run、Attempt、Dispatch 派生任务级身份，Step 沿用模板值；`collaboration_steps.step_id` 是主键。
- **复现**：双任务回归修复前失败，两个任务的 Step ID 均为 `step-route`。
- **当前改动**：为受治理的单步任务生成任务级 Step ID；保留对单步模板的约束。
- **验收条件**：不仅解析器返回不同 ID，还应在真实 Collaboration 存储中完成两个任务的创建、执行与重放。当前受 D01 阻塞，尚未完成这项端到端验收。

### D03：重复执行开始事件阻塞返回

- **证据**：[protocol.rs](../../crates/codex-adapter/src/protocol.rs) 原先把 `thread/status/changed(active)` 与 `turn/started` 都映射为 `ExecutionStarted`。
- **实测状态**：前一个事件已消费，后一个 `turn/started` 持续 pending；此时 Codex 原生会话已完成，而应用内容为空。
- **原因**：Collaboration 的执行开始转换要求 Attempt 处于 Acknowledged；第二次开始事件到达时已经是 Running，事件被保留等待依赖，后续内容无法继续处理。
- **当前改动**：线程活跃改为信息事件，由 `turn/started` 承担回合执行开始事实；增加同序列只产生一次执行开始的回归。
- **验收条件**：真实事件序列能推进到最终内容与终止事件；还需明确旧版本已经卡住的持久化事件如何恢复。修改映射不会自动改写旧记录。

### D04：协作投影没有接入生产组合

- **证据**：试跑时 Collaboration outbox 的 `collaboration-snapshot-v1` 持续 pending；CLI 的协作 Run 信息为空、任务投影 stale。原生 Harness 组合没有将对应投影源接到公共投影器。
- **当前改动**：在 [lib.rs](../../apps/agentosd/src/lib.rs) 中接入 Collaboration owner 的投影读取与 ACK，并增加投影源存在的回归。
- **边界**：仍通过 owner 接口读取和确认 outbox，不让 UI 或 Worker 直接写权威状态。
- **验收条件**：真实任务的 Run、Step 与状态可在 CLI/TUI 查询；重启后投影补齐，重复投递不重复生成事实。最新完整试跑先被 D01 中断，不能把这一项标为已闭环。

### D05—D07：首次安装与默认入口缺陷

- [agentos-config.example.json](../../config/agentos-config.example.json)：权限摘要与当前 Authorization 合约不一致，已更新两个对应引用。
- [install-egopulse.ps1](../../install-egopulse.ps1)：原工作区引用包含 `:`，但解析器把它当作 Windows 相对目录；现创建真实目录，并同步 Harness 与 Artifact 的工作区引用。
- 安装器原任务允许范围是替换占位值，与 Founder 的 `scope:founder` 不一致；现同步范围。
- [TUI main.rs](../../apps/tui/src/main.rs)：工作预览默认类型原为 `general`，而配置仅允许 `governed_repository_change`；已修改默认值。
- **验收条件**：全新安装后，不手改配置即可通过默认入口准备并提交工作。安装回归已通过；用户完整交互仍待上述 P1 问题解决。

### D08：错误诊断不足

- 原日志仅输出 `harness dispatch runner failed`，隐藏具体来源；部分内部路径进一步把嵌套错误转成笼统字符串。
- 已在后台入口补充标准错误原因链，但最新错误仍止于 Collaboration 操作失败，尚未得到安全、明确的底层约束错误。
- **修复要求**：输出安全错误码、失败阶段和必要关联信息；避免直接打印原生载荷、密钥或完整敏感上下文。不能靠忽略失败使服务看似健康。
- **验收条件**：遇到约束冲突、无效工作目录、派发失败时，可从日志明确定位阶段与原因。

## 3. 产品闭环缺口

| 编号 | 优先级 | 缺口 | 证据与当前状态 | 验收条件 |
|---|---|---|---|---|
| C01 | P1 | 实际可用的 Verification Worker 未配置 | 默认安装没有 `verification_worker`；示例中的检查器、声明、证据引用为占位值 | 真实返回被检查器读取，结果提交 Verification Authority，并写回对应 Task |
| C02 | P1 | Codex 原生审查与应用内验证未完成接入 | 仓库改码用的 Sego review bridge 与 EgoPulse 的任务验证是不同入口，不能互相替代 | 使用 Codex 原生审查链路，形成与具体任务、产物、版本绑定的可核验验证记录 |
| C03 | P1 | 检查器证明材料及动态任务绑定未落地 | 示例配置使用固定 claim、请求字节、预期摘要和产物引用；实际任务身份动态生成 | 明确检查器 profile、attestation、输入输出契约和任务绑定来源；不复用上一任务的证据 |
| C04 | P1 | 从真实结果到 Founder Verdict、Task 终态尚未贯通 | 有 Authority 与局部测试，但本次真实试跑没有到达可验收终态 | 通过用户入口查看证据并作接受/返工/拒绝决定，Task 正确转换；重复操作可安全重放 |
| C05 | P2 | 实际交互交付未验收 | TUI 尚未完成“创建工作—查看结果—验收”的真人体验前检查 | 启动入口可用、状态准确、结果可见、失败可解释、可再创建下一项工作 |

### 验证接入必须保留的约束

1. [verification-worker.example.json](../../config/verification-worker.example.json) 是字段示例，不是已可用检查器。不能把占位 ID 换成任意字符串后就称为验证完成。
2. 检查器 attestation 必须有真实、可核验的 Artifact 证据；检查结果必须绑定实际任务与产物。
3. [sego.rs](../../crates/verification-authority/src/sego.rs) 区分“未发现问题”和“正向验收证据”。普通模型审查零发现不自动等于 Passed，不能为通过流程而伪造正向验收。
4. 按用户要求，Sego 审查走当前 Codex 原生链路，不另开 DeepSeek 等付费审查调用。本次修改尚未完成最终 Sego 提交，不能声明审查通过。
5. 不能让 UI、TypeScript Harness 或 Python Worker 直接修改 Authority 状态，也不能手工把数据库任务改成 Completed。

## 4. 待核查事项：不混同为已确认缺陷

| 编号 | 现象/问题 | 需要核查什么 |
|---|---|---|
| V01 | 无 context-ref 的工作请求返回 `LOCAL_API_PROTOCOL_ERROR`；提供虚构 README 后可创建任务 | 是产品要求必须有来源，还是错误映射/空来源处理有缺陷；若不支持，需给可理解提示 |
| V02 | 历史失败任务存在 Active 或 CancellationPending 等未收敛状态 | 修复后怎样恢复部分提交、重复开始事件及未知执行结果；不能删除旧记录代替恢复验收 |
| V03 | 模型原生会话完成，但应用未完成返回接收 | 修复 D01、D03、D04 后，继续验证 Artifact Return、内容披露、证据接收及状态推进是否还有问题 |
| V04 | 验证模板大量固定字段 | 哪些字段可以通过现有配置准确接入，哪些需要补充任务级绑定实现；尚未完成逐字段接入设计 |
| V05 | 默认 Rust 检查脚本未运行全部 daemon 集成测试 | [check-rust.ps1](../../scripts/check-rust.ps1) 先排除 daemon，再只运行其 lib 与 `c5_00_daemon_fixture`；需补足连续任务及真实返回覆盖 |

## 5. 已有验证证据及其边界

| 验证 | 已观察结果 | 限制 |
|---|---|---|
| 真实 Codex 调用 | 已完成并返回中文答案 | 不等于 EgoPulse 已显示、验证、验收该答案 |
| 安装回归 | `installer_hermetic_test=passed` | 不覆盖完整模型执行与最终验收 |
| 后台单元测试 | 133 项通过 | 是局部实现验证，不代表真实全链路通过 |
| Codex Adapter 单元测试 | 13 项通过，包含重复开始事件回归 | 仍需真实事件序列验证 |
| pnpm 综合检查 | 合约、代码生成、包完整性、TypeScript 检查通过 | 在后续返回链路改动前完成，不能表述为最新全部检查重新通过 |
| Rust clippy | 曾完成全工作区检查 | 此后又修改了返回链路，需针对最终变更重跑 |
| 全工作区 cargo test | 已发起 | 截至本次文档读取，日志尚无完整结束结论；不计为通过 |
| Sego Codex 原生审查 | 尚未完成本轮最终提交 | 代码修复任务仍未完成 |

本机原始证据保存在忽略目录 `.artifacts/experience-evidence/`，不应假设这些文件随仓库交付：

- `step-id-regression.log`：修复前两个任务 Step ID 相同的失败回归。
- `return-regressions.log`：后台 133 项与 Adapter 13 项通过记录。
- `installer-tests.log`：安装回归结果。
- `experience-r2.stderr.log`：最新后台退出及错误原因链。
- `live-work-source.json`、`live-work-r2.json`：真实任务创建回执。
- `workspace-tests.log`：全工作区测试过程日志，需继续确认最终退出码。

工作区有未提交代码改动；本文中的“已修改”均指本地状态，不代表已提交、发布或完成验收。早期失败实例与独立体验实例均保留，不含伪造的完成状态。

## 6. 建议修复顺序与完成门槛

1. **先修跨任务身份**：D01，并补真实存储层双任务与同任务重试回归，复核 D02。
2. **跑通返回和展示**：实测 D03、D04，验证内容、Artifact 与 Task 证据的真实衔接。
3. **处理失败恢复**：核查 V02、V03，明确旧任务处理方式及后台重启恢复行为。
4. **补齐验证接入**：落实 C01—C03，使用真实 Codex 审查和准确的任务/产物绑定。
5. **完成用户验收路径**：验证 C04、C05，再交付用户体验。
6. **最终检查与审查**：运行适用的完整测试、最终变更检查和 Codex 原生 Sego review，记录未通过或未覆盖项。

一期可实际使用的最低验收条件：

- [ ] 新安装无需手改内部 ID、合约摘要或路径即可提交工作。
- [ ] 连续两个独立任务成功运行，没有跨任务唯一键冲突。
- [ ] 同一任务重试和后台重启不重复执行外部副作用。
- [ ] Codex 的最终回答能在 EgoPulse 界面中看到，而非仅存在原生会话里。
- [ ] 返回产物与证据由对应 Authority 正确接收，投影无持续空白或错误状态。
- [ ] 检查器基于真实产物完成验证；不足的证据明确标为未验证。
- [ ] 用户可查看验证结果并作验收决定，Task 进入相应终态。
- [ ] 失败与取消路径有明确结果或可操作的恢复入口。
- [ ] 必需检查与 Sego 审查完成，留下与最终代码对应的证据。

## 7. 2026-09-06 复用审计与真实验收追记

### 交接前已有实现，问题在完整用户路径的证据与接线

交接产品提交 `44b3408` 到本次修复基线 `5c7c442` 的 `apps/crates/config/contracts` 没有源码差异。没有发现迁移丢失或遗漏合并，不需要再次导入旧施工分支。原文档确曾声明 CLI/TUI 一期闭合；其证据主要覆盖真实 Authority、确定性原生事件 fixture、候选安装和分段流程，不能覆盖本次实测暴露的全新真实任务阻塞。

本轮继续使用原 Task、Collaboration、Artifact、Verification、FounderVerdict、Policy Authority、原 Codex Adapter、共享 client-operations 和 CLI/TUI。补齐当前任务冻结材料、真实检查器、返回产物关联、显式 Issue→Apply、持久收据消费与恢复。没有重建 Authority、另加一套任务状态机或通过直接写库推进状态。

### 当前通过的实际路径

| 范围 | 当前结果 | 本机证据批次或日志 |
|---|---|---|
| D01—D07、V03；连续真实任务 | 全新隔离安装后连续创建两个独立 Task，实际 Codex 修改各自任务工作树；第一条接受为 Completed，第二条返工为 Rework；无跨任务身份冲突 | `20260906T114312Z-f68c767e43aa`；`fresh-two-task-accept-rework.log` |
| C01—C03、V04；动态验证 | 两条任务各自产生独立 ArtifactSet、Verification Artifact/Run；固定 scope/tests 检查通过，原生模型 review 的证据不足仍标为 Unverified，整体为 Indeterminate | 同批 `repository-observations.json`；每条 Task 的 `task review` |
| C04；显式用户决定 | CLI 的非 Passed Accept 保存真实风险说明和补偿控制；Rework 保存真实修改要求。Task 状态改变由 Task Authority 执行，精确重试返回原裁决与收据 | 同批两个裁决及重启后 replay |
| C05；TUI 实际入口 | 隐藏 ConPTY 运行实际 TUI，24 个键盘操作检查点通过：创建工作、审阅产物/证据/验证、明确 Reject、看到 Rejected、返回并打开下一项工作表单 | `20260906T114735Z-c7841f32c133` 的 `repository-tui-live-report.json` 与 24 组屏幕记录 |
| V02；同库恢复 | 双任务同密钥、同数据库重启后保留原终态、回答、产物关联、Verification ID；恢复裁决不重新执行模型 | `fresh-two-task-accept-rework.log` |
| C05/V02；TUI 裁决恢复 | 原 TUI Reject 的同一 capsule 精确重试返回原 Task/Verdict；同密钥、同数据库再次重启后保持 ArtifactSet、Artifact 成员、Verification Artifact/Run 和裁决身份 | `tui-preserved-exact-replay.log`；`tui-preserved-same-database-restart.log` |
| V02；未知提交结果 | 保留的 `20260906T101002Z-9256accdfe21` 原真实任务，恢复同一个 Issue/Apply capsule 后确认 Completed；原验证和裁决身份不变 | `preserved-task-exact-recovery.log` |
| V02；未应用裁决到期 | 保留的 `20260906T093029Z-3e6f3dba759e` 旧 Issue 经真实 Policy 授权到期，Task 仍待裁决；新明确 Reject 后同库重启和精确 replay 通过 | `preserved-unapplied-expiry-rejection.log` |
| V02；取消 | 原生审批等待中，经公开入口 Cancel，收敛到 Cancelled、关闭原审批；重启保持，未修改源仓库 | `20260906T093453Z-2cf0f7f8284f`；`repository-live-cancel-resident-stream.log` |
| D08；可操作诊断 | 配置预检、任务状态与受控审批摘要可读；已提交但未知的客户端结果保留精确恢复路径；后台单项恢复拒绝保留 pending 并报告，不终止其他任务 | CLI/TUI 恢复回归及真实保存任务复验 |
| V05；检查覆盖 | Rust gate 已改为覆盖所有 daemon 测试目标；最新全目标运行通过，包含 daemon lib 226、C5 42、生产裁决回执/时钟 5 和并发操作门 1 | `daemon-all-targets-recovery-corrected.log`；完整 local CI 状态另以当前 evidence 为准 |
| 最终本地检查 | 2026-09-06 12:01 UTC 完整 local CI 退出 0；合同/生成/TypeScript、Rust 全目标、Python foundation/contract-bindings/memory-rag 全部通过 | `phase-one-final-local-ci-r8.log`；`.local-ci/evidence/latest.json`，`status=passed`、`worktree_dirty_at_start=true` |

### 必须保留的证据边界

- 原生模型审查没有足够正向证明时仍为 Unverified；本次 Accept 是针对隔离夹具、带明确风险承担的测试决定，不是将 Review 伪造为 Passed，也不是用户批准发布。
- TUI 驱动本身 24 项通过。第一次外围协调脚本在更新进度 JSON 时因 PowerShell 对 `File.Replace(..., $null)` 的参数转换报错；产品已提交 Reject。原现场和失败日志保留，恢复核对沿用同一个 Task，不重做任务制造通过结果。
- 原 C06 规定 Issue 后未提交 Task 的重启不得自动 Apply。本轮后台只恢复已提交收据，或对没有 Task 提交的过期 Issue 执行合法 Policy 到期；用户必须明确提交新决定。
- 新旧业务库、原源码工作区和全部失败现场均保留。Policy 增加 V3 到期授权记录；旧二进制不可直接用于已升级测试库的回退。回退应使用升级前备份或保留原始工作区，不能通过删表或清库隐藏问题。
- 所有真实验证使用隔离仓库和本机固定 Codex 版本；不认证其他供应商、任意项目检查器、生产部署或正式发行包。
- Sego 自动 Hook 与自动上报保持关闭；本轮执行现有窗口的独立代码审阅及正常测试，不计作 Sego 审查通过。
- 当前仍是本地未提交修复；本地候选打包要求干净提交和与该提交匹配的成功 CI。未执行提交、整合、推送、发布或原业务数据迁移。

在这些条件达成前，不应把“模块存在”“单元测试通过”或“模型有回答”表述为一期产品闭环完成。
