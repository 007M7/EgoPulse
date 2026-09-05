# EgoPulse 产品使用模型审查

- 日期：2026-08-27
- 状态：待 Founder 审核；不是冻结架构或合同变更
- 范围：首版 Windows x64 的 CLI/TUI 用户使用逻辑
- 明确暂停：Desktop 产品设计、Desktop 新功能和 Desktop 验收

## 1. 这次审查要解决的问题

EgoPulse 的确定性控制平面已经具备 Task、Collaboration、Approval、Artifact、
Verification、Founder Verdict 和 Memory Authority 的实现边界。但当前 CLI/TUI
入口主要暴露的是这些内部治理命令，而不是用户真正想完成的工作。

用户的目标应当是：

> 把一个工作意图交给本地 Agent OS，在可控的权限边界内由合适的模型和 Harness
> 执行，用户能够看到进度、处理必要审批、审阅结果，并决定是否接受结果以及是否
> 将可复用信息纳入 Memory。

因此，当前需要先冻结的是“用户如何使用产品”的产品模型，而不是继续增加一个
展示面。

## 2. 事实账本

### 2.1 已由仓库和本地证据确认的事实

| 领域 | 当前事实 |
| --- | --- |
| 产品形态 | 本地运行、用户自带 API Key（BYOK）的 Founder-controlled Agent OS |
| 首发范围 | Windows x64；CLI/TUI 包已完成本地打包验证；Desktop 暂不纳入当前首发工作流 |
| 运行内核 | CLI、TUI 共享同一个 Rust Client Kernel、Local API 和 agentosd 控制平面 |
| 权威事实 | Rust Authority 模块拥有 Task、Collaboration、Artifact、Verification、Verdict 和 Memory 的写入权 |
| 模型协作 | Provider、Harness、Model 是独立概念；当前 Codex 是唯一生产准入 Harness，其余仍是候选/held |
| Memory | Agent/Model/Harness 只能提交 candidate；Founder 或治理动作才能 accept/revoke；检索默认 lexical baseline |
| 当前入口 | `task create`、`approval decide`、`verdict issue`、`memory candidate/accept/revoke` 等低层命令 |
| 当前合同 | 已冻结合同包含 revision、digest、snapshot、evidence 和 idempotency 等协议级字段 |

### 2.2 尚未被产品决策确认的事实

| 问题 | 当前状态 | 影响 |
| --- | --- | --- |
| 用户首要任务 | 尚未用一个首要场景定义 | 决定首个 `run/work` 入口的语义 |
| 工作单位 | 既有 Task 是治理对象，不等于用户理解的工作会话 | 决定 Task 与 Session 的产品分层 |
| 模型选择 | 已有配置和候选路由边界，但没有最终用户选择流程 | 决定首次配置和每次工作的交互 |
| 审批时机 | 内部 Approval 已存在，但用户何时被打断尚未产品化 | 决定工作流是否连续、哪些操作必须暂停 |
| 结果接受 | Founder Verdict 已实现，但用户如何看到“可接受结果”尚未定义 | 决定结果页/终态和 rework 入口 |
| Memory 使用方式 | 治理边界明确，用户日常使用方式尚未明确 | 决定 Memory 是自动建议收件箱还是主动知识库 |
| 恢复方式 | 内部 recovery 事实存在，用户如何恢复未定义 | 决定 CLI/TUI 的 resume/retry/recover 入口 |

## 3. 当前产品逻辑的主要偏差

### 3.1 内部协议字段被当成用户输入

当前 `task create` 要求用户提供：

- `input_snapshot_id`；
- acceptance contract 的 ID、version、SHA-256；
- budget profile 的 ID、version、SHA-256；
- 以及后续流程中的 revision、observation sequence、artifact manifest digest、
  verification payload digest 和 idempotency key。

这些字段对 Authority 的确定性和幂等性是必要的，但不应成为普通用户的工作入口。
它们应由系统根据用户的工作意图、工作区、已选能力和当前策略生成、绑定并在需要时
展示为诊断信息。

### 3.2 当前入口从“治理动作”开始，而不是从“工作意图”开始

用户不会先想“创建一个绑定验收合同哈希的 Task”，而是想：

- 分析这个项目并给出修改方案；
- 在指定工作区实现一个功能；
- 检查当前代码并运行验证；
- 读取已有记忆后继续上一次工作。

现有 Authority 闭环可以正确承载这些行为，但缺少一个把自然语言工作意图转化为
内部 Task/Run/Step/Policy 的产品入口。

### 3.3 Memory 治理动作和 Memory 日常使用混在一起

`memory candidate`、`memory accept`、`memory revoke` 是治理操作，不是用户每天的
主要工作方式。正常流程应当是工作过程中产生候选记忆，用户在明确的候选收件箱中
审阅，接受后才进入 accepted snapshot；日常工作只读取已接受记忆，不要求用户手工
拼装 source ref、revision 和 evidence ref。

### 3.4 Provider/Harness/Model 的工程边界尚未转译成用户概念

工程上必须区分 Provider、Harness 和 Model；用户侧可以只看到：

- 使用哪个模型能力；
- 当前是否已配置并可用；
- 本次工作使用了什么确切模型；
- 是否允许系统按已批准策略选择模型。

工程身份、协议指纹和 admission digest 应留在系统事实与诊断层，不能要求用户在
普通工作命令中填写。

## 4. 建议的首版用户心智模型

EgoPulse 首版只需要让用户理解四件事：

1. **工作**：我想让 Agent 完成什么，以及在哪个工作区完成。
2. **能力**：这次工作使用哪个已配置的 Provider/Model/Harness，或者交给已批准策略选择。
3. **授权**：遇到高风险动作时，系统会暂停并向我请求批准。
4. **结果与记忆**：我审阅工作结果；有价值的信息作为候选 Memory 由我决定是否保存。

用户不需要理解 Authority 的分库、outbox、revision、digest 或 Worker 进程才能完成
一次工作。高级诊断仍可保留，但必须与主工作入口分开。

## 5. 建议的单次工作闭环

以下是待 Founder 审核的产品使用基线，不是新的合同定义：

```text
用户提出工作意图
        |
        v
选择/确认工作区与能力策略
        |
        v
系统生成内部 Work Request / Task / 输入快照 / 合同绑定
        |
        v
读取授权范围内的 accepted Memory
        |
        v
模型/Harness 制定并执行工作步骤
        |
        +--> 需要高风险授权 --> 用户批准/拒绝 --> 继续或终止
        |
        v
产出 Artifact + Evidence，并由 Sego/Checker 验证
        |
        v
用户查看结果：接受 / 要求返工 / 取消
        |
        v
候选 Memory 进入治理收件箱
        |
        +--> 用户接受 --> 写入 accepted Memory snapshot
        +--> 用户拒绝/撤销 --> 保持非权威或进入 revoked
```

### 5.1 用户必须提供的内容

首版普通工作入口原则上只要求：

- 工作意图或任务描述；
- 工作区/项目目录；
- 能力选择：默认策略或明确的已配置模型；
- 可选的风险/自动批准策略；
- 在结果阶段作出接受、返工或取消决定。

### 5.2 系统必须自动生成或维护的内容

- 输入快照和工作版本；
- acceptance contract、budget profile 及其 digest；
- Task/Run/Step/Attempt 的内部 revision；
- Provider/Harness/Model 的精确路由绑定；
- Approval observation、Action digest 和确认关联；
- Artifact、Evidence、Verification 和 Founder Verdict 的引用链；
- Memory candidate 的 source/evidence 绑定、幂等键和审计记录。

### 5.3 用户必须能够看见但不必填写的内容

- 当前使用的确切 Provider/Model/Harness；
- 当前工作状态和下一步等待原因；
- 需要批准的具体动作及风险；
- 产出的文件、验证结论和失败原因；
- Memory 候选的内容、来源、影响范围和接受/拒绝原因；
- 恢复、返工或回滚的可用选择。

## 6. CLI、TUI 的产品分工

两端共享能力和一个内核，但不要求相同的交互形态。

### CLI：首选的可组合工作入口

CLI 应优先支持少量高价值用户动作：

```text
egopulse setup                 # 首次配置和能力就绪检查
egopulse run "工作意图"         # 创建并运行一次工作
egopulse status <work>         # 查看工作状态
egopulse approve <request>     # 处理一次明确的审批请求
egopulse result <work>         # 查看结果、证据和验证摘要
egopulse accept|rework|cancel   # 处理工作终态
egopulse memory review         # 审阅候选 Memory
egopulse resume <work>         # 恢复可恢复的工作
```

这里的命令名只是产品语义草案，不能直接视为已批准的合同或实现任务。现有低层
`task`、`approval`、`verdict`、`memory` 命令可以保留为高级/诊断接口，供测试、
自动化和故障恢复使用。

### TUI：同一工作流的持续观察与交互面

TUI 的核心不是再造一套能力，而是把一次工作持续呈现为：

```text
当前工作
  -> 进度与步骤
  -> 待处理审批
  -> 结果与证据
  -> Memory 候选收件箱
  -> 恢复/返工/取消
```

TUI 可以提供快捷操作、实时状态和候选审阅；所有写入仍经由共享 Client Kernel、
Local API 和对应 Authority。

## 7. 内部对象与用户对象的映射

| 用户概念 | 内部承载 | 用户是否直接填写内部字段 |
| --- | --- | --- |
| 工作意图 | Task input / input snapshot | 否，用户填写自然语言和工作区 |
| 一次工作 | Task + Collaboration Run | 否，系统创建并绑定 |
| 执行步骤 | Step + Attempt + Harness dispatch | 否 |
| 模型能力 | Provider profile + Harness + exact model | 只选择已就绪能力，不填写 digest |
| 安全询问 | Policy + Approval projection | 用户只作批准/拒绝 |
| 工作产物 | Artifact set + Evidence graph | 用户查看，不手工组装引用 |
| 验证结果 | Verification artifact | 用户查看结论和证据 |
| 接受结果 | Founder Verdict | 用户作接受/返工/取消决定 |
| 记忆建议 | Memory candidate | 用户审阅内容与来源 |
| 长期记忆 | accepted Memory snapshot | 用户通过治理动作接受或撤销 |

## 8. 对现有六阶段计划的影响

### 不变的部分

- Rust Authority、单写者、Local API、共享 Client Kernel 和跨语言合同继续保留。
- Provider/Harness/Model 的精确绑定和独立准入规则继续保留。
- Memory 的 candidate → accepted/revoked 治理继续保留。
- CLI/TUI 仍然是共享内核的两个不同表面。
- Desktop 不应成为首版产品使用逻辑的前置条件。

### 必须调整的部分

- 阶段五的首要任务从“补齐三端表面”改为“完成 CLI/TUI 的用户工作流门面”。
- 需要增加一个产品级 Work/Session Facade，把用户意图映射到现有内部 Authority。
- 内部协议命令与用户命令必须分层；不能为了复用已有命令而强迫用户提供协议字段。
- Provider 配置、能力就绪、选择和工作内精确路由需要形成一次性配置 + 每次工作确认的流程。
- Memory 需要优先实现“工作后候选收件箱”的用户流程，而不是继续扩展裸的 mutation 参数。
- Desktop 仅在 CLI/TUI 的工作流、恢复、审批、结果和 Memory 收件箱被验证后再重新评估。

## 9. 后续工作顺序（待 Founder 审核）

1. 选定首个主场景：例如“在指定项目中完成一个受治理的代码工作”。
2. 明确一次工作从开始到结束的用户状态和用户决策点。
3. 明确首次配置、Provider/Model 选择和缺失凭证时的行为。
4. 明确审批只在什么风险边界触发，以及用户看到什么信息。
5. 明确结果接受、返工、取消、失败和恢复的用户语义。
6. 明确 Memory 候选如何从工作结果进入审阅收件箱。
7. 设计用户级 CLI/TUI 命令草案，并映射到现有内部合同；需要新增合同时单独提交 ADR。
8. 先实现 CLI 用户闭环，再实现 TUI 的同能力持续交互。
9. 用一名新用户完成从安装、配置、首次工作到结果接受和 Memory 审阅的本地 E2E。
10. 只有上述闭环稳定后，才重新讨论 Desktop 是否需要进入首发包。

## 10. 目前不应推进的事项

- 不继续增加 Desktop 页面、按钮或 GUI 自动化。
- 不把现有低层命令直接包装成“产品已经可用”的证据。
- 不在 Founder 未确认用户主场景前冻结 `Work Request` 或 `Work Session` 新合同。
- 不因 CLI/TUI 入口缺少产品门面而削弱 Authority、审批或 Memory 治理。
- 不把 Provider 候选准入、语义 RAG 实验结果或 Desktop 二进制存在误报为首版用户能力。

## 11. 审核结论

当前结论是：**内核工程闭环已先于产品使用闭环完成**。下一步不是继续做
Desktop，而是由 Founder 确认首个真实工作场景和一次工作中的用户决策点；确认后，
再把现有确定性内核包装成用户可理解、可操作、可恢复的 CLI/TUI 工作入口。

