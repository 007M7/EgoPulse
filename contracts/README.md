# V-01 Gate 3 contract candidates v0.1

本目录是治理仓库中的机器可读设计候选，不是 EgoPulse 实现期合同唯一事实源。

- 当前候选：C-00 common wire primitives、C-01 Task、C-02 Collaboration、C-03 Harness Adapter、C-04 Artifact/Claim/Evidence/ReturnHandoff、C-05 Verification、C-06 FounderVerdict、C-07 Local API/Read Model、C-08 Persistence/Recovery。
- 当前状态：C-01—C-07 `founder_confirmed / toolchain_pending`；C-08 `candidate_ready / awaiting_founder_decision / toolchain_pending`。
- 本地校验：`node scripts/validate-candidate.js`。
- 本地校验不替代 Buf lint/breaking、protoc 编译或 Rust/TypeScript/Python 生成测试。
- Gate 3 通过且 Gate 4 建立隔离现场后，按 `manifest.json` digest 精确导入 `EgoPulse/contracts/`；导入校验后由后者成为实现期唯一机器合同源。
