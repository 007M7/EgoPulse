# EgoPulse 本地配置

`agentos-config.example.json` 是首个本地生产启动配置的模板。它只包含路径、合同引用、工作流和环境变量名；真实密钥不进入 JSON，也不应提交到 Git。

使用时复制模板到用户数据目录，替换所有 `replace-*` 占位值，并设置：

```powershell
$env:EGOPULSE_USER_CONFIG = "D:\\EgoPulse\\data\\agentos-config.json"
```

配置中的六个 Authority 密钥必须由对应的环境变量提供，值是非零的 32 字节十六进制字符串：

- `EGOPULSE_TASK_KEY_HEX`
- `EGOPULSE_VERIFICATION_KEY_HEX`
- `EGOPULSE_POLICY_KEY_HEX`
- `EGOPULSE_VERDICT_KEY_HEX`
- `EGOPULSE_ADAPTER_KEY_HEX`
- `EGOPULSE_COLLABORATION_KEY_HEX`

守护进程的读模型和本地会话还需要：

- `EGOPULSE_READ_MODEL_KEY_HEX`
- `EGOPULSE_TOKEN_MAC_KEY_HEX`

`EGOPULSE_READ_MODEL_DB`、`EGOPULSE_READ_MODEL_EPOCH`、`EGOPULSE_IPC_INSTANCE`、`EGOPULSE_SESSION_TTL_SECONDS` 和 `EGOPULSE_HARNESS_DISPATCH_INTERVAL_MS` 可以使用默认值，也可以按本地安装覆盖。

当前配置加载会严格拒绝未知字段、缺失密钥、非法密钥、策略引用不一致和非 `EGOPULSE_*_KEY_HEX` 的密钥变量名。Verification 仍由生产启动边界拒绝未审核的 Sego/checker 引用；这是安全门，不是可通过配置绕过的开关。
