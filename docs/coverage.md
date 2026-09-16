# 功能覆盖矩阵

以下状态针对“不修改 OpenCode 核心”的插件实现。

| 能力 | 状态 | 说明 |
|---|---|---|
| 结构化 PII / secret 检测 | 已支持 | 复用 pi-privacy 0.14.1 的 MIT 代码，并加中文手机号与凭据字段规则 |
| 消息、系统、压缩、工具结果脱敏 | 已支持（钩子范围） | 在 OpenCode 插件钩子可见的数据上处理 |
| 最终模型请求脱敏 | 部分支持 | 通过 provider `fetch` 包装；未暴露 fetch 的供应商无法声明覆盖 |
| 工具外发检查 | 部分支持 | 命令和 URL 是启发式判断；未知程序副作用无法静态保证 |
| PII warn / redact / block | 已支持 | 无交互批准时采用安全脱敏或阻断 |
| 工具结果凭据脱敏 | 已支持（可重建对象） | 附件和未知媒体默认拒绝 |
| 模型降级保护 | 部分支持 | 在 `chat.params` 观察到的供应商等级之间阻断；不能观察的内部请求不声明覆盖 |
| 本地端点识别 | 已支持（可观察） | loopback 只证明地址，不证明背后没有转发 |
| OpenRouter ZDR | 部分支持 | 实际 guarded fetch 添加约束；需通过该 provider fetch 才能标记 observed |
| TEE 证明 | 明确不支持验证结论 | 只显示 `tee-unverified`，不把上游报告解析器升级为 verified |
| 工具来源 / surface | 部分支持 | 记录插件可见的工具名；未知来源标记 unknown |
| 会话 PII 开关 | 部分支持 | 用户配置控制，插件没有模型可调用的降级 RPC |
| 项目配置安全底线 | 已支持 | 项目文件不能关闭用户保护、增加 allowlist 或改 broker |
| 凭据引用 | 已支持 | Keychain、owner-only socket、精确 grant、输出清洗 |
| 受控 HTTP 操作 | 已支持 | HTTPS、目标/方法/头绑定、禁止重定向、DNS 私网检查 |
| 受控 JSON 配置 | 已支持 | 字段白名单、版本校验、符号链接检查、原子写入 |
| 任意 shell 恢复凭据 | 明确不支持 | 不能安全地把真实值插入任意 shell 字符串 |
| 任意远程 MCP 恢复凭据 | 明确不支持 | 远程服务收到明文即是显式披露，需单独适配 |

## 验证记录

本地单元、集成和构建检查：31 项通过（`npm run check`）。`npm pack --dry-run` 成功。

2026-09-16 回归验证覆盖带双引号的敏感文件外发、JSON 文本凭据（含转义和数组标点）、凭据快照冲突，以及 OpenCode 宿主传入的非普通 JSON Schema 对象。Keychain 数据读写使用注入的 runner 测试，未操作真实用户 vault；Swift helper 已通过类型检查，原生锁已在临时文件上验证并发拒绝、进程退出释放、权限和符号链接拒绝。随后在真实 macOS 登录钥匙串中使用合成值完成写入、重载、删除和清理。

使用真实 OpenCode 1.18.31 和当前账号配置，在临时项目配置中完成了 `opencode/big-pickle` 与 `opencode/ling-3.0-flash-fin-free` 两次非交互会话。两者均成功加载插件并完成模型请求；Big Pickle 对要求原样重复的 GitHub token 返回了 `«token»`，未返回原值。

OpenCode 1.18.31 隔离宿主烟测未在 90 秒内形成有效 fixture 模型会话，因而没有把宿主端到端集成标为通过；它也没有捕获到模型请求或敏感值外发。需要用实际 OpenCode 配置和可用模型供应商继续验证 provider `fetch` 的运行时接入。
