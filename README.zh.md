# opencode-privacy

面向 [OpenCode](https://opencode.ai/) 的隐私控制和受限凭据操作插件。

[English](README.md) | [简体中文](README.zh.md)

> 独立社区插件，与 OpenCode 团队没有隶属、背书或官方关联关系。

## 安装

OpenCode 会在启动时使用 Bun 自动安装 npm 插件。发布到 npm 后，在 `opencode.json` 中加入：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-privacy"]
}
```

如果无法连接 npm registry，或 npm 安装失败但 GitHub 可以访问，可以直接使用 Git 仓库作为备用方式：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-privacy@git+https://github.com/heroims/opencode-privacy.git"]
}
```

本地开发时，使用本地构建：

```sh
npm install
npm run check
npm run build
```

然后配置构建后的绝对路径：

```json
{
  "plugin": ["/absolute/path/to/opencode-privacy/dist/plugin.js"]
}
```

OpenCode 也支持 `.opencode/plugins/` 和 `~/.config/opencode/plugins/` 下的本地 JS/TS 插件文件。

## 快速开始

要求 Node.js `>=22.19.0`。macOS 上执行：

```sh
node dist/cli.js init
node dist/cli.js secret add       # 隐藏输入，只输出 secret://...
node dist/cli.js serve            # 保持运行
```

在 `~/.config/opencode-privacy/grants.json` 中添加最小权限授权，然后重启 OpenCode。模型只会使用 `secret://<uuid>` 引用，不会收到真实密码。

## 功能

### 隐私防护

- 检测并脱敏结构化 PII、API Key、Token、JWT 和私钥。
- 处理消息、系统提示、压缩内容、工具结果和可见的 provider `fetch` 请求体。
- 检查 URL、Shell 命令和 `.env`、SSH Key 等敏感文件外发。
- 支持 PII、工具外发和模型降级策略，并在无法安全判断时阻断。
- 对实际经过 guarded `fetch` 的 OpenRouter 请求加入 ZDR 参数。
- 保守报告隐私等级；TEE 只显示 `tee-unverified`。

### 受限凭据操作

- 使用 macOS Keychain 保存不透明 `secret://<uuid>` 引用。
- 通过 owner-only Unix socket 运行本地 broker。
- 将授权绑定到会话、操作、目标、HTTP 方法、请求头和 JSON 字段。
- 提供 `privacy_http`、`privacy_config_read`、`privacy_config_write`。
- 检查重定向、私网地址、符号链接、版本冲突和未授权字段。

## 配置

用户策略文件：`~/.config/opencode-privacy/config.json`。

```json
{
  "piiPolicy": "redact",
  "toolExfilPolicy": "block",
  "downgradePolicy": "block",
  "piiAllow": [],
  "enforceOpenRouterZdr": false,
  "blockAttachments": true,
  "brokerSocket": "/Users/你的用户名/.config/opencode-privacy/broker.sock"
}
```

`piiPolicy` 支持 `off`、`warn`、`redact`、`block`；工具外发和降级策略支持 `off`、`warn`、`block`。关闭 PII 检测不会关闭凭据保护。环境变量 `OPENCODE_PRIVACY_CONFIG` 和 `OPENCODE_PRIVACY_BROKER_SOCKET` 可以指定路径。

broker 读取 `~/.config/opencode-privacy/grants.json`。grant 不支持通配符，必须精确指定 `sessionID`、`operation`、`target` 和 `refs`：

```json
[
  {
    "sessionID": "SESSION_ID",
    "operation": "http",
    "target": "https://api.example.com",
    "refs": ["secret://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],
    "methods": ["GET"],
    "headers": ["authorization"]
  }
]
```

配置文件操作使用单独的 `config.read` 和 `config.write` grant，并列出如 `database.password` 的字段。读取返回 `version`；写入必须携带该版本，并且只能写入凭据引用。

Keychain 写入使用跨进程锁和快照比较。CLI 修改凭据后请重启 broker；若并发修改导致保存失败，重新运行 CLI 命令，或重启 broker 后重试配置读取。旧快照不会自动覆盖新数据。升级到此版本前应先停止旧版 broker 和 CLI 进程，避免旧版写入绕过锁。锁文件位于 `~/.opencode-privacy-keychain.lock`，运行期间不要删除。

## 安全边界

插件和 broker 与 OpenCode 使用同一用户，无法保证抵御恶意同用户插件、任意 Shell、恶意 MCP、本机管理员或旧会话文件中的既有明文。任意 Shell 恢复凭据和任意远程 MCP 凭据转发明确不支持，并会 fail closed。PII 检测是确定性模式匹配，不是语义识别。

## 开发

```sh
npm install
npm run check
npm pack --dry-run
```

测试使用合成凭据和本地 HTTP 服务，验证授权目标能收到原值，而模型内容、broker 错误和审计状态不包含原值。

## 许可证

MIT。移植的 pi-privacy 代码和版权说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
