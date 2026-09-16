# opencode-privacy（中文）

这是一个通过 OpenCode 插件 API 工作的隐私插件，不修改 OpenCode 核心。英文主文档见 [README.md](README.md)。

## 功能

- 检测并脱敏结构化 PII、API Key、Token、JWT、私钥等。
- 处理消息、系统提示、压缩文本、工具结果，以及 provider 暴露的 `fetch` 请求体。
- 阻止普通工具把敏感参数发送到外部地址。
- OpenRouter 请求可加入 `provider.zdr=true` 和 `provider.data_collection="deny"`。
- TEE 只显示 `tee-unverified`，不会把供应商声明当成密码学验证。
- 提供 `privacy_http`、`privacy_config_read`、`privacy_config_write` 三个受控工具。

模型只看到 `secret://<uuid>` 形式的引用。真实值只会在通过授权的操作内部短暂恢复，没有任意“解析密码”工具。

## 按 OpenCode 插件模式安装

发布到 npm 后，OpenCode 会在启动时用 Bun 自动安装插件。在 `opencode.json` 中加入包名：

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-privacy"]
}
```

重启 OpenCode 即可。当前仓库尚未发布到 npm。

开发阶段使用本地构建：

```sh
npm install
npm run check
npm run build
```

然后配置绝对路径：

```json
{
  "plugin": ["/absolute/path/to/opencode-privacy/dist/plugin.js"]
}
```

OpenCode 也支持 `.opencode/plugins/` 和 `~/.config/opencode/plugins/` 下的本地 JS/TS 插件文件。

## 初始化和保存凭据

要求 Node.js `>=22.19.0`。macOS 上执行：

```sh
node dist/cli.js init
node dist/cli.js secret add
node dist/cli.js secret list
node dist/cli.js secret remove secret://<uuid>
```

`secret add` 使用隐藏 TTY 输入，命令行参数中的密码会被拒绝。真实值保存在 macOS Keychain，终端只显示引用。

初始化后会生成：

```text
~/.config/opencode-privacy/
├── config.json
├── grants.json
└── broker.sock
```

另开终端启动 broker：

```sh
node dist/cli.js serve
```

## 配置策略

编辑 `~/.config/opencode-privacy/config.json`：

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

- `piiPolicy`：`off`、`warn`、`redact`、`block`。
- `toolExfilPolicy`：`off`、`warn`、`block`。
- `downgradePolicy`：`off`、`warn`、`block`。
- `piiAllow`：明确允许的 PII 例外；项目配置不能追加。
- `enforceOpenRouterZdr`：是否给实际经过 guarded `fetch` 的 OpenRouter 请求加入 ZDR 约束。
- `blockAttachments`：是否拒绝无法安全检查的附件。

也可以设置：

```sh
export OPENCODE_PRIVACY_CONFIG="$HOME/.config/opencode-privacy/config.json"
export OPENCODE_PRIVACY_BROKER_SOCKET="$HOME/.config/opencode-privacy/broker.sock"
```

## 配置 grants.json

每条 grant 都绑定精确的 `sessionID`、`operation`、`target` 和 `refs`。

### HTTP 授权

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

这只允许指定会话对指定 HTTPS origin 发起 `GET`，并且只能在 `authorization` 请求头使用该引用。默认禁止重定向和私网地址；本地测试才使用 `allowHTTPForTests`，可信私网才使用 `allowPrivateNetwork`。

### JSON 配置读写

读写需要分开授权，并限制字段：

```json
[
  {
    "sessionID": "SESSION_ID",
    "operation": "config.read",
    "target": "/Users/你/project/config.json",
    "refs": [],
    "fields": ["database.password"]
  },
  {
    "sessionID": "SESSION_ID",
    "operation": "config.write",
    "target": "/Users/你/project/config.json",
    "refs": ["secret://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"],
    "fields": ["database.password"]
  }
]
```

模型先调用 `privacy_config_read`，取得字段引用和 `version`；再将引用和版本传给 `privacy_config_write`。写入会检查版本、拒绝符号链接并原子替换文件。目标配置文件可能含真实密码，必须按敏感文件保护。

`SESSION_ID` 必须是当前 OpenCode 会话 ID。修改 grants 后重启 broker。

## 使用流程

1. `secret add` 保存凭据并得到 `secret://...`。
2. 在 `grants.json` 写入最小权限授权。
3. 启动 `node dist/cli.js serve`。
4. 在 OpenCode 中加载 `opencode-privacy` npm 插件或本地 `dist/plugin.js`。
5. 让模型调用 `privacy_config_read`、`privacy_config_write` 或 `privacy_http`。
6. 目标服务可以收到真实值；模型、普通工具、会话记录和错误信息只看到引用或脱敏结果。

使用 `privacy_status` 查看当前策略、已观察工具、provider 覆盖范围和 broker 连接状态。

## 安全边界

这是与 OpenCode 同一用户运行的插件，不能保证抵御恶意同用户插件、任意 shell、恶意 MCP、本机管理员或旧会话文件中的既有明文。任意 shell 恢复凭据和任意远程 MCP 凭据转发明确不支持，并会 fail closed。PII 检测是确定性模式匹配，不是语义识别。

完整覆盖情况见 [docs/coverage.md](docs/coverage.md)。
