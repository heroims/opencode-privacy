# opencode-privacy

OpenCode plugin for local, deterministic privacy checks and scoped credential operations. It works through the OpenCode plugin API and does not modify OpenCode core.

## 中文说明

### 功能

- 在消息、系统提示、压缩内容、工具结果和可拦截的 provider 请求中检测并替换常见 PII、API Key、Token、JWT、私钥等。
- 阻止普通工具把敏感参数发往外部地址；记录工具名称和策略结果，不记录原始请求体。
- 当 OpenCode 暴露 provider `fetch` 时包装最终请求。OpenRouter ZDR 会加入 `provider.zdr=true` 和 `provider.data_collection="deny"`。
- 以保守方式展示隐私等级。TEE 供应商默认为 `tee-unverified`，不会把供应商自称当成密码学验证结果。
- 提供三个受控工具：`privacy_http`、`privacy_config_read`、`privacy_config_write`。

模型看到的是引用，例如 `secret://8f3c...-uuid`。真实值只在 broker 的受控操作内部恢复。普通 `bash`、`read` 或任意 MCP 工具不能请求“读取真实密码”。

### 安装和构建

要求 Node.js `>=22.19.0`。在项目目录执行：

```sh
npm install
npm run check
npm run build
```

构建后插件入口是 `dist/plugin.js`。

### 初始化本地目录

```sh
node dist/cli.js init
```

这会创建以下目录和文件（如果 `config.json` 已存在则不会覆盖）：

```text
~/.config/opencode-privacy/
├── config.json       # 用户策略和 broker socket 路径，权限 0600
├── grants.json       # 明确授权的会话、目标和字段，权限 0600
└── broker.sock       # 启动 broker 后创建，权限 0600
```

默认 `config.json`：

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

策略值说明：

| 配置项 | 可选值 | 作用 |
|---|---|---|
| `piiPolicy` | `off` / `warn` / `redact` / `block` | 模型上下文中的结构化 PII；凭据检测不会被 `off` 关闭 |
| `toolExfilPolicy` | `off` / `warn` / `block` | 工具外发检查；敏感外发默认阻断 |
| `downgradePolicy` | `off` / `warn` / `block` | 会话切换到更弱隐私等级的模型时处理 |
| `piiAllow` | 字符串数组 | 只允许明确的 PII 例外；项目配置不能增加此列表 |
| `enforceOpenRouterZdr` | `true` / `false` | 只对实际经过 guarded `fetch` 的 OpenRouter 请求施加 ZDR |
| `blockAttachments` | `true` / `false` | 默认拒绝插件无法安全检查的图片、音频和文件附件 |

也可以使用环境变量指定配置：

```sh
export OPENCODE_PRIVACY_CONFIG="$HOME/.config/opencode-privacy/config.json"
export OPENCODE_PRIVACY_BROKER_SOCKET="$HOME/.config/opencode-privacy/broker.sock"
```

### 保存凭据

不要把密码放在命令行参数、聊天消息、`.env` 或普通环境变量中。使用隐藏 TTY 输入：

```sh
node dist/cli.js secret add
# 输出：secret://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

macOS 使用 Keychain 保存真实值。命令只输出引用，不输出密码。查看和删除引用：

```sh
node dist/cli.js secret list
node dist/cli.js secret remove secret://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 配置 grants.json

broker 只接受精确授权。每条 grant 至少绑定：`sessionID`、`operation`、`target` 和 `refs`。

HTTP 示例：

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

这条授权只允许指定会话访问指定 HTTPS origin，并且只能在 `authorization` 请求头使用该引用。`target` 是 origin，不包含路径、查询参数或凭据。默认只允许 HTTPS；测试本地 HTTP 服务时才使用 `allowHTTPForTests: true`，私网地址还需要显式 `allowPrivateNetwork: true`。

JSON 配置文件读写需要分别授权：

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

模型先调用 `privacy_config_read` 得到字段引用和 `version`，再把引用传给 `privacy_config_write`。写入会检查版本、拒绝符号链接，并使用临时文件和原子替换。目标配置文件本身可能包含真实密码，必须按敏感文件保护。

`SESSION_ID` 必须是当前 OpenCode 会话 ID。修改 `grants.json` 后重启 broker。broker 不提供任意“解析引用为明文”的 RPC。

### 启动 broker 和加载插件

```sh
node dist/cli.js serve
```

把绝对路径加入 OpenCode 配置的 `plugin` 数组：

```json
{
  "plugin": ["/Users/你/opencode-privacy/dist/plugin.js"]
}
```

启动 broker 后重新启动 OpenCode。首次使用建议调用 `privacy_status`，检查策略、观察到的工具、provider fetch 覆盖范围和 broker 是否已连接。

典型流程：

1. `secret add` 保存账户、密码或 API Key，得到 `secret://...`。
2. 在 `grants.json` 写入精确的会话、目标、操作和字段授权。
3. 启动 `node dist/cli.js serve`。
4. 在 OpenCode 中让模型调用 `privacy_config_read`、`privacy_config_write` 或 `privacy_http`。
5. 真实目标收到原值；模型、普通工具结果、审计状态和错误信息只收到引用或脱敏结果。
6. 任务结束后删除 grant 或 `secret remove`，再重启 broker。

## English

`opencode-privacy` is an OpenCode plugin for deterministic local privacy controls and scoped credential operations. It uses the OpenCode plugin API and does not patch OpenCode core.

It detects and redacts structured PII and common secrets in messages, system text, compaction text, tool results, and provider request bodies when a provider `fetch` hook is available. It blocks sensitive ordinary-tool arguments, wraps exposed provider fetch functions, adds OpenRouter ZDR parameters, and reports TEE claims conservatively as `tee-unverified`.

The model receives opaque references such as `secret://<uuid>`. A real value is restored only inside an explicitly granted operation. There is no raw “resolve secret” tool.

### Install

Node.js `>=22.19.0` is required:

```sh
npm install
npm run check
npm run build
```

Add the absolute path to `dist/plugin.js` to OpenCode's `plugin` array.

### Initialize and store secrets

```sh
node dist/cli.js init
node dist/cli.js secret add       # hidden TTY input; prints only secret://...
node dist/cli.js secret list
node dist/cli.js secret remove secret://<uuid>
```

On macOS, real values are stored in Keychain. Passwords are rejected when supplied as command-line arguments. `config.json`, `grants.json`, and the Unix socket are owner-only.

### Configure policy

The user file is `~/.config/opencode-privacy/config.json`. Environment variables `OPENCODE_PRIVACY_CONFIG` and `OPENCODE_PRIVACY_BROKER_SOCKET` can point to explicit paths. Project-local `opencode-privacy.config.json` may tighten policy but cannot turn guards off, add an allowlist, or change the broker.

```json
{
  "piiPolicy": "redact",
  "toolExfilPolicy": "block",
  "downgradePolicy": "block",
  "piiAllow": [],
  "enforceOpenRouterZdr": false,
  "blockAttachments": true,
  "brokerSocket": "/Users/you/.config/opencode-privacy/broker.sock"
}
```

Use `off`, `warn`, `redact`, or `block` for `piiPolicy`; `off`, `warn`, or `block` for tool and downgrade policies. Turning PII off never disables credential protection.

### Configure grants

Edit `~/.config/opencode-privacy/grants.json` with exact `sessionID`, `operation`, `target`, and `refs` values. HTTP grants additionally list allowed methods and header names. Configuration grants list exact dotted JSON fields. The broker rejects unknown references, wrong sessions, wrong targets, redirects, symlinks, stale versions, and unapproved headers.

HTTP example:

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

For JSON configuration, grant `config.read` and `config.write` separately and list fields such as `database.password`. `privacy_config_read` returns a `version`; `privacy_config_write` requires that version and accepts only references.

### Start and use the broker

```sh
node dist/cli.js serve
```

Restart the broker after editing grants. In OpenCode, use `privacy_status` to inspect policy, observed tools, provider transport coverage, and broker connectivity. Then ask the model to use a scoped privacy tool. The destination may receive the real credential, while the model and ordinary transcript remain reference-only.

### Security boundary

This is same-user plugin code. It cannot guarantee protection from malicious same-user plugins, arbitrary shell programs, malicious MCP servers, a local administrator, or secrets already written to old session files. Arbitrary shell credential restoration and arbitrary remote MCP credential forwarding are intentionally unsupported and fail closed. PII detection is deterministic pattern matching, not semantic classification. A configuration file that must contain a real password remains sensitive.

## Development / 开发

```sh
npm run check
npm pack --dry-run
```

The test suite uses synthetic credentials and local HTTP servers. It verifies that authorized destinations receive the original value while model-like output, broker errors, and audit state do not. See [docs/coverage.md](docs/coverage.md) for the supported, partial, and explicitly unsupported feature matrix.
