# opencode-privacy

OpenCode plugin for deterministic privacy controls and scoped credential operations. It uses the OpenCode plugin API and does not modify OpenCode core. [中文说明](README.zh.md)

## Features

- Detects and redacts structured PII and common secrets in messages, system text, compaction text, tool results, and provider request bodies when a provider `fetch` hook is available.
- Blocks sensitive arguments sent through ordinary tools and keeps only bounded tool and policy metadata.
- Wraps exposed provider `fetch` functions. OpenRouter ZDR adds `provider.zdr=true` and `provider.data_collection="deny"`.
- Reports TEE claims conservatively as `tee-unverified`; a plugin cannot cryptographically bind inference TLS without host support.
- Adds `privacy_http`, `privacy_config_read`, and `privacy_config_write` tools.

The model receives opaque references such as `secret://<uuid>`. A real value is restored only inside an explicitly granted operation. There is no raw “resolve secret” tool.

## Install as an OpenCode plugin

OpenCode installs npm plugins automatically with Bun at startup. After this package is published, add the package name directly to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-privacy"]
}
```

Restart OpenCode. There is no separate npm install step for the plugin itself. This repository is not published to npm yet.

For local development, build the package and reference the absolute path:

```sh
npm install
npm run check
npm run build
```

```json
{
  "plugin": ["/absolute/path/to/opencode-privacy/dist/plugin.js"]
}
```

OpenCode also loads local JavaScript or TypeScript files from `.opencode/plugins/` and `~/.config/opencode/plugins/`.

## Initialize and store secrets

Node.js `>=22.19.0` is required. On macOS:

```sh
node dist/cli.js init
node dist/cli.js secret add       # hidden TTY input; prints only secret://...
node dist/cli.js secret list
node dist/cli.js secret remove secret://<uuid>
```

Real values are stored in Keychain. Passwords are rejected when supplied as command-line arguments. The command prints only an opaque reference.

`init` creates `~/.config/opencode-privacy/config.json`, `grants.json`, and the broker socket location. Files are owner-only. Start the broker in a separate terminal:

```sh
node dist/cli.js serve
```

## Configure policy

The user policy file is `~/.config/opencode-privacy/config.json`. `OPENCODE_PRIVACY_CONFIG` and `OPENCODE_PRIVACY_BROKER_SOCKET` can point to explicit paths. A project-local `opencode-privacy.config.json` may tighten policy but cannot turn guards off, add an allowlist, or change the broker.

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

## Configure grants

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

For JSON configuration, grant `config.read` and `config.write` separately and list fields such as `database.password`. `privacy_config_read` returns a `version`; `privacy_config_write` requires that version and accepts only references. A configuration file that must contain a real password remains sensitive.

`SESSION_ID` must be the current OpenCode session ID. Restart the broker after editing grants.

## Typical flow

1. Run `secret add` and keep the returned `secret://...` reference.
2. Add a narrowly scoped grant for the session, target, operation, and fields.
3. Start `node dist/cli.js serve`.
4. Add `opencode-privacy` to OpenCode's plugin list, or use the local `dist/plugin.js` path during development.
5. Ask the model to call `privacy_config_read`, `privacy_config_write`, or `privacy_http`.
6. The destination may receive the real credential; the model, ordinary tools, transcript, and broker errors receive only references or sanitized output.

Use `privacy_status` to inspect policy, observed tools, provider transport coverage, and broker connectivity.

## Security boundary

This is same-user plugin code. It cannot guarantee protection from malicious same-user plugins, arbitrary shell programs, malicious MCP servers, a local administrator, or secrets already written to old session files. Arbitrary shell credential restoration and arbitrary remote MCP credential forwarding are intentionally unsupported and fail closed. PII detection is deterministic pattern matching, not semantic classification.

See [docs/coverage.md](docs/coverage.md) for the supported, partial, and explicitly unsupported feature matrix.

## Development

```sh
npm run check
npm pack --dry-run
```

The test suite uses synthetic credentials and local HTTP servers. It verifies that authorized destinations receive the original value while model-like output, broker errors, and audit state do not.
