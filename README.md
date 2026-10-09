# opencode-privacy

Privacy controls and scoped credential operations for [OpenCode](https://opencode.ai/).

[English](README.md) | [简体中文](README.zh.md)

> An independent community plugin. It is not built by, endorsed by, or affiliated with the OpenCode team.

## Installation

OpenCode installs npm plugins automatically with Bun at startup. Add the package to your OpenCode configuration:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-privacy"]
}
```

If the npm registry cannot be reached or the npm package install fails, and GitHub is reachable, install the repository directly from Git:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-privacy@git+https://github.com/heroims/opencode-privacy.git"]
}
```

For local development from a checkout:

```sh
npm install
npm run check
npm run build
```

Then reference the built plugin by absolute path:

```json
{
  "plugin": ["/absolute/path/to/opencode-privacy/dist/plugin.js"]
}
```

OpenCode also loads local plugins from `.opencode/plugins/` and `~/.config/opencode/plugins/`.

## Quick start

Node.js `>=22.19.0` is required. On macOS, create the local credential workspace and start its broker:

```sh
node dist/cli.js init
node dist/cli.js secret add       # hidden TTY input; prints only secret://...
node dist/cli.js serve            # keep this process running
```

Add a narrow grant to `~/.config/opencode-privacy/grants.json`, then restart OpenCode. The model can use the returned `secret://<uuid>` reference through a permitted privacy tool; it never receives a raw secret.

## What it provides

### Privacy enforcement

- Deterministic detection and redaction for structured PII and common secrets.
- Message, system, compaction, tool-result, and provider-fetch hook coverage.
- Sensitive tool-egress checks for URLs, shell commands, and credential-file references.
- PII, tool-egress, and model-downgrade policies with fail-closed behavior.
- OpenRouter ZDR request patching when the provider exposes a guarded `fetch` path.
- Conservative posture reporting; TEE claims remain `tee-unverified`.

### Scoped credentials

- Opaque `secret://<uuid>` references backed by macOS Keychain.
- Owner-only local Unix socket broker.
- Grants bound to session, operation, target, HTTP method, request header, and JSON field.
- `privacy_http` for explicitly authorized HTTPS calls.
- `privacy_config_read` and `privacy_config_write` for field-scoped JSON configuration updates.
- Redirect, private-network, symlink, version-conflict, and unapproved-field checks.

## Configuration

User policy is stored at `~/.config/opencode-privacy/config.json`:

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

Use `off`, `warn`, `redact`, or `block` for `piiPolicy`; use `off`, `warn`, or `block` for tool-egress and downgrade policies. Turning PII off does not turn off credential protection.

The broker reads `~/.config/opencode-privacy/grants.json`. Grants are exact and do not support wildcard sessions or targets:

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

Grant lists and operation-specific fields are validated before startup. Network exceptions require actual JSON booleans; strings such as `"false"` are rejected. Duplicate session/operation/target grants are rejected; combine their permissions into one grant.

For configuration files, use separate `config.read` and `config.write` grants with exact dotted fields such as `database.password`. `privacy_config_read` returns a version; `privacy_config_write` requires that version and accepts only references.

Keychain writes use a process lock and snapshot comparison. Restart the broker after changing credentials with the CLI. If concurrent changes cause a save to fail, rerun the CLI command or restart the broker before retrying a configuration read. Stale snapshots never automatically overwrite newer data. Stop older broker and CLI processes before upgrading, since older writers do not participate in locking. Do not delete `~/.opencode-privacy-keychain.lock` while processes are running.

## Security model and limitations

The plugin and broker run as the same user as OpenCode. They cannot guarantee protection from malicious same-user plugins, arbitrary shell programs, malicious MCP servers, local administrators, or secrets already written to old session files. Arbitrary shell credential restoration and arbitrary remote MCP credential forwarding are intentionally unsupported and fail closed.

PII detection is deterministic pattern matching, not semantic classification. Provider `fetch` wrapping only covers requests that OpenCode exposes through that hook.

## Development

```sh
npm install
npm run check
npm pack --dry-run
```

The test suite uses synthetic credentials and local HTTP servers. It verifies that authorized destinations receive the original value while model-like output, broker errors, and audit state do not.

## License

MIT. Vendored pi-privacy code and notices are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Credential protection preserves complete `secret://` references and JSON Schema declarations while scrubbing credential values in examples and defaults. A session marked `zdr-required` requires the configured guarded OpenRouter path; provider-wide request observations do not prove that session’s inference execution.
