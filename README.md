# opencode-privacy

OpenCode plugin for local, deterministic privacy checks and scoped credential operations. It does not modify OpenCode core.

## What it protects

- Detects and redacts structured PII and common secrets before they remain in messages, history transforms, tool results, system text, compaction text, and provider fetch bodies.
- Blocks sensitive arguments sent through ordinary tools and records observed tool names without recording payloads.
- Wraps provider `fetch` options when OpenCode exposes them. OpenRouter ZDR adds `provider.zdr=true` and `provider.data_collection="deny"`; redirects and unsupported provider targets fail closed.
- Reports provider posture conservatively. TEE provider claims are `tee-unverified` because the plugin cannot cryptographically bind inference TLS without changing the host.
- Provides `privacy_http`, `privacy_config_read`, and `privacy_config_write`. These accept `secret://<uuid>` references and restore values only inside a scoped operation.

## Install

Build the package and add the absolute path to the built plugin in OpenCode's plugin list:

```sh
npm install
npm run check
npm run build
```

The package requires Node 22.19 or newer. On macOS, initialize the local files and start the broker:

```sh
node dist/cli.js init
node dist/cli.js secret add       # hidden TTY input; prints only secret://...
node dist/cli.js serve
```

Set `OPENCODE_PRIVACY_BROKER_SOCKET` or `brokerSocket` in the user config so the plugin can call the broker. Keep `grants.json` owner-only. A grant names an exact session, operation, target, reference, method, header, or JSON field. Project-local config can only strengthen the user's policy.

## Security boundary

This is a plugin and runs as the same user as OpenCode. It cannot guarantee protection from malicious same-user plugins, arbitrary shell programs, malicious MCP servers, a local administrator, or secrets already written to old session files. Unsupported sensitive operations fail closed. A target configuration file may contain a real value because its consumer requires it; that file must be treated as sensitive.

PII and secret detection is deterministic pattern matching, not semantic classification. TEE labels remain unverified unless a future host adapter supplies a real inference-channel verifier.

## Development

```sh
npm run check
npm pack --dry-run
```

The tests use synthetic credentials and local HTTP servers. They verify that an authorized destination receives the real value while model-like output, broker errors, and audit state do not.
