# OpenCode Privacy Implementation Plan

> Execute in this session with test-driven-development and independent code review. Approved design: ../specs/2026-09-15-opencode-privacy-design.md. Do not modify OpenCode core.

**Goal:** Deliver an installable plugin with pi-privacy-derived controls and scoped credential operations, documenting every partial or unsupported upstream feature.

**Architecture:** TypeScript policy engine and OpenCode hook adapter; separate credential module and local CLI; safe operation tools restore secrets internally. Upstream pure functionality is reused through a pinned dependency or attributed source if exports are unsuitable.

**Tech Stack:** Node >=22.19, TypeScript, node:test via tsx, @opencode-ai/plugin, pi-privacy 0.14.1.

## Task 1: Baseline and upstream audit

- [ ] Fix upstream revisions and exact installed package versions in lockfile and docs/upstream.md.
- [ ] Inspect pi-privacy exports and OpenCode hooks/call sites. Record each feature as supported, partial or unsupported in docs/coverage.md.
- [ ] Create package metadata, scripts and TypeScript configs. `npm install`, followed by `npm run typecheck` once tests exist.

## Task 2: Core policy and hook adapter

Files: src/privacy.ts, src/config.ts, src/plugin.ts; tests/privacy.test.ts, tests/plugin.test.ts.

- [ ] Write tests for detector-backed redaction and user/project trust boundaries before implementation.
  ```ts
  assert.equal(JSON.stringify(scrub({ text: fixture }, policy)).includes(fixture), false)
  assert.throws(() => parseConfig({ toolExfilPolicy: 'invalid' }))
  ```
- [ ] Run `npm test` and confirm missing behavior. Implement each exported unit, run targeted tests, then full suite.
- [ ] Exercise chat.message, system/message transformation, tool arguments and after results using real hook functions and synthetic secrets.
- [ ] Check metadata and object keys, unknown attachments, missing broker, and malformed configuration fail safely.
- [ ] Add state tool with no model-accessible mutators. Surface observed tools, unknown provenance, provider levels and policy state without raw payloads.
- [ ] Implement conservative external tool checks, sensitive file references and provider downgrade behavior. Keep local classification evidence distinct from verified local execution.

## Task 3: Scoped credential operations

Files: src/credentials.ts, src/operations.ts, src/broker.ts, src/cli.ts; tests/credentials.test.ts, tests/operations.test.ts, tests/broker.test.ts.

- [ ] Write behavioral tests using memory store and synthetic random credentials; watch failure before implementation.
- [ ] Implement stable random references, per-session + per-operation + per-target grants, hidden CLI input, macOS Keychain store without password in process arguments.
- [ ] Implement broker client/server over owner-only local socket, request bounds and fixed sanitized errors. Document same-user limitations.
- [ ] Implement HTTP operation with exact origin/method/header binding, no redirects, bounded output and timeouts. No generic shell restoration.
- [ ] Implement JSON configuration field operations with explicit paths, permissions, symlink rejection, concurrency check and atomic writes.
- [ ] Assert destination receives real secret while response and audit contain no raw value. Reject wrong session, wrong origin, unknown references, redirects and symlinks.

## Task 4: Provider parity and user controls

Files: src/providers.ts, tests/providers.test.ts, docs/coverage.md.

- [ ] Reuse upstream posture and attestation code only where evidence semantics remain valid.
- [ ] Test OpenRouter options at actual adapter boundary, downgrade state, unverifiable TEE classification and untrusted project restrictions.
- [ ] Expose explicit unsupported labels for any provider transport whose actual request binding cannot be verified without core changes. Never manufacture verified TEE from a report parser alone.
- [ ] Persist user-only session controls via local CLI state; no model tool for approval or disabling policies.

## Task 5: Documentation, packaging and review

Files: README.md, examples/, docs/coverage.md, docs/upstream.md, LICENSE, THIRD_PARTY_NOTICES.md.

- [ ] Document install, local secret entry, grants, secure tool calls, revocation and limitations in Chinese.
- [ ] Run `npm run check`, `npm pack --dry-run`, import built plugin and CLI help smoke test. Test real OpenCode load if runtime available; otherwise document lack of host integration validation.
- [ ] Obtain independent spec review then security/code review; fix significant findings with regression tests.
- [ ] Commit verified implementation on codex/privacy-plugin; do not publish to npm or alter the user's OpenCode configuration automatically.

## Progress

This plan tracks a first release across the approved scope. Unsupported functionality is a visible delivery limitation, never presented as completed protection. Host/TEE live verification requires a usable host/provider and is reported separately from offline tests. The implementation currently has 25 passing local tests and a successful TypeScript build; the isolated OpenCode fixture smoke test timed out before producing a model request and remains unverified.
