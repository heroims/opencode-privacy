// @ts-nocheck -- vendored upstream; own adapters use strict TypeScript.
// pi-privacy 93adf5037749f9b8d4948fe0f3c82a620dff9419; MIT Patrick (zahnno).
// Local, deterministic structured-PII + secret detection. HONESTY BOUND (the whole
// reason this package exists): this catches STRUCTURED PII — emails, phones, SSNs,
// credit cards, IPs — and prefix-anchored SECRETS (API keys, tokens, private keys)
// via patterns only. It CANNOT catch names, addresses, or contextual PII, and it
// never uses a model (that would send the PII to detect it). So it is "best-effort
// structured detection", never a guarantee. Callers must label it that way — the
// same verified-vs-claimed discipline as the posture engine.

import type { AllowMatcher } from "./allow.js";

const PLACEHOLDER: Record<PiiType, string> = {
  email: "«email»",
  phone: "«phone»",
  ssn: "«ssn»",
  "credit-card": "«card»",
  ip: "«ip»",
  iban: "«iban»",
  mac: "«mac»",
  "aws-key": "«aws-key»",
  "gh-token": "«token»",
  "api-key": "«api-key»",
  jwt: "«jwt»",
  "private-key": "«private-key»",
};

export type PiiType =
  | "email"
  | "phone"
  | "ssn"
  | "credit-card"
  | "ip"
  | "iban"
  | "mac"
  // Secrets — credentials that are strictly worse to leak than consumer PII. These
  // are prefix-anchored (AKIA…, gh?_…, sk-…, eyJ….….…, PEM blocks), so precision
  // stays high without an entropy heuristic that would false-positive on hashes/IDs.
  | "aws-key"
  | "gh-token"
  | "api-key"
  | "jwt"
  | "private-key";

// The secret subset of PiiType. A hit of one of these means a CREDENTIAL is present
// — messaging escalates and the tool-exfil gate treats it as high-severity.
export const SECRET_TYPES: ReadonlySet<PiiType> = new Set<PiiType>([
  "aws-key",
  "gh-token",
  "api-key",
  "jwt",
  "private-key",
]);

// Order matters: run more-specific/structured patterns first so a card isn't also
// counted as a phone. Credit-card + phone are validated further below. Several types
// (api-key) intentionally have multiple pattern entries — detectPii accumulates them
// under one type.
//
// PRECISION GUARDS, AND THE BOUND ON THEM. Several entries carry a `validate` or a
// lookaround whose only job is to REFUSE a match: `logo@2x.png` is not an email,
// `1.2.3.4.5` is an OID and not an address, the six hex octets in the middle of a
// certificate fingerprint are not a MAC, and a 16-digit run that starts with a 9 is
// not a card number (no issuer does). This matters more than tidiness: a gate that
// fires on a filename teaches you to dismiss it, and when the host answers the gate
// unattended (piiUnattended) a false positive silently rewrites a payload nobody
// asked it to touch.
//
// A guard is a hole, exactly like an allowlist entry, so it carries the same
// discipline as pii/allow.ts: each one refuses a shape that is IMPOSSIBLE for the
// type (a card IIN, a six-octet MAC), or one whose alternative reading is
// structurally certain (a dotted run longer than a quad). Nothing is refused for
// being "probably fine in code" — where a real value and a false positive are
// genuinely indistinguishable (`8.0.0.0`, a bare `555-867-5309`), the gate still
// fires and the allowlist is the answer.
const PATTERNS: { type: PiiType; re: RegExp; validate?: (m: string) => boolean }[] = [
  { type: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, validate: mailboxShaped },
  { type: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/g },
  // ── secrets (prefix-anchored, high precision) ──────────────────────────────
  // PEM private-key block — match the whole block so redaction removes the key body.
  { type: "private-key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  // AWS access key id (AKIA / ASIA + 16 upper-alnum).
  { type: "aws-key", re: /\bA(?:KIA|SIA)[0-9A-Z]{16}\b/g },
  // GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36+ base62.
  { type: "gh-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  // JWT: three base64url segments. `eyJ` is base64 of `{"` — a strong header marker.
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  // OpenAI/Anthropic/Privateer & generic `sk-` secret keys.
  { type: "api-key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  // Slack tokens (bot/user/app/refresh/legacy).
  { type: "api-key", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  // Google API key.
  { type: "api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  // Stripe live secret / restricted keys.
  { type: "api-key", re: /\b[sr]k_live_[0-9A-Za-z]{20,}\b/g },
  // ── consumer PII ───────────────────────────────────────────────────────────
  // 13–19 digit runs (optionally space/dash grouped) that pass the Luhn check — this
  // sharply cuts false positives vs "any long number".
  { type: "credit-card", re: /\b(?:\d[ -]?){13,19}\b/g, validate: cardShaped },
  // IPv4 with each octet 0–255. The lookarounds keep it out of longer dotted runs —
  // `1.2.3.4.5` (an OID), `v1.2.3.4` (a version) — see the precision note above.
  { type: "ip", re: /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)/g },
  // IBAN: 2-letter country + 2 check digits + 11–30 alphanumerics, mod-97 validated
  // (cuts false positives on random alphanumeric runs sharply).
  { type: "iban", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, validate: ibanValid },
  // MAC address (colon or dash separated). A MAC is exactly six octets, so a run that
  // CONTINUES on either side is a hex dump or a certificate fingerprint, not an address.
  { type: "mac", re: /(?<![0-9A-Fa-f][:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![:-][0-9A-Fa-f]{2})\b/g },
  // North-American / international-ish phone. Deliberately last + conservative to
  // avoid eating IDs; requires a plausible separator or leading +.
  { type: "phone", re: /(?<![\d.])(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g },
];

// Filename/version extensions that a mail domain's last label can never be. Kept to
// suffixes that are NOT real TLDs — `.md`, `.sh`, `.ai`, `.py`, `.rs`, `.zip` and
// `.mov` all resolve on the public internet, so an address at one of them stays a
// hit even though the string also looks like a file.
const NOT_A_TLD = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "tif", "tiff", "avif",
  "mp3", "mp4", "wav", "avi", "mkv", "webm", "ogg", "flac",
  "pdf", "docx", "xlsx", "pptx", "csv", "json", "yaml", "yml", "toml", "xml",
  "html", "htm", "css", "scss", "sass", "less", "tsx", "jsx", "mjs", "cjs",
  "java", "php", "sql", "txt", "log", "lock", "exe", "dll", "dmg", "iso",
  "tar", "gz", "tgz", "bz2", "rar", "woff", "woff2", "ttf", "otf", "eot",
  "bak", "tmp", "swp", "map", "min", "snap", "patch", "diff",
]);

// A semver-ish domain: `5.4.0`, `5.4.0-beta.rc`, `2.0.0-rc.1`. This is what an npm
// spec (`typescript@5.4.0-beta.rc`) looks like once the email pattern has eaten it.
// Numeric labels only, so real digit-leading mail domains (1and1.com, 23andme.com)
// are untouched.
const VERSION_DOMAIN = /^\d+(?:\.\d+)+(?:-[A-Za-z0-9.]+)?$/;

// Is this email-shaped string plausibly a MAILBOX, rather than a file or a package
// spec that happens to contain an `@`? `logo@2x.png`, `hero@3x.webp` and
// `typescript@5.4.0-beta.rc` are the shapes this refuses.
function mailboxShaped(value: string): boolean {
  const domain = value.slice(value.lastIndexOf("@") + 1).toLowerCase();
  if (VERSION_DOMAIN.test(domain)) return false;
  const tld = domain.slice(domain.lastIndexOf(".") + 1);
  return !NOT_A_TLD.has(tld);
}

// Card-number lengths that issuers actually mint: 13 (old Visa), 14 (Diners), 15
// (Amex), 16 (the rest), 19 (Visa/Discover/UnionPay extended). 17 and 18 are not
// issued by anyone, so a run of that length passing Luhn is a coincidence.
const CARD_LENGTHS = new Set([13, 14, 15, 16, 19]);

// Luhn alone accepts about one in ten random digit runs, which is how an order id or
// a concatenated timestamp ends up "a card number". The issuer identifier narrows it
// further at no cost: every major network starts 2–6 (Amex 3, Visa 4, MC 2/5,
// Discover/UnionPay 6, Diners 3/5), so a run starting 0, 1, 7, 8 or 9 is not a card.
function cardShaped(s: string): boolean {
  const digits = s.replace(/\D/g, "");
  if (!CARD_LENGTHS.has(digits.length)) return false;
  const iin = digits.charCodeAt(0) - 48;
  if (iin < 2 || iin > 6) return false;
  return luhn(s);
}

function luhn(s: string): boolean {
  const digits = s.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// IBAN mod-97 check (ISO 13616): move the first 4 chars to the end, map letters to
// numbers (A=10…Z=35), and verify the big-integer mod 97 === 1.
function ibanValid(s: string): boolean {
  const iban = s.toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch >= "A" && ch <= "Z" ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (const d of code) remainder = (remainder * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

export interface PiiHit {
  type: PiiType;
  count: number;
}

export interface ScanOptions {
  // Values this session does not treat as PII (see pii/allow.ts). Matches are moved
  // to `suppressed` instead of `hits`, and redaction leaves them alone.
  allow?: AllowMatcher;
  // Max distinct masked samples to keep per type (default 4, 0 disables sampling).
  samples?: number;
}

// One detected value, masked for display. Masking is one-way and deliberately
// lossy: enough to recognize your own test fixture ("«p…k@gmail.com»"), never
// enough to reconstruct the value from a screenshot or a log.
export interface PiiSample {
  type: PiiType;
  masked: string;
}

export interface PiiScan {
  // Types that count as PII here, with counts.
  hits: PiiHit[];
  // Matches the allowlist removed. Reported, never hidden — a gate that silently
  // drops matches is indistinguishable from a gate that missed them.
  suppressed: PiiHit[];
  // Masked examples of the counted (NOT suppressed) values, for "show me what you
  // found" in the prompt.
  samples: PiiSample[];
}

// Mask one value for display. Types whose every digit is sensitive (SSN, card,
// IBAN, phone) get NO sample — there is no prefix of an SSN worth showing, and a
// count is enough to decide. Types where the identity is in the shape (the domain
// of an email, the prefix of a token) show that part only.
export function maskPii(type: PiiType, value: string): string | undefined {
  switch (type) {
    case "email": {
      const at = value.lastIndexOf("@");
      const local = value.slice(0, at);
      const domain = value.slice(at);
      const head = local.length > 2 ? `${local[0]}…${local[local.length - 1]}` : "…";
      return `${head}${domain}`;
    }
    case "ip":
      return value.replace(/\.\d{1,3}$/, ".•");
    case "mac":
      return `${value.slice(0, 8)}:••:••:••`;
    case "private-key":
      return "-----BEGIN PRIVATE KEY----- block";
    case "aws-key":
    case "gh-token":
    case "api-key":
    case "jwt":
      // Prefix identifies WHICH credential (ghp_ vs sk-), length shows it is whole.
      return `${value.slice(0, 6)}… (${value.length} chars)`;
    default:
      return undefined;
  }
}

// Scan text once: what counts, what the allowlist suppressed, and masked samples.
// Never returns a raw detected value — the samples are masked at the source, so a
// caller cannot accidentally log or send one.
export function scanPii(text: string, opts: ScanOptions = {}): PiiScan {
  if (!text) return { hits: [], suppressed: [], samples: [] };
  const { allow, samples: sampleCap = 4 } = opts;
  const counts = new Map<PiiType, number>();
  const skipped = new Map<PiiType, number>();
  const seen = new Map<PiiType, Set<string>>();
  for (const { type, re, validate } of PATTERNS) {
    for (const m of text.matchAll(re)) {
      if (validate && !validate(m[0])) continue;
      if (allow?.(type, m[0])) {
        skipped.set(type, (skipped.get(type) ?? 0) + 1);
        continue;
      }
      counts.set(type, (counts.get(type) ?? 0) + 1);
      if (sampleCap > 0) {
        const masked = maskPii(type, m[0]);
        if (masked) {
          const set = seen.get(type) ?? new Set<string>();
          if (set.size < sampleCap) set.add(masked);
          seen.set(type, set);
        }
      }
    }
  }
  const toHits = (m: Map<PiiType, number>) => [...m.entries()].map(([type, count]) => ({ type, count }));
  return {
    hits: toHits(counts),
    suppressed: toHits(skipped),
    samples: [...seen.entries()].flatMap(([type, set]) => [...set].map((masked) => ({ type, masked }))),
  };
}

// Detect structured PII in text. Returns the types present with counts (not the raw
// values — we don't want to log the PII we found).
export function detectPii(text: string, opts: ScanOptions = {}): PiiHit[] {
  return scanPii(text, { ...opts, samples: 0 }).hits;
}

export function hasPii(text: string, opts: ScanOptions = {}): boolean {
  return detectPii(text, opts).length > 0;
}

// True when any hit is a credential (not merely consumer PII). Drives the escalated
// wording + safer defaults in the gates — a leaked secret is strictly worse.
export function hasSecrets(hits: PiiHit[]): boolean {
  return hits.some((h) => SECRET_TYPES.has(h.type));
}

// Just the credential hits. The tool-RESULT gate works on these alone: an email in a
// source file the agent is editing is not worth rewriting what the model sees, but an
// API key entering the transcript is.
export function secretHits(hits: PiiHit[]): PiiHit[] {
  return hits.filter((h) => SECRET_TYPES.has(h.type));
}

// Redact structured PII in text, replacing each match with a typed placeholder.
// `only` restricts redaction to a subset of types (e.g. SECRET_TYPES) — everything
// outside it is left byte-for-byte alone, so a caller that only means to strip
// credentials can't silently rewrite the rest of the text.
// An ALLOWLISTED value is left alone too: it was never counted as PII, so masking it
// would rewrite text the gate already declared harmless.
export function redactPii(text: string, only?: ReadonlySet<PiiType>, allow?: AllowMatcher): string {
  let out = text;
  for (const { type, re, validate } of PATTERNS) {
    if (only && !only.has(type)) continue;
    out = out.replace(re, (m) => {
      if (validate && !validate(m)) return m;
      if (allow?.(type, m)) return m;
      return PLACEHOLDER[type];
    });
  }
  return out;
}

// Human-readable summary of a hit list, e.g. "2 emails, 1 SSN".
export function summarizePii(hits: PiiHit[]): string {
  const label: Record<PiiType, [string, string]> = {
    email: ["email", "emails"],
    phone: ["phone number", "phone numbers"],
    ssn: ["SSN", "SSNs"],
    "credit-card": ["card number", "card numbers"],
    ip: ["IP address", "IP addresses"],
    iban: ["IBAN", "IBANs"],
    mac: ["MAC address", "MAC addresses"],
    "aws-key": ["AWS key", "AWS keys"],
    "gh-token": ["GitHub token", "GitHub tokens"],
    "api-key": ["API key", "API keys"],
    jwt: ["JWT", "JWTs"],
    "private-key": ["private key", "private keys"],
  };
  return hits.map((h) => `${h.count} ${label[h.type][h.count === 1 ? 0 : 1]}`).join(", ");
}

// ── what the gate actually found ─────────────────────────────────────────────
// "12 emails detected" is a number you can only accept or refuse. This is the
// breakdown behind it: masked samples per type, plus what the allowlist suppressed,
// so the decision is informed rather than a coin flip on an aggregate.
export function piiDetail(scan: PiiScan): string {
  const lines: string[] = [];
  for (const hit of scan.hits) {
    const shown = scan.samples.filter((s) => s.type === hit.type).map((s) => s.masked);
    const more = hit.count - shown.length;
    const tail = shown.length
      ? `: ${shown.join(", ")}${more > 0 ? `, +${more} more` : ""}`
      : " (masked — not shown)";
    lines.push(`  • ${summarizePii([hit])}${tail}`);
  }
  if (scan.suppressed.length) {
    lines.push(`  • allowlisted (not counted): ${summarizePii(scan.suppressed)}`);
  }
  lines.push("  Values are masked here; the full values are in what would be sent.");
  return lines.join("\n");
}

// One-line form of piiDetail, for notices rather than prompts: masked samples inline
// after each count — "2 IP addresses (192.168.1.•, 10.0.0.•), 1 email (p…k@x.com)".
// Same masking rules as piiDetail: never a raw value, sampleless types show count only.
export function piiInline(scan: PiiScan): string {
  return scan.hits
    .map((h) => {
      const shown = scan.samples.filter((s) => s.type === h.type).map((s) => s.masked);
      const more = h.count - shown.length;
      const tail = shown.length ? ` (${shown.join(", ")}${more > 0 ? `, +${more} more` : ""})` : "";
      return `${summarizePii([h])}${tail}`;
    })
    .join(", ");
}

// ── "only prompt on NEW PII" ─────────────────────────────────────────────────
// The outbound payload is the WHOLE conversation, so PII you already decided about
// is still there on every later turn. Diffing against what was already decided is
// what turns "prompt every turn forever" into "prompt when something changes".
export type PiiBaseline = ReadonlyMap<PiiType, number>;

// The part of `hits` that exceeds the baseline: types never seen, and types whose
// count has grown (a 13th email is a new email). Counts are the DELTA.
export function newPii(hits: readonly PiiHit[], baseline: PiiBaseline): PiiHit[] {
  const out: PiiHit[] = [];
  for (const h of hits) {
    const seen = baseline.get(h.type) ?? 0;
    if (h.count > seen) out.push({ type: h.type, count: h.count - seen });
  }
  return out;
}

// Fold a decided scan into the baseline. Max, not sum: counts are cumulative over
// the same growing context, so a shorter payload later must not lower the bar.
export function mergePiiBaseline(baseline: PiiBaseline, hits: readonly PiiHit[]): Map<PiiType, number> {
  const out = new Map(baseline);
  for (const h of hits) out.set(h.type, Math.max(out.get(h.type) ?? 0, h.count));
  return out;
}
