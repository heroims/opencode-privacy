import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';

export interface PrivacyConfig {
  piiPolicy: 'off' | 'warn' | 'redact' | 'block';
  toolExfilPolicy: 'off' | 'warn' | 'block';
  downgradePolicy: 'off' | 'warn' | 'block';
  piiAllow: string[];
  brokerSocket?: string;
  enforceOpenRouterZdr: boolean;
  blockAttachments: boolean;
}
export const defaults: PrivacyConfig = {
  piiPolicy: 'redact', toolExfilPolicy: 'block', downgradePolicy: 'block',
  piiAllow: [], enforceOpenRouterZdr: false, blockAttachments: true,
};
const options = {
  piiPolicy: ['off','warn','redact','block'], toolExfilPolicy:['off','warn','block'], downgradePolicy:['off','warn','block'],
};
export function parseConfig(raw: unknown): PrivacyConfig {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('PRIVACY_CONFIG');
  const result = { ...defaults, piiAllow: [] } as PrivacyConfig;
  for (const [key, value] of Object.entries(raw)) {
    if (Object.hasOwn(options, key)) {
      if (typeof value !== 'string' || !(options as Record<string,string[]>)[key]!.includes(value)) throw new Error('PRIVACY_CONFIG');
    } else if (key === 'piiAllow') {
      if (!Array.isArray(value) || value.length > 100 || value.some(x => typeof x !== 'string' || !x.trim() || x === '*' || x.length > 256)) throw new Error('PRIVACY_CONFIG');
    } else if (key === 'brokerSocket') {
      if (typeof value !== 'string' || !isAbsolute(value)) throw new Error('PRIVACY_CONFIG');
    } else if (key === 'enforceOpenRouterZdr' || key === 'blockAttachments') {
      if (typeof value !== 'boolean') throw new Error('PRIVACY_CONFIG');
    } else throw new Error('PRIVACY_CONFIG');
    Object.assign(result, { [key]: value });
  }
  return result;
}
export function mergeProjectConfig(user: PrivacyConfig, project: unknown): PrivacyConfig {
  if (!project || typeof project !== 'object' || Array.isArray(project)) throw new Error('PRIVACY_CONFIG');
  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(project)) {
    if (Object.hasOwn(options,key)) {
      const values = (options as Record<string,string[]>)[key]!;
      if (typeof value !== 'string' || !values.includes(value)) throw new Error('PRIVACY_CONFIG');
      if (values.indexOf(value) > values.indexOf(user[key as keyof PrivacyConfig] as string)) safe[key] = value;
    } else if (['enforceOpenRouterZdr','blockAttachments'].includes(key)) {
      if (typeof value !== 'boolean') throw new Error('PRIVACY_CONFIG');
      if (value) safe[key] = true;
    }
    // Project cannot change the broker, allowlist or add an unrecognized setting.
  }
  return parseConfig({ ...user, ...safe });
}
export async function loadConfig(directory: string, env = process.env): Promise<PrivacyConfig> {
  async function read(path: string, required = false): Promise<unknown> {
    try { return JSON.parse(await readFile(path, 'utf8')); }
    catch (e) { if (!required && (e as NodeJS.ErrnoException).code === 'ENOENT') return {}; throw new Error('PRIVACY_CONFIG'); }
  }
  const userPath = env.OPENCODE_PRIVACY_CONFIG ?? join(homedir(), '.config/opencode-privacy/config.json');
  let config = parseConfig(await read(userPath, Boolean(env.OPENCODE_PRIVACY_CONFIG)));
  if (env.OPENCODE_PRIVACY_BROKER_SOCKET) config = parseConfig({...config, brokerSocket:env.OPENCODE_PRIVACY_BROKER_SOCKET});
  config = mergeProjectConfig(config, await read(join(directory, 'opencode-privacy.config.json')));
  return config;
}
