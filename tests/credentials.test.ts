import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryCredentialStore, KeychainCredentialStore } from '../src/credentials.js';

test('credentials have opaque stable references and scrub nested output and common encodings', () => {
  const store = new MemoryCredentialStore();
  const secret = 'fake-pass/with"special-12345';
  const ref = store.add(secret);
  assert.match(ref, /^secret:\/\/[a-f0-9-]+$/);
  assert.equal(store.add(secret), ref);
  assert.equal(store.resolve(ref), secret);
  const scrubbed = JSON.stringify(store.scrub({ [secret]: [secret, encodeURIComponent(secret), Buffer.from(secret).toString('base64')] }));
  assert.ok(!scrubbed.includes(secret));
  assert.ok(!scrubbed.includes(encodeURIComponent(secret)));
  assert.ok(!scrubbed.includes(Buffer.from(secret).toString('base64')));
  assert.throws(() => store.resolve('secret://missing'), /UNKNOWN_REFERENCE/);
});

test('Keychain persistent store sends contents only through stdin and preserves refs on reload', async () => {
  let saved = ''; const invocations: string[][] = [];
  const runner = async (args: string[], input: string) => {
    invocations.push(args);
    const command = JSON.parse(input);
    if (command.action === 'set') { saved = command.value; return ''; }
    return saved;
  };
  const store = new KeychainCredentialStore(runner);
  const ref = store.add('fake-keychain-value-987654');
  await store.save();
  const restored = new KeychainCredentialStore(runner);
  await restored.load();
  assert.equal(restored.resolve(ref), 'fake-keychain-value-987654');
  assert.ok(!JSON.stringify(invocations).includes('fake-keychain-value-987654'));
});
