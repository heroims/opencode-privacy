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

// Model the native helper's atomic compare-and-set protocol without touching a user's Keychain.
function versionedVault() {
  let saved='';
  return async (_args:string[], input:string) => {
    const command=JSON.parse(input);
    if(command.action==='get')return saved;
    if(command.expected!==undefined && command.expected!==saved)throw new Error('conflict');
    saved=command.value;
    return '';
  };
}

test('stale Keychain saves cannot discard additions or restore deletions', async () => {
  const runner=versionedVault();
  const original=new KeychainCredentialStore(runner);
  const removed=original.add('synthetic-original');await original.save();
  const broker=new KeychainCredentialStore(runner);await broker.load();
  const cli=new KeychainCredentialStore(runner);await cli.load();
  cli.remove(removed);const added=cli.add('synthetic-new');await cli.save();
  broker.add('synthetic-config-read');
  await assert.rejects(broker.save(), /KEYCHAIN_SAVE_FAILED/);
  const restored=new KeychainCredentialStore(runner);await restored.load();
  assert.equal(restored.resolve(added),'synthetic-new');
  assert.throws(()=>restored.resolve(removed),/UNKNOWN_REFERENCE/);
  await broker.load();broker.add('synthetic-retry');await broker.save();
});

test('two writers of the same Keychain snapshot cannot both commit', async () => {
  const runner=versionedVault();
  const a=new KeychainCredentialStore(runner),b=new KeychainCredentialStore(runner);
  await a.load();await b.load();
  a.add('synthetic-a');b.add('synthetic-b');
  const result=await Promise.allSettled([a.save(),b.save()]);
  assert.equal(result.filter(x=>x.status==='fulfilled').length,1);
  assert.equal(result.filter(x=>x.status==='rejected').length,1);
});
