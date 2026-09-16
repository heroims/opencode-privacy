import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryCredentialStore } from '../src/credentials.js';
import { OperationEngine } from '../src/operations.js';
import { startBroker, BrokerClient } from '../src/broker.js';

test('broker exposes scrub and scoped operations over owner-only socket', async () => {
  const directory = await mkdtemp(join(tmpdir(),'privacy-broker-')); const socket = join(directory,'broker.sock');
  const store = new MemoryCredentialStore(); const secret = 'fake-broker-password-1234'; const ref = store.add(secret);
  const broker = await startBroker(socket, new OperationEngine(store, []));
  try {
    assert.equal((await stat(socket)).mode & 0o777,0o600);
    const client = new BrokerClient(socket);
    assert.deepEqual(await client.scrub({value:secret}),{value:ref});
    assert.ok(!JSON.stringify(await client.status()).includes(secret));
    await assert.rejects(client.http('unauthorized',{url:'https://example.com',headers:{authorization:ref}}),/DENIED/);
  } finally { await broker.close(); await rm(directory,{recursive:true,force:true}); }
});
