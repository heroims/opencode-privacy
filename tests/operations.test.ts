import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, symlink, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryCredentialStore } from '../src/credentials.js';
import { OperationEngine } from '../src/operations.js';

test('HTTP target receives secret but output never contains it; grants bind session, origin and headers', async () => {
  const secret = 'fake-http-password-123456'; let received = '';
  const server = createServer((req, res) => { received = String(req.headers.authorization); res.end(JSON.stringify({echo: received})); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as {port: number};
  const origin = `http://127.0.0.1:${address.port}`;
  const store = new MemoryCredentialStore(); const ref = store.add(secret);
  const engine = new OperationEngine(store, [{sessionID: 's1', operation:'http', target:origin, refs:[ref], methods:['GET'], headers:['authorization'], allowPrivateNetwork:true, allowHTTPForTests:true}]);
  try {
    const result = await engine.http('s1', {url: origin, headers:{authorization:ref}});
    assert.equal(received, secret); assert.ok(!result.includes(secret));
    await assert.rejects(engine.http('s2', {url:origin, headers:{authorization:ref}}), /DENIED/);
    await assert.rejects(engine.http('s1', {url:origin, headers:{'x-secret':ref}}), /DENIED/);
    await assert.rejects(engine.http('s1', {url:origin+'/?secret='+ref, headers:{authorization:ref}}), /DENIED/);
    await assert.rejects(engine.http('s1', {url:origin, headers:{authorization:'secret://missing'}}), /DENIED/);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('HTTP rejects redirects and private networks without explicit trusted opt-in', async () => {
  const server = createServer((_req, res) => { res.writeHead(302, {location:'https://example.com'}); res.end(); });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as {port:number}).port}`;
  const store = new MemoryCredentialStore(); const ref = store.add('fake-redirect-password-456');
  const grant = {sessionID:'s', operation:'http' as const, target:origin, refs:[ref], methods:['GET'], headers:['authorization'], allowHTTPForTests:true};
  try {
    await assert.rejects(new OperationEngine(store,[grant]).http('s',{url:origin,headers:{authorization:ref}}),/DENIED/);
    await assert.rejects(new OperationEngine(store,[{...grant,allowPrivateNetwork:true}]).http('s',{url:origin,headers:{authorization:ref}}),/REDIRECT_DENIED/);
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('config field reads return references and writes check version, path and symlinks', async () => {
  const dir = await mkdtemp(join(tmpdir(),'privacy-config-'));
  const path = join(dir,'config.json'); const secret = 'fake-config-password-1234';
  await writeFile(path, JSON.stringify({db:{password:secret},public:'keep'}));
  const store = new MemoryCredentialStore(); const replacement = store.add('fake-replacement-5678');
  const engine = new OperationEngine(store,[
    {sessionID:'s',operation:'config.read',target:path,refs:[],fields:['db.password']},
    {sessionID:'s',operation:'config.write',target:path,refs:[replacement],fields:['db.password']},
  ]);
  try {
    const read = JSON.parse(await engine.configRead('s',{path,fields:['db.password']}));
    assert.match(read.fields['db.password'],/^secret:\/\//); assert.ok(!JSON.stringify(read).includes(secret));
    await engine.configWrite('s',{path,version:read.version,updates:{'db.password':replacement}});
    assert.equal(JSON.parse(await readFile(path,'utf8')).db.password,'fake-replacement-5678');
    assert.equal((await stat(path)).mode & 0o777,0o600);
    await assert.rejects(engine.configWrite('s',{path,version:read.version,updates:{'db.password':replacement}}),/VERSION_CONFLICT/);
    await assert.rejects(engine.configRead('s',{path,fields:['public']}),/DENIED/);
    const link = join(dir,'link.json'); await symlink(path,link);
    const linkEngine = new OperationEngine(store,[{sessionID:'s',operation:'config.read',target:link,refs:[],fields:['db.password']}]);
    await assert.rejects(linkEngine.configRead('s',{path:link,fields:['db.password']}),/UNSAFE_PATH/);
  } finally { await rm(dir,{recursive:true,force:true}); }
});
