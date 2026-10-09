import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { PrivacyEngine, mapJson } from '../src/privacy.js';
import { parseConfig } from '../src/config.js';
import { createPrivacyHooks } from '../src/adapter.js';
import { OperationEngine } from '../src/operations.js';
import { MemoryCredentialStore } from '../src/credentials.js';

test('R1: reject non-boolean network opt-ins before issuing a request', async () => {
  const server=createServer((_req,res)=>res.end('synthetic local response'));
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin=`http://127.0.0.1:${(server.address() as {port:number}).port}`;
  try {
    const store=new MemoryCredentialStore();
    const grant:any={sessionID:'s',operation:'http',target:origin,refs:[],methods:['GET'],headers:[],allowPrivateNetwork:'false',allowHTTPForTests:'false'};
    let denied=false;
    try { await new OperationEngine(store,[grant]).http('s',{url:origin}); } catch { denied=true; }
    assert.ok(denied,'string false was treated as permission to send HTTP to loopback');
  } finally {await new Promise<void>(resolve=>server.close(()=>resolve()));}
});

test('R2: a string field whitelist must not authorize substring field names', async () => {
  const dir=await mkdtemp('/private/tmp/privacy-review-');const path=join(dir,'config.json');
  await writeFile(path,JSON.stringify({db:{password:'synthetic-db-secret'},password:'synthetic-root-secret'}));
  try {
    let denied=false;
    try {await new OperationEngine(new MemoryCredentialStore(),[{sessionID:'s',operation:'config.read',target:path,refs:[],fields:'db.password'} as any]).configRead('s',{path,fields:['password']});} catch {denied=true;}
    assert.ok(denied,'fields="db.password" authorized reading root password');
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('R3: redact common environment assignments and modern token prefixes', () => {
  const engine=new PrivacyEngine(parseConfig({piiPolicy:'off'}));
  const cases=[
    'AWS_SECRET_ACCESS_KEY=opaqueSampleCredentialValue123',
    'DATABASE_PASSWORD=ordinarySamplePass123',
    'TOKEN=opaqueSampleCredentialValue123',
    'Authorization: Bearer opaqueSampleCredentialValue123',
    'github_pat_'+ 'A'.repeat(40),
    'npm_'+ 'A'.repeat(36),
    'postgres://alice:ordinarySamplePass123@database.internal/app',
  ];
  const misses=cases.filter(text=>engine.scrub(text)===text);
  assert.deepEqual(misses,[],'common credentials survived opencode-privacy unchanged');
});

test('R4: first guarded ZDR request must establish downgrade state for its session',async()=>{
  const hooks=createPrivacyHooks(parseConfig({enforceOpenRouterZdr:true}));
  const host:any={provider:{openrouter:{options:{fetch:async()=>new Response('{}')}}}};
  await hooks.config!(host);
  await hooks['chat.message']!({sessionID:'s'} as any,{message:{},parts:[{type:'text',text:'sk-'+ 'A'.repeat(30)}]} as any);
  const params=(providerID:string,url:string)=>({sessionID:'s',model:{providerID,api:{url}},provider:{options:{baseURL:url}}} as any);
  await hooks['chat.params']!(params('openrouter','https://openrouter.ai/api/v1'),{} as any);
  await host.provider.openrouter.options.fetch('https://openrouter.ai/api/v1/chat/completions',{method:'POST',body:'{"messages":[]}'});
  await assert.rejects(hooks['chat.params']!(params('custom','https://model.example/v1'),{} as any),/PRIVACY_DOWNGRADE/);
});

test('R5: a broker-detected opaque secret must mark its session sensitive',async()=>{
  const broker:any={scrub:async(value:unknown)=>mapJson(value,text=>text.replaceAll('opaqueSampleValue57','secret://12345678-1234-1234-1234-123456789abc'))};
  const hooks=createPrivacyHooks(parseConfig({}),broker);
  await hooks['chat.message']!({sessionID:'s'} as any,{message:{},parts:[{type:'text',text:'opaqueSampleValue57'}]} as any);
  const params=(providerID:string,url:string)=>({sessionID:'s',model:{providerID,api:{url}},provider:{options:{baseURL:url}}} as any);
  await hooks['chat.params']!(params('venice','https://api.venice.ai/v1'),{} as any);
  await assert.rejects(hooks['chat.params']!(params('custom','https://model.example/v1'),{} as any),/PRIVACY_DOWNGRADE/);
});

test('R6: preserve secret references even when UUID contains phone-shaped digits',()=>{
  const ref='secret://12345678-1234-4234-8234-13800138000a';
  assert.equal(new PrivacyEngine(parseConfig({})).scrub(ref),ref);
});

test('R7: honor the configured Chinese phone allowlist',()=>{
  assert.equal(new PrivacyEngine(parseConfig({piiAllow:['13800138000']})).scrub('13800138000'),'13800138000');
});

test('R8: structured numeric credential values must not pass to model unchanged',()=>{
  assert.notDeepEqual(new PrivacyEngine(parseConfig({})).scrub({password:123456}),{password:123456});
});

test('R9: tool result replacement must remove original sensitive top-level keys',async()=>{
  const hooks=createPrivacyHooks(parseConfig({}));const token='ghp_'+ 'A'.repeat(36);
  const result:any={title:'safe',output:'safe',metadata:{},[token]:'safe'};
  await hooks['tool.execute.after']!({sessionID:'s',tool:'custom',callID:'c'} as any,result);
  assert.ok(!Object.hasOwn(result,token),'Object.assign retained the original key after producing a redacted key');
});
