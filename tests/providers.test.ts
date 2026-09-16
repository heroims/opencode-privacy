import { test } from 'node:test';
import assert from 'node:assert/strict';
import { providerPosture, guardedFetch, checkDowngrade } from '../src/providers.js';

test('provider reports never promote names or TEE claims to verified guarantees',()=>{
  assert.equal(providerPosture('ollama','https://remote.example.com').tier,'standard');
  assert.equal(providerPosture('tinfoil','https://inference.tinfoil.sh/v1').tier,'tee-unverified');
  assert.equal(providerPosture('custom','http://127.0.0.1:1234').tier,'loopback');
  assert.equal(providerPosture('openrouter','https://evil.example').tier,'standard');
  assert.equal(providerPosture('openrouter','https://openrouter.ai/api/v1').tier,'standard');
});
test('ZDR fetch patches real outgoing JSON for approved endpoint and never forwards redirects',async()=>{
  let sent:Request|undefined;
  const fetcher = guardedFetch({provider:'openrouter',enforceZdr:true,scrub:async x=>x,fetch:async input=>{sent=input as Request;return new Response('{}');}});
  await fetcher('https://openrouter.ai/api/v1/chat/completions',{method:'POST',body:JSON.stringify({model:'test',provider:{zdr:false,allow_fallbacks:true}})});
  const body=await sent!.json();
  assert.equal(body.provider.zdr,true);assert.equal(body.provider.data_collection,'deny');assert.equal(body.provider.allow_fallbacks,true);
  assert.equal(sent!.redirect,'error');
  await assert.rejects(fetcher('https://evil.example/api/v1/chat/completions',{method:'POST',body:'{}'}),/PRIVACY_PROVIDER_TARGET/);
});
test('transport sanitizes full outgoing body, strips stale length and preserves auth header',async()=>{
  let sent:Request|undefined;
  const fetcher=guardedFetch({provider:'custom',scrub:async x=>JSON.parse(JSON.stringify(x).replaceAll('fixture-secret','secret://id')),fetch:async input=>{sent=input as Request;return new Response('{}');}});
  await fetcher('https://model.example/v1',{method:'POST',headers:{authorization:'Bearer provider-auth','content-length':'999'},body:JSON.stringify({messages:[{content:'fixture-secret'}]})});
  assert.ok(!(await sent!.text()).includes('fixture-secret'));assert.equal(sent!.headers.get('content-length'),null);assert.equal(sent!.headers.get('authorization'),'Bearer provider-auth');
});
test('downgrade guards retain previous provider until allowed',()=>{
  assert.throws(()=>checkDowngrade({tier:'zdr-enforced',evidence:'test'},{tier:'standard',evidence:'test'},true,'block'),/PRIVACY_DOWNGRADE/);
  assert.doesNotThrow(()=>checkDowngrade({tier:'standard',evidence:'test'},{tier:'tee-unverified',evidence:'test'},true,'block'));
});
