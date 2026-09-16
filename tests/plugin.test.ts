import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createPrivacyHooks} from '../src/adapter.js';
import {parseConfig} from '../src/config.js';

const token='sk-'+ 'A'.repeat(30);
const context:any={sessionID:'s',callID:'c',tool:'read'};
test('ingress, history, system and tool results are scrubbed at their hook boundaries',async()=>{
  const hooks=createPrivacyHooks(parseConfig({}));
  const message:any={message:{},parts:[{type:'text',text:token}]};
  await hooks['chat.message']!({sessionID:'s'} as any,message);
  assert.ok(!JSON.stringify(message).includes(token));
  const result={title:token,output:token,metadata:{password:'ordinary-password'}};
  await hooks['tool.execute.after']!(context,result);
  assert.ok(!JSON.stringify(result).includes(token));assert.ok(!JSON.stringify(result).includes('ordinary-password'));
  const system={system:[token]};await hooks['experimental.chat.system.transform']!({model:{},sessionID:'s'} as any,system);assert.ok(!system.system[0]?.includes(token));
  const history:any={messages:[{info:{sessionID:'s',id:'preserve-id'},parts:[{type:'text',text:token}]}]};
  await hooks['experimental.chat.messages.transform']!({},history);assert.ok(!JSON.stringify(history).includes(token));assert.equal(history.messages[0].info.id,'preserve-id');
});
test('broker failures fail closed rather than sending unprotected values',async()=>{
  const hooks=createPrivacyHooks(parseConfig({}),{scrub:async()=>{throw new Error('raw fake-password');}} as any);
  await assert.rejects(hooks['chat.message']!({sessionID:'s'} as any,{message:{},parts:[{type:'text',text:'hello'}]} as any),/PRIVACY_BROKER_UNAVAILABLE/);
});
test('tools do not expose a raw secret resolver or policy mutation command',()=>{
  const hooks=createPrivacyHooks(parseConfig({}));
  assert.deepEqual(Object.keys(hooks.tool!).sort(),['privacy_config_read','privacy_config_write','privacy_http','privacy_status']);
});
test('unknown media fails closed by default',async()=>{
  const hooks=createPrivacyHooks(parseConfig({}));
  await assert.rejects(hooks['chat.message']!({sessionID:'s'} as any,{message:{},parts:[{type:'file',mime:'image/png',url:'data:image/png;base64,abc'}]} as any),/PRIVACY_ATTACHMENT/);
});
test('config hook wraps final provider fetch and broker receives content before transport',async()=>{
  const hooks=createPrivacyHooks(parseConfig({}));let transmitted='';
  const hostConfig:any={provider:{custom:{options:{fetch:async(request:Request)=>{transmitted=await request.text();return new Response('{}');}}}}};
  await hooks.config!(hostConfig);
  await hostConfig.provider.custom.options.fetch('https://model.example/v1',{method:'POST',body:JSON.stringify({messages:[{content:token}]})});
  assert.ok(!transmitted.includes(token));
});
test('package entry exports exactly one plugin initializer for OpenCode legacy loader',async()=>{
  const entry=await import('../src/plugin.js');
  assert.deepEqual(Object.keys(entry),['default']);
});

test('JSON passwords from file output remain masked through history and provider transport', async () => {
  const hooks=createPrivacyHooks(parseConfig({}));
  const output={title:'config.json',output:'{"password":"ordinaryPassword123"}',metadata:{}};
  await hooks['tool.execute.after']!(context,output);
  assert.ok(!output.output.includes('ordinaryPassword123'));
  const history:any={messages:[{info:{sessionID:'s'},parts:[{type:'text',text:output.output}]}]};
  await hooks['experimental.chat.messages.transform']!({},history);
  let sent='';
  const host:any={provider:{custom:{options:{fetch:async(req:Request)=>{sent=await req.text();return new Response('{}');}}}}};
  await hooks.config!(host);
  await host.provider.custom.options.fetch('https://model.example/v1',{method:'POST',body:JSON.stringify(history)});
  assert.ok(!sent.includes('ordinaryPassword123'));
});

test('tool definitions with host-owned schema objects do not abort the session', async () => {
  const hooks=createPrivacyHooks(parseConfig({}));
  const parameters=Object.assign(Object.create({hostOwned:true}), {type:'object', properties:{}});
  const definition:any={description:'safe tool',parameters};
  await hooks['tool.definition']!({} as any,definition);
  assert.equal(definition.parameters,parameters);
});
