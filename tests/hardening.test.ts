import test from 'node:test';
import assert from 'node:assert/strict';
import { PrivacyEngine } from '../src/privacy.js';
import { parseConfig } from '../src/config.js';
import { OperationEngine } from '../src/operations.js';
import { MemoryCredentialStore } from '../src/credentials.js';
import { createPrivacyHooks } from '../src/adapter.js';

test('malformed and ambiguous grants fail at load rather than broadening permissions',()=>{
  const grant={sessionID:'s',operation:'http',target:'https://api.example.com',refs:[],methods:['GET'],headers:['authorization']};
  for(const patch of [
    {methods:'GET'},{headers:'authorization'},{fields:'password'},
    {allowPrivateNetwork:'false'},{allowHTTPForTests:1},{typo:true},
    {sessionID:1},{target:'https://api.example.com/path'},{methods:['GET',1]},
    {headers:['bad header']},{refs:[123]},
  ])assert.throws(()=>new OperationEngine(new MemoryCredentialStore(),[{...grant,...patch} as any]),/INVALID_GRANTS/);
  assert.throws(()=>new OperationEngine(new MemoryCredentialStore(),[grant,grant] as any),/INVALID_GRANTS/);
  assert.throws(()=>new OperationEngine(new MemoryCredentialStore(),[{sessionID:'s',operation:'config.write',target:'/tmp/config.json',refs:[],fields:['__proto__.password']}]),/INVALID_GRANTS/);
});

test('accepted grants cannot be weakened by mutating the caller snapshot',async()=>{
  const grant={sessionID:'s',operation:'http' as const,target:'https://api.example.com',refs:[],methods:['GET'],headers:['authorization']};
  const engine=new OperationEngine(new MemoryCredentialStore(),[grant]);
  grant.methods.push('POST');grant.target='https://other.example.com';
  await assert.rejects(engine.http('s',{url:'https://other.example.com',method:'POST'}),/DENIED/);
  assert.throws(()=>engine.grants[0]!.methods!.push('POST'),TypeError);
});

test('quoted and prefixed assignments remove the complete credential while preserving safe text',()=>{
  const engine=new PrivacyEngine(parseConfig({piiPolicy:'off'}));
  for(const text of [
    'export DATABASE_PASSWORD="synthetic pass with spaces"',
    "AWS_SECRET_ACCESS_KEY='synthetic pass with spaces'",
    'TOKEN=ordinary-secret',
    'Authorization: Basic b3JkaW5hcnktc2VjcmV0',
  ])assert.ok(!String(engine.scrub(text)).includes('synthetic')&&!String(engine.scrub(text)).includes('ordinary-secret')&&!String(engine.scrub(text)).includes('b3JkaW5hcnktc2VjcmV0'));
  assert.equal(engine.scrub('MONKEY=public KEYBOARD=public PASSWORD_STORE_DIR=/tmp/store'),'MONKEY=public KEYBOARD=public PASSWORD_STORE_DIR=/tmp/store');
});

test('numeric and container credential fields are protected in objects and JSON text',()=>{
  const engine=new PrivacyEngine(parseConfig({piiPolicy:'off'}));
  for(const value of [123456,['ordinary-secret'],{value:'ordinary-secret'}]){
    const object={password:value,public:123456};
    assert.equal((engine.scrub(object) as any).password,'«credential»');
    assert.equal((engine.scrub(object) as any).public,123456);
    assert.equal(JSON.parse(String(engine.scrub(JSON.stringify(object)))).password,'«credential»');
  }
  assert.equal(JSON.parse(String(engine.scrub('1: {"password":123456}'.slice(3)))).password,'«credential»');
  assert.equal(engine.scrub('1: {"password":123456}'),'1: {"password":"«credential»"}');
});

test('reference protection does not bypass adjacent secrets or quoted JSON parsing',()=>{
  const engine=new PrivacyEngine(parseConfig({}));
  const ref='secret://12345678-1234-4234-8234-13800138000a';
  assert.equal(engine.scrub({password:ref}) && (engine.scrub({password:ref}) as any).password,ref);
  const clean=String(engine.scrub(ref+' TOKEN=ordinary-secret'));
  assert.ok(clean.includes(ref));assert.ok(!clean.includes('ordinary-secret'));
  const nested=JSON.stringify({input:JSON.stringify({password:ref})});
  assert.equal(JSON.parse(JSON.parse(String(engine.scrub(nested))).input).password,ref);
});

test('sensitive references preserve downgrade blocking across two independent sessions',async()=>{
  const hooks=createPrivacyHooks(parseConfig({enforceOpenRouterZdr:true}));
  const host:any={provider:{openrouter:{options:{fetch:async()=>new Response('{}')}}}};
  await hooks.config!(host);
  const ref='secret://12345678-1234-4234-8234-123456789abc';
  const params=(sessionID:string,providerID:string,url:string)=>({sessionID,model:{providerID,api:{url}},provider:{options:{baseURL:url}}} as any);
  await hooks['chat.message']!({sessionID:'a'} as any,{message:{},parts:[{type:'text',text:ref}]} as any);
  await hooks['chat.params']!(params('a','openrouter','https://openrouter.ai/api/v1'),{} as any);
  const status=JSON.parse(String(await hooks.tool!.privacy_status!.execute({}, {sessionID:'a'} as any)));
  assert.equal(status.posture.tier,'zdr-required');
  assert.equal(status.transports[0].requests,0);
  await hooks['chat.params']!(params('b','custom','https://model.example/v1'),{} as any);
  await assert.rejects(hooks['chat.params']!(params('a','custom','https://model.example/v1'),{} as any),/PRIVACY_DOWNGRADE/);
  // Deleting the session drops its sensitivity and its required posture.
  await hooks.event!({event:{type:'session.deleted',properties:{info:{id:'a'}}}} as any);
  await hooks['chat.params']!(params('a','custom','https://model.example/v1'),{} as any);
});

test('credential field masking preserves tool schema declarations at definition and transport',async()=>{
  const hooks=createPrivacyHooks(parseConfig({}));
  const schema={type:'object',properties:{password:{type:'string',description:'credential input'},token:{type:'string'}},required:['password']};
  const definition:any={description:'synthetic tool',parameters:schema};
  await hooks['tool.definition']!({} as any,definition);
  assert.deepEqual(definition.parameters,schema);
  let sent:any;
  const host:any={provider:{custom:{options:{fetch:async(req:Request)=>{sent=await req.json();return new Response('{}');}}}}};
  await hooks.config!(host);
  await host.provider.custom.options.fetch('https://model.example/v1',{method:'POST',body:JSON.stringify({tools:[{type:'function',function:{name:'sample',parameters:schema}}],messages:[{role:'user',content:'TOKEN=ordinary-secret'}]})});
  assert.deepEqual(sent.tools[0].function.parameters,schema);
  assert.ok(!JSON.stringify(sent.messages).includes('ordinary-secret'));
});

test('references embedded in opaque credential values do not exempt the complete value',()=>{
  const engine=new PrivacyEngine(parseConfig({piiPolicy:'off'}));
  const ref='secret://12345678-1234-4234-8234-123456789abc';
  for(const text of [`TOKEN="${ref} ordinarySampleSecret"`,`log: {"password":"${ref} ordinarySampleSecret"}`])
    assert.ok(!String(engine.scrub(text)).includes('ordinarySampleSecret'));
  assert.equal(engine.scrub(`TOKEN="${ref}"`),`TOKEN="${ref}"`);
});

test('schema instance examples and credential defaults are scrubbed without damaging declarations',async()=>{
  const hooks=createPrivacyHooks(parseConfig({piiPolicy:'off'}));
  const schema={type:'object',properties:{password:{type:'string',default:'ordinarySampleSecret',examples:['ordinarySampleSecret']}},examples:[{password:'ordinarySampleSecret'}]};
  const definition:any={description:'sample',parameters:schema};
  await hooks['tool.definition']!({} as any,definition);
  assert.equal(definition.parameters.properties.password.type,'string');
  assert.ok(!JSON.stringify(definition.parameters).includes('ordinarySampleSecret'));
  let sent:any;
  const host:any={provider:{custom:{options:{fetch:async(req:Request)=>{sent=await req.json();return new Response('{}');}}}}};
  await hooks.config!(host);
  await host.provider.custom.options.fetch('https://model.example/v1',{method:'POST',body:JSON.stringify({tools:[{type:'function',function:{name:'sample',parameters:schema}}]})});
  assert.equal(sent.tools[0].function.parameters.properties.password.type,'string');
  assert.ok(!JSON.stringify(sent).includes('ordinarySampleSecret'));
});

test('Gemini functionDeclarations preserve schemas and scrub instance examples',async()=>{
  let sent:any;
  const hooks=createPrivacyHooks(parseConfig({piiPolicy:'off'}));
  const host:any={provider:{google:{options:{fetch:async(req:Request)=>{sent=await req.json();return new Response('{}');}}}}};
  await hooks.config!(host);
  const schema={type:'object',properties:{password:{type:'string'}},examples:[{password:'ordinarySampleSecret'}]};
  await host.provider.google.options.fetch('https://model.example/v1',{method:'POST',body:JSON.stringify({tools:[{functionDeclarations:[{name:'login',parameters:schema}]}]})});
  assert.equal(sent.tools[0].functionDeclarations[0].parameters.properties.password.type,'string');
  assert.ok(!JSON.stringify(sent).includes('ordinarySampleSecret'));
});
