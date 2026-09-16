import {createServer} from 'node:http';
import {mkdtemp,writeFile,readFile,mkdir,rm,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
const binary=process.env.OPENCODE_TEST_BINARY;
if(!binary)throw new Error('Set OPENCODE_TEST_BINARY to OpenCode 1.18.31 executable');
const root=await mkdtemp(join(tmpdir(),'opencode-privacy-host-'));
const token='ghp_'+ 'F'.repeat(36);const requests=[];
const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  if(req.method!=='POST'){res.setHeader('content-type','application/json');res.end('{"data":[]}');return;}
  requests.push(body);
  res.setHeader('content-type','text/event-stream');
  res.write('data: '+JSON.stringify({id:'fixture',object:'chat.completion.chunk',created:1,model:'fixture',choices:[{index:0,delta:{role:'assistant',content:'Privacy integration complete.'},finish_reason:null}]})+'\n\n');
  res.write('data: '+JSON.stringify({id:'fixture',object:'chat.completion.chunk',created:1,model:'fixture',choices:[{index:0,delta:{},finish_reason:'stop'}],usage:{prompt_tokens:10,completion_tokens:5,total_tokens:15}})+'\n\n');
  res.end('data: [DONE]\n\n');
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try{
  const config={plugin:[pathToFileURL(resolve('dist/plugin.js')).href],model:'privacytest/fixture',small_model:'privacytest/fixture',provider:{privacytest:{npm:'@ai-sdk/openai-compatible',name:'Privacy Test',options:{baseURL:`http://127.0.0.1:${server.address().port}/v1`,apiKey:'fixture-provider-auth'},models:{fixture:{name:'Fixture',limit:{context:32768,output:1024}}}}},permission:{bash:'deny',external_directory:'deny'}};
  await mkdir(join(root,'project'));
  await writeFile(join(root,'config.json'),JSON.stringify(config));await writeFile(join(root,'privacy.json'),'{}');
  const result=await new Promise((done,reject)=>{
    const child=spawn(binary,['run','--format','json','--model','privacytest/fixture',`Reply briefly. Here is a synthetic test token: ${token}`],{cwd:join(root,'project'),env:{...process.env,XDG_CONFIG_HOME:join(root,'config'),XDG_DATA_HOME:join(root,'data'),XDG_CACHE_HOME:join(root,'cache'),XDG_STATE_HOME:join(root,'state'),OPENCODE_CONFIG:join(root,'config.json'),OPENCODE_CONFIG_DIR:join(root,'config'),OPENCODE_PRIVACY_CONFIG:join(root,'privacy.json'),OPENCODE_DISABLE_MODELS_FETCH:'true',OPENCODE_DISABLE_DEFAULT_PLUGINS:'true',OPENCODE_DISABLE_AUTOUPDATE:'true'}});
    let stdout='',stderr='';child.stdout.on('data',x=>stdout+=x);child.stderr.on('data',x=>stderr+=x);
    const timeout=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('Host timeout; '+stderr.slice(-1500)));},90000);
    child.on('error',reject);child.on('close',code=>{clearTimeout(timeout);done({code,stdout,stderr});});
  });
  assert.equal(result.code,0,result.stderr.slice(-3000));
  assert.ok(requests.length>0,'No model requests captured: '+result.stdout+' '+result.stderr);
  assert.ok(requests.every(body=>!body.includes(token)),'Synthetic credential leaked into a model request');
  assert.ok(result.stdout.includes('Privacy integration complete.'),result.stdout);
  console.log(JSON.stringify({opencode:'1.18.31',modelRequests:requests.length,rawCredentialInRequests:false,assistantCompleted:true}));
}finally{await new Promise(resolve=>server.close(resolve));await rm(root,{recursive:true,force:true});}
