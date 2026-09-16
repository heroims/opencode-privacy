import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCli } from '../src/cli.js';
test('help requires no keychain and rejects passwords supplied on command line',async()=>{
  let output='';await runCli(['--help'],{write:s=>{output+=s;}});assert.match(output,/secret add/);
  await assert.rejects(runCli(['secret','add','password-in-argv'],{write:()=>{}}),/CLI_USAGE/);
});
test('init writes private local configuration and never overwrites existing policy',async()=>{
  const root=await mkdtemp(join(tmpdir(),'privacy-cli-'));
  try{
    await runCli(['init'],{directory:root,write:()=>{}});
    const config=JSON.parse(await readFile(join(root,'config.json'),'utf8'));
    assert.equal(config.brokerSocket,join(root,'broker.sock'));
    assert.equal((await stat(join(root,'config.json'))).mode&0o777,0o600);
    await assert.rejects(runCli(['init'],{directory:root,write:()=>{}}),/CLI_EXISTS/);
  }finally{await rm(root,{recursive:true,force:true});}
});
