#!/usr/bin/env node
import { mkdir, readFile, writeFile, lstat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { defaults } from './config.js';
import { KeychainCredentialStore } from './credentials.js';
import { OperationEngine, type Grant } from './operations.js';
import { startBroker, BrokerClient } from './broker.js';

const HELP=`opencode-privacy (Node >=22.19.0)
  init                 Create private user config and empty grants file (no overwrite)
  secret add           Read a secret from hidden terminal input; print only its reference
  secret list          List opaque references, never values
  secret remove REF    Remove a saved reference (restart broker after changes)
  serve                Load Keychain + grants and start the local socket broker
  status               Query running broker counts
  --help               Show this help

Configuration: ~/.config/opencode-privacy/{config.json,grants.json,broker.sock}
Edit grants.json locally to authorize exact sessions, targets, operations and fields.
Restart the broker after changes. macOS secret storage requires Swift + Keychain.
No password arguments, raw resolver, remote listener or policy mutation RPC.
`;
interface CliIO {directory?:string;write?:(text:string)=>void;readSecret?:()=>Promise<string>;}
async function hiddenInput():Promise<string>{
  if(!process.stdin.isTTY||!process.stdout.isTTY)throw new Error('CLI_TTY_REQUIRED');
  process.stdout.write('Secret (hidden): ');
  return new Promise((resolve,reject)=>{
    let value='';const wasRaw=process.stdin.isRaw;process.stdin.setRawMode(true);process.stdin.resume();
    const finish=(error?:Error)=>{process.stdin.off('data',data);process.stdin.setRawMode(wasRaw);process.stdin.pause();process.stdout.write('\n');error?reject(error):resolve(value);};
    const data=(chunk:Buffer)=>{
      const text=chunk.toString('utf8');
      for(const char of text){
        if(char==='\u0003'||char==='\u0004'){finish(new Error('CLI_CANCELLED'));return;}
        if(char==='\r'||char==='\n'){finish();return;}
        if(char==='\u007f'||char==='\b'){value=Array.from(value).slice(0,-1).join('');continue;}
        if(char<' '){finish(new Error('CLI_INPUT'));return;}
        value+=char;if(value.length>65536){finish(new Error('CLI_INPUT'));return;}
      }
    };
    process.stdin.on('data',data);
  });
}
export async function runCli(args:string[],io:CliIO={}):Promise<void>{
  const write=io.write??(s=>process.stdout.write(s));
  const directory=io.directory??join(homedir(),'.config/opencode-privacy');
  if(!args.length||args[0]==='--help'){write(HELP);return;}
  if(args.length===1&&args[0]==='init'){
    await mkdir(directory,{recursive:true,mode:0o700});
    try{await writeFile(join(directory,'config.json'),JSON.stringify({...defaults,brokerSocket:join(directory,'broker.sock')},null,2)+'\n',{flag:'wx',mode:0o600});}
    catch(e){if((e as NodeJS.ErrnoException).code==='EEXIST')throw new Error('CLI_EXISTS');throw new Error('CLI_INIT');}
    try{await writeFile(join(directory,'grants.json'),'[]\n',{flag:'wx',mode:0o600});}
    catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw new Error('CLI_INIT');}
    write('Created local configuration. No operations authorized.\n');return;
  }
  if(args[0]==='secret'){
    if(!((args.length===2&&['add','list'].includes(args[1]!))||(args.length===3&&args[1]==='remove'&&/^secret:\/\/[a-f0-9-]{36}$/.test(args[2]!))))throw new Error('CLI_USAGE');
    const store=new KeychainCredentialStore();await store.load();
    if(args[1]==='list'){write(store.references().join('\n')+'\n');return;}
    if(args[1]==='remove'){store.remove(args[2]!);await store.save();write('Removed. Restart the broker.\n');return;}
    const secret=await (io.readSecret??hiddenInput)();const ref=store.add(secret);await store.save();write(ref+'\n');return;
  }
  if(args.length!==1||!['serve','status'].includes(args[0]!))throw new Error('CLI_USAGE');
  const socket=join(directory,'broker.sock');
  if(args[0]==='status'){write(JSON.stringify(await new BrokerClient(socket).status(),null,2)+'\n');return;}
  const path=join(directory,'grants.json');const info=await lstat(path);
  if(!info.isFile()||info.isSymbolicLink()||(info.mode&0o077)!==0||info.uid!==process.getuid?.()||info.size>1_000_000)throw new Error('CLI_GRANTS_PERMISSIONS');
  let grants:Grant[];try{const raw:unknown=JSON.parse(await readFile(path,'utf8'));if(!Array.isArray(raw)||raw.length>1000)throw new Error();grants=raw as Grant[];}catch{throw new Error('CLI_GRANTS');}
  const store=new KeychainCredentialStore();await store.load();
  const broker=await startBroker(socket,new OperationEngine(store,grants));
  write('Credential broker ready. Same-user trusted runtime; no raw credential retrieval.\n');
  let stopping=false;const stop=()=>{if(stopping)return;stopping=true;void broker.close().then(()=>{process.exitCode=0;}).catch(()=>{process.exitCode=1;});};
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  runCli(process.argv.slice(2)).catch(()=>{process.stderr.write('opencode-privacy: command failed; check usage, local permissions, grants, and Keychain access.\n');process.exitCode=1;});
}
