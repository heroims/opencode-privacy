import { createHash, randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { BlockList, isIP } from 'node:net';
import { constants } from 'node:fs';
import { open, lstat, realpath, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve, parse } from 'node:path';
import { MemoryCredentialStore } from './credentials.js';

export interface Grant {
  sessionID:string;operation:'http'|'config.read'|'config.write';target:string;refs:string[];
  methods?:string[];headers?:string[];fields?:string[];allowPrivateNetwork?:boolean;allowHTTPForTests?:boolean;
}
const REF=/^secret:\/\/[a-f0-9-]{36}$/;
const object=(v:unknown):Record<string,unknown>=>{if(!v||typeof v!=='object'||Array.isArray(v))throw new Error('DENIED');return v as Record<string,unknown>;};
const text=(v:unknown):string=>{if(typeof v!=='string')throw new Error('DENIED');return v;};
const fields=(v:unknown):string[]=>{if(!Array.isArray(v)||!v.length||v.length>100||v.some(x=>typeof x!=='string'||!x||x.split('.').some((s:string)=>!s||['__proto__','constructor','prototype'].includes(s))))throw new Error('DENIED');return v as string[];};
const digest=(s:string)=>createHash('sha256').update(s).digest('hex');
function validateGrant(value:unknown):Grant {
  const fail=():never=>{throw new Error('INVALID_GRANTS');};
  if(!value||typeof value!=='object'||Array.isArray(value))return fail();
  const g=value as Record<string,unknown>;
  if(typeof g.sessionID!=='string'||!g.sessionID.trim()||g.sessionID.length>256||
    typeof g.target!=='string'||!['http','config.read','config.write'].includes(String(g.operation)))return fail();
  const http=g.operation==='http';
  const keys=http?['sessionID','operation','target','refs','methods','headers','allowPrivateNetwork','allowHTTPForTests']:['sessionID','operation','target','refs','fields'];
  if(Object.keys(g).some(key=>!keys.includes(key)))return fail();
  const strings=(v:unknown,check:(s:string)=>boolean):string[]=>{
    if(!Array.isArray(v)||v.length>1000||v.some(x=>typeof x!=='string'||!check(x))||new Set(v).size!==v.length)return fail();
    return [...v] as string[];
  };
  const refs=strings(g.refs,s=>REF.test(s));
  const result:Grant={sessionID:g.sessionID,operation:g.operation as Grant['operation'],target:g.target,refs};
  if(http){
    let url:URL;try{url=new URL(g.target);}catch{return fail();}
    if(!['http:','https:'].includes(url.protocol)||url.origin!==g.target||url.username||url.password)return fail();
    result.methods=strings(g.methods,s=>/^[A-Z]+$/.test(s));
    result.headers=strings(g.headers??[],s=>/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(s));
    if(!result.methods.length)return fail();
    for(const key of ['allowPrivateNetwork','allowHTTPForTests'] as const){
      if(g[key]!==undefined){if(typeof g[key]!=='boolean')return fail();result[key]=g[key];}
    }
  }else{
    if(!isAbsolute(g.target)||resolve(g.target)!==g.target)return fail();
    try{result.fields=[...fields(g.fields)];}catch{return fail();}
    if(new Set(result.fields).size!==result.fields.length)return fail();
  }
  for(const list of [result.refs,result.methods,result.headers,result.fields])if(list)Object.freeze(list);
  return Object.freeze(result);
}
const blocked=new BlockList();
for(const [address,prefix]of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.168.0.0',16],['192.0.0.0',24],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]] as const)blocked.addSubnet(address,prefix,'ipv4');
for(const [address,prefix]of [['::',128],['::1',128],['fc00::',7],['fe80::',10],['ff00::',8]] as const)blocked.addSubnet(address,prefix,'ipv6');
export class OperationEngine {
  private locks=new Set<string>();
  readonly grants:readonly Grant[];
  constructor(readonly store:MemoryCredentialStore,grants:Grant[]){
    if(!Array.isArray(grants)||grants.length>1000)throw new Error('INVALID_GRANTS');
    const validated=grants.map(validateGrant);
    const identities=validated.map(g=>JSON.stringify([g.sessionID,g.operation,g.target]));
    if(new Set(identities).size!==identities.length)throw new Error('INVALID_GRANTS');
    this.grants=Object.freeze(validated);
  }
  scrub(value:unknown){return this.store.scrub(value);}
  status(){return {credentials:this.store.references().length,grants:this.grants.length,scope:'same-user trusted runtime; not an OS sandbox'};}
  private grant(session:string,operation:Grant['operation'],target:string):Grant {
    const g=this.grants.find(x=>x.sessionID===session&&x.operation===operation&&x.target===target);
    if(!g)throw new Error('DENIED');return g;
  }
  async http(session:string,input:unknown):Promise<string>{
    try {
      const args=object(input);const url=new URL(text(args.url));const method=args.method===undefined?'GET':text(args.method).toUpperCase();
      if(url.username||url.password||url.hash||url.href.includes('secret:')||url.href.includes('secret%3A'))throw new Error('DENIED');
      const g=this.grant(session,'http',url.origin);
      if(url.protocol!=='https:'&&!(url.protocol==='http:'&&g.allowHTTPForTests===true))throw new Error('DENIED');
      if(!g.methods?.includes(method))throw new Error('DENIED');
      const headers:Record<string,string>={};
      for(const [key,value]of Object.entries(args.headers===undefined?{}:object(args.headers))){
        const name=key.toLowerCase();const raw=text(value);
        if(!g.headers?.map(x=>x.toLowerCase()).includes(name)||['host','connection','content-length','transfer-encoding','proxy-authorization','upgrade'].includes(name))throw new Error('DENIED');
        if(raw.includes('secret://')){if(!REF.test(raw)||!g.refs.includes(raw))throw new Error('DENIED');headers[name]=this.store.resolve(raw);}
        else {if(this.store.scrub(raw)!==raw)throw new Error('DENIED');headers[name]=raw;}
      }
      const body=args.body===undefined?undefined:text(args.body);
      if(body&&(body.length>1_000_000||body.includes('secret://')||this.store.scrub(body)!==body))throw new Error('DENIED');
      if(this.store.scrub(url.href)!==url.href)throw new Error('DENIED');
      const host=url.hostname.replace(/^\[|\]$/g,'');
      const addresses=isIP(host)?[{address:host,family:isIP(host)}]:await lookup(host,{all:true});
      if(!addresses.length||(g.allowPrivateNetwork!==true&&addresses.some(x=>blocked.check(x.address,x.family===6?'ipv6':'ipv4'))))throw new Error('DENIED');
      const chosen=addresses[0]!;
      // Pin the validated lookup result for this connection; no DNS re-resolution.
      const result=await new Promise<{status:number;body:string}>((resolveResult,reject)=>{
        let done=false;const fail=(code:string)=>{if(!done){done=true;reject(new Error(code));}};
        const req=(url.protocol==='https:'?httpsRequest:httpRequest)(url,{
          method,headers,agent:false,lookup:(_hostname,opts,callback)=>{
            if(opts.all)callback(null,[{address:chosen.address,family:chosen.family}]);
            else callback(null,chosen.address,chosen.family);
          },
        },res=>{
          if((res.statusCode??0)>=300&&(res.statusCode??0)<400){res.destroy();req.destroy();fail('REDIRECT_DENIED');return;}
          let size=0;const chunks:Buffer[]=[];
          res.on('data',chunk=>{size+=chunk.length;if(size>1_000_000){res.destroy();req.destroy();fail('RESPONSE_LIMIT');return;}chunks.push(Buffer.from(chunk));});
          res.on('error',()=>fail('HTTP_FAILED'));
          res.on('end',()=>{if(done)return;done=true;resolveResult({status:res.statusCode??0,body:Buffer.concat(chunks).toString('utf8')});});
        });
        const timeout=setTimeout(()=>{req.destroy();fail('HTTP_TIMEOUT');},15000);
        req.on('close',()=>clearTimeout(timeout));req.on('error',()=>fail('HTTP_FAILED'));req.end(body);
      });
      return JSON.stringify(this.store.scrub(result));
    }catch(e){const code=e instanceof Error?e.message:'';throw new Error(['DENIED','REDIRECT_DENIED','RESPONSE_LIMIT','HTTP_TIMEOUT'].includes(code)?code:'HTTP_FAILED');}
  }
  private async safePath(path:string):Promise<void>{
    if(!isAbsolute(path)||resolve(path)!==path)throw new Error('UNSAFE_PATH');
    let current=path;
    while(current!==parse(current).root){
      const info=await lstat(current);
      if(info.isSymbolicLink()){
        const systemAlias=(current==='/var'&&await realpath(current)==='/private/var')||(current==='/tmp'&&await realpath(current)==='/private/tmp');
        if(!systemAlias)throw new Error('UNSAFE_PATH');
      }
      current=dirname(current);
    }
  }
  private async readConfig(path:string):Promise<{content:string;data:Record<string,unknown>}>{
    await this.safePath(path);
    const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
    try{const info=await file.stat();if(!info.isFile()||info.size>1_000_000)throw new Error('UNSAFE_PATH');const content=await file.readFile('utf8');return {content,data:object(JSON.parse(content))};}
    finally{await file.close();}
  }
  async configRead(session:string,input:unknown):Promise<string>{
    try{
      const args=object(input);const path=text(args.path);const selected=fields(args.fields);const g=this.grant(session,'config.read',path);
      if(selected.some(f=>!g.fields?.includes(f)))throw new Error('DENIED');
      const {content,data}=await this.readConfig(path);const out:Record<string,string>={};
      for(const field of selected){let value:unknown=data;for(const part of field.split('.')){const parent=object(value);if(!Object.hasOwn(parent,part))throw new Error('DENIED');value=parent[part];}out[field]=this.store.add(text(value));}
      await this.store.save();
      return JSON.stringify({version:digest(content),fields:out});
    }catch(e){throw this.configError(e);}
  }
  async configWrite(session:string,input:unknown):Promise<string>{
    let lock:string|undefined;let temp:string|undefined;
    try{
      const args=object(input);const path=text(args.path);const updates=object(args.updates);const selected=fields(Object.keys(updates));const g=this.grant(session,'config.write',path);
      if(selected.some(f=>!g.fields?.includes(f)))throw new Error('DENIED');
      for(const ref of Object.values(updates))if(typeof ref!=='string'||!REF.test(ref)||!g.refs.includes(ref))throw new Error('DENIED');
      if(this.locks.has(path))throw new Error('VERSION_CONFLICT');this.locks.add(path);lock=path;
      const {content,data}=await this.readConfig(path);
      if(text(args.version)!==digest(content))throw new Error('VERSION_CONFLICT');
      for(const [field,ref]of Object.entries(updates)){
        const parts=field.split('.');let parent=data;
        for(const part of parts.slice(0,-1)){
          if(!Object.hasOwn(parent,part))parent[part]={};parent=object(parent[part]);
        }
        parent[parts.at(-1)!]=this.store.resolve(text(ref));
      }
      temp=join(dirname(path),'.privacy-'+randomUUID()+'.tmp');
      const file=await open(temp,'wx',0o600);
      try{await file.writeFile(JSON.stringify(data,null,2)+'\n');await file.sync();}finally{await file.close();}
      // Detect intervening writes immediately before rename; this is not OS-level CAS.
      const current=await this.readConfig(path);if(digest(current.content)!==text(args.version))throw new Error('VERSION_CONFLICT');
      await rename(temp,path);temp=undefined;
      return JSON.stringify({ok:true,version:digest(JSON.stringify(data,null,2)+'\n')});
    }catch(e){throw this.configError(e);}
    finally{if(temp)await unlink(temp).catch(()=>{});if(lock)this.locks.delete(lock);}
  }
  private configError(e:unknown):Error {const code=e instanceof Error?e.message:'';return new Error(['DENIED','UNSAFE_PATH','VERSION_CONFLICT'].includes(code)?code:'CONFIG_FAILED');}
}
