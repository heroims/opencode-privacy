import { createServer, request, type Server } from 'node:http';
import { chmod, lstat, mkdir } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import { OperationEngine } from './operations.js';

const errors=new Set(['DENIED','UNSAFE_PATH','VERSION_CONFLICT','CONFIG_FAILED','REDIRECT_DENIED','RESPONSE_LIMIT','HTTP_TIMEOUT','HTTP_FAILED','PRIVACY_SHAPE','PRIVACY_SIZE','PRIVACY_KEY_COLLISION']);
export async function startBroker(socketPath:string,engine:OperationEngine):Promise<{close:()=>Promise<void>}>{
  if(!isAbsolute(socketPath))throw new Error('BROKER_PATH');
  const parent=dirname(socketPath);await mkdir(parent,{recursive:true,mode:0o700});
  const info=await lstat(parent);
  if(!info.isDirectory()||info.isSymbolicLink()||(info.mode&0o077)!==0||info.uid!==process.getuid?.())throw new Error('BROKER_DIRECTORY');
  let active=0;
  const server:Server=createServer((req,res)=>{
    if(req.method!=='POST'||req.url!=='/'||active>=32){res.writeHead(400);res.end('{"error":"BROKER_REQUEST"}');return;}
    active++;let size=0;const chunks:Buffer[]=[];let finished=false;
    const finish=(body:unknown)=>{if(finished)return;finished=true;active--;res.setHeader('content-type','application/json');res.end(JSON.stringify(body));};
    req.on('data',chunk=>{size+=chunk.length;if(size>4_000_000){finish({error:'BROKER_SIZE'});req.destroy();return;}chunks.push(chunk);});
    req.on('error',()=>finish({error:'BROKER_REQUEST'}));
    req.on('end',async()=>{
      if(finished)return;
      try{
        const input=JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string,unknown>;
        let result:unknown;
        if(input.method==='scrub')result=engine.scrub(input.args);
        else if(input.method==='status')result=engine.status();
        else if(['http','configRead','configWrite'].includes(String(input.method))&&typeof input.sessionID==='string'){
          const method=input.method as 'http'|'configRead'|'configWrite';result=await engine[method](input.sessionID,input.args);
        }else throw new Error('DENIED');
        finish({result});
      }catch(e){const code=e instanceof Error?e.message:'';finish({error:errors.has(code)?code:'BROKER_FAILED'});}
    });
  });
  server.requestTimeout=20000;server.headersTimeout=10000;
  await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,()=>resolve());});
  await chmod(socketPath,0o600);
  return {close:()=>new Promise((resolve,reject)=>{server.close(error=>error?reject(error):resolve());server.closeIdleConnections();})};
}
export class BrokerClient {
  constructor(readonly socketPath:string){}
  private async call(method:string,args?:unknown,sessionID?:string):Promise<unknown>{
    return new Promise((resolve,reject)=>{
      const payload=JSON.stringify({method,args,sessionID});
      if(payload.length>4_000_000){reject(new Error('BROKER_SIZE'));return;}
      const req=request({socketPath:this.socketPath,path:'/',method:'POST',headers:{'content-type':'application/json'}},res=>{
        const chunks:Buffer[]=[];let size=0;
        res.on('data',chunk=>{size+=chunk.length;if(size>8_000_000){res.destroy();reject(new Error('BROKER_SIZE'));return;}chunks.push(chunk);});
        res.on('error',()=>reject(new Error('BROKER_UNAVAILABLE')));
        res.on('end',()=>{try{const response=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(response.error)reject(new Error(errors.has(response.error)?response.error:'BROKER_FAILED'));else resolve(response.result);}catch{reject(new Error('BROKER_FAILED'));}});
      });
      const timer=setTimeout(()=>{req.destroy();reject(new Error('BROKER_UNAVAILABLE'));},45000);
      req.on('close',()=>clearTimeout(timer));req.on('error',()=>reject(new Error('BROKER_UNAVAILABLE')));req.end(payload);
    });
  }
  scrub(value:unknown){return this.call('scrub',value);}
  async http(sessionID:string,args:unknown){return String(await this.call('http',args,sessionID));}
  async configRead(sessionID:string,args:unknown){return String(await this.call('configRead',args,sessionID));}
  async configWrite(sessionID:string,args:unknown){return String(await this.call('configWrite',args,sessionID));}
  status(){return this.call('status');}
}
