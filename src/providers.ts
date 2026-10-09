import { isLocalEndpoint } from './vendor/pi-privacy/providers/catalog.js';
import { openRouterZdrPatch, veniceRequestPatch } from './vendor/pi-privacy/ext/patches.js';
export type Posture = {tier:'standard'|'loopback'|'tee-unverified'|'zdr-policy'|'zdr-required'|'zdr-enforced';evidence:string};
export function providerPosture(provider:string,baseURL?:string,zdrObserved=false):Posture {
  let host='';try{host=new URL(baseURL??'').hostname;}catch{}
  if(isLocalEndpoint(baseURL))return {tier:'loopback',evidence:'Loopback endpoint observed; may forward remotely. Credentials remain masked.'};
  if(provider==='openrouter'&&host==='openrouter.ai'&&zdrObserved)return {tier:'zdr-enforced',evidence:'ZDR constraints added at guarded fetch; server policy, not hardware attestation.'};
  if((provider==='tinfoil'&&host==='inference.tinfoil.sh')||(provider==='nearai'&&host==='cloud-api.near.ai'))return {tier:'tee-unverified',evidence:'Provider TEE claim; signature chain and inference connection not verified.'};
  if((provider==='venice'&&host==='api.venice.ai')||(provider==='privateer'&&host==='api.privateer.pro'))return {tier:'zdr-policy',evidence:'Upstream catalog policy claim; not independently verified.'};
  return {tier:'standard',evidence:'No verified data retention or execution guarantee.'};
}
const rank:Record<Posture['tier'],number>={standard:0,loopback:0,'tee-unverified':0,'zdr-policy':1,'zdr-required':2,'zdr-enforced':2};
export function checkDowngrade(previous:Posture|undefined,next:Posture,sensitive:boolean,policy:'off'|'warn'|'block'):void {
  if(sensitive&&previous&&rank[next.tier]<rank[previous.tier]&&policy!=='off')throw new Error('PRIVACY_DOWNGRADE');
}
export interface GuardOptions {
  provider:string;
  enforceZdr?:boolean;
  scrub:(value:unknown)=>Promise<unknown>;
  fetch?:typeof globalThis.fetch;
  observed?:(url:string,zdr:boolean)=>void;
}
export function guardedFetch(options:GuardOptions):typeof globalThis.fetch {
  const delegate=options.fetch??globalThis.fetch;
  return async(input,init)=>{
    try {
      const request=new Request(input,init);
      const url=new URL(request.url);
      if(url.username||url.password||!['https:','http:'].includes(url.protocol))throw new Error('PRIVACY_PROVIDER_TARGET');
      if(options.enforceZdr&&(url.origin!=='https://openrouter.ai'||!['/api/v1/chat/completions','/api/v1/responses'].includes(url.pathname)))throw new Error('PRIVACY_PROVIDER_TARGET');
      let body:string|undefined;
      if(request.body){
        const reader=request.body.getReader();const chunks:Uint8Array[]=[];let size=0;
        try {while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>4_000_000)throw new Error('PRIVACY_PROVIDER_SIZE');chunks.push(part.value);}}
        finally{await reader.cancel().catch(()=>{});}
        let parsed:unknown;
        try {parsed=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new Error('PRIVACY_PROVIDER_FORMAT');}
        parsed=await options.scrub(parsed);
        if(options.enforceZdr)parsed=openRouterZdrPatch(parsed);
        if(options.provider==='venice'&&url.origin==='https://api.venice.ai')parsed=veniceRequestPatch(parsed);
        body=JSON.stringify(parsed);
      }else if(options.enforceZdr)throw new Error('PRIVACY_PROVIDER_FORMAT');
      const headers=new Headers(request.headers);headers.delete('content-length');headers.delete('content-encoding');
      const outgoing=new Request(request.url,{method:request.method,headers,body,signal:request.signal,redirect:'error'});
      options.observed?.(url.origin,Boolean(options.enforceZdr));
      return await delegate(outgoing);
    } catch(error){
      const message=error instanceof Error?error.message:'';
      throw new Error(/^PRIVACY_[A-Z_]+$/.test(message)?message:'PRIVACY_PROVIDER_FAILED');
    }
  };
}
