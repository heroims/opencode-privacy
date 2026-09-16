import { tool, type Hooks } from '@opencode-ai/plugin';
import { type PrivacyConfig } from './config.js';
import { PrivacyEngine, SECURE_TOOLS } from './privacy.js';
import { BrokerClient } from './broker.js';
import { guardedFetch, providerPosture, checkDowngrade, type Posture } from './providers.js';

export function createPrivacyHooks(config:PrivacyConfig,broker?:BrokerClient):Hooks {
  const engine=new PrivacyEngine(config);
  const transports=new Map<string,{origin?:string;zdr:boolean;requests:number}>();
  const sessionPostures=new Map<string,Posture>();
  async function scrub(value:unknown,session?:string):Promise<unknown>{
    if(session)engine.note(session,value);
    let masked=value;
    if(broker){try{masked=await broker.scrub(value);}catch{throw new Error('PRIVACY_BROKER_UNAVAILABLE');}}
    const clean=engine.scrub(masked);
    if(config.piiPolicy==='block'&&JSON.stringify(value)!==JSON.stringify(clean))throw new Error('PRIVACY_CONTENT_BLOCKED');
    // warn uses safe unattended behavior: redact, never silently release originals.
    return clean;
  }
  function checkMedia(value:unknown):void {
    if(!config.blockAttachments)return;
    function walk(v:unknown,depth=0):void {
      if(depth>50)throw new Error('PRIVACY_SHAPE');
      if(!v||typeof v!=='object')return;
      const o=v as Record<string,unknown>;
      if(o.type==='file'||o.type==='image'||o.type==='image_url'||o.type==='input_image'||o.type==='input_audio'||o.type==='input_file'||o.inlineData||o.fileData)throw new Error('PRIVACY_ATTACHMENT');
      for(const child of Object.values(o))walk(child,depth+1);
    }
    walk(value);
  }
  async function cleanParts(parts:unknown[],session?:string){checkMedia(parts);return await scrub(parts,session) as typeof parts;}
  function requireBroker(){if(!broker)throw new Error('PRIVACY_BROKER_REQUIRED');return broker;}
  async function secure(method:'http'|'configRead'|'configWrite',session:string,args:unknown):Promise<string>{
    try {return String(await scrub(await requireBroker()[method](session,args),session));}
    catch(e){const code=e instanceof Error?e.message:'';throw new Error(/^(?:PRIVACY_|BROKER_|DENIED$|UNSAFE_PATH$|VERSION_CONFLICT$|CONFIG_FAILED$|REDIRECT_DENIED$|HTTP_)[A-Z_]*$/.test(code)?code:'PRIVACY_OPERATION_FAILED');}
  }
  return {
    config:async host=>{
      // Wrap configured providers plus explicitly selected main/small providers.
      host.provider??={};
      for(const model of [host.model,host.small_model])if(typeof model==='string'&&model.includes('/'))host.provider[model.split('/')[0]!]??={};
      if(config.enforceOpenRouterZdr)host.provider.openrouter??={};
      for(const [id,provider]of Object.entries(host.provider)){
        if(!provider)continue;
        provider.options??={};const opts=provider.options as Record<string,unknown>;
        if(opts.fetch!==undefined&&typeof opts.fetch!=='function')throw new Error('PRIVACY_PROVIDER_FETCH');
        const state={origin:undefined as string|undefined,zdr:false,requests:0};transports.set(id,state);
        opts.fetch=guardedFetch({provider:id,enforceZdr:id==='openrouter'&&config.enforceOpenRouterZdr,
          fetch:opts.fetch as typeof fetch|undefined,
          scrub:async body=>{checkMedia(body);return scrub(body);},
          observed:(origin,zdr)=>{state.origin=origin;state.zdr=zdr;state.requests++;},
        });
      }
    },
    'chat.message':async(input,output)=>{output.parts=await cleanParts(output.parts,input.sessionID) as typeof output.parts;},
    'command.execute.before':async(input,output)=>{output.parts=await cleanParts(output.parts,input.sessionID) as typeof output.parts;},
    'experimental.chat.messages.transform':async(_input,output)=>{
      for(const message of output.messages)message.parts=await cleanParts(message.parts,message.info.sessionID) as typeof message.parts;
    },
    'experimental.chat.system.transform':async(input,output)=>{output.system=await scrub(output.system,input.sessionID) as string[];},
    'experimental.session.compacting':async(input,output)=>{
      output.context=await scrub(output.context,input.sessionID) as string[];
      if(output.prompt)output.prompt=String(await scrub(output.prompt,input.sessionID));
    },
    'experimental.text.complete':async(input,output)=>{output.text=String(await scrub(output.text,input.sessionID));},
    'tool.definition':async(_input,output)=>{
      output.description=String(await scrub(output.description));
      output.parameters=await scrub(output.parameters);
    },
    'tool.execute.before':async(input,output)=>{
      engine.checkTool(input.sessionID,input.tool,output.args);
      if(!SECURE_TOOLS.has(input.tool)&&broker){
        let clean:unknown;try{clean=await broker.scrub(output.args);}catch{throw new Error('PRIVACY_BROKER_UNAVAILABLE');}
        if(JSON.stringify(clean)!==JSON.stringify(output.args))throw new Error('PRIVACY_TOOL_BLOCKED');
      }
    },
    'tool.execute.after':async(input,output)=>{
      if(!output)return;
      checkMedia(output);
      const clean=await scrub(output,input.sessionID) as typeof output;
      Object.assign(output,clean);
    },
    'chat.params':async(input)=>{
      const id=input.model.providerID;
      const observed=transports.get(id);
      const configured=input.provider.options?.baseURL;
      const base=typeof configured==='string'?configured:input.model.api.url;
      const next=providerPosture(id,base,Boolean(observed?.zdr&&observed.origin===new URL(base).origin));
      checkDowngrade(sessionPostures.get(input.sessionID),next,engine.hasSensitive(input.sessionID),config.downgradePolicy);
      if(config.enforceOpenRouterZdr&&id==='openrouter'&&!observed)throw new Error('PRIVACY_ZDR_UNAVAILABLE');
      sessionPostures.set(input.sessionID,next);
    },
    event:async({event})=>{
      if(event.type==='session.deleted'){
        const id=(event.properties as {info?:{id?:string}}).info?.id;
        if(id){engine.forget(id);sessionPostures.delete(id);}
      }
    },
    tool:{
      privacy_status:tool({description:'Report privacy controls, observed tools and transport coverage. Does not change permissions or reveal credentials.',args:{},execute:async(_args,ctx)=>JSON.stringify({
        sessionID:ctx.sessionID,policy:{pii:config.piiPolicy,tools:config.toolExfilPolicy,downgrade:config.downgradePolicy,warnBehavior:'redact content / block sensitive operations without interactive approval'},
        ...engine.status(ctx.sessionID),posture:sessionPostures.get(ctx.sessionID)??{tier:'standard',evidence:'not observed'},
        transports:[...transports].map(([provider,state])=>({provider,requests:state.requests,zdrConstraintsObserved:state.zdr,coverage:'configured fetch path only'})),
        credentialBroker:broker?'configured (operations fail closed if unavailable)':'not configured',tee:'unsupported: no inference-bound cryptographic verifier',
      })}),
      privacy_http:tool({description:'Send an authorized HTTP request using secret:// references in approved headers. Grants bind this session, target, method and headers. No redirects.',args:{url:tool.schema.string(),method:tool.schema.string().optional(),headers:tool.schema.record(tool.schema.string(),tool.schema.string()).optional(),body:tool.schema.string().optional()},execute:(args,ctx)=>secure('http',ctx.sessionID,args)}),
      privacy_config_read:tool({description:'Read authorized JSON credential fields as stable secret:// references with a version for safe updating.',args:{path:tool.schema.string(),fields:tool.schema.array(tool.schema.string())},execute:(args,ctx)=>secure('configRead',ctx.sessionID,args)}),
      privacy_config_write:tool({description:'Update authorized JSON fields from secret:// references. Requires version from privacy_config_read and an explicit local grant.',args:{path:tool.schema.string(),version:tool.schema.string(),updates:tool.schema.record(tool.schema.string(),tool.schema.string())},execute:(args,ctx)=>secure('configWrite',ctx.sessionID,args)}),
    },
  };
}
