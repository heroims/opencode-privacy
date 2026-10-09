import { tool, type Hooks } from '@opencode-ai/plugin';
import { type PrivacyConfig } from './config.js';
import { PrivacyEngine, SECURE_TOOLS } from './privacy.js';
import { BrokerClient } from './broker.js';
import { guardedFetch, providerPosture, checkDowngrade, type Posture } from './providers.js';

export function createPrivacyHooks(config:PrivacyConfig,broker?:BrokerClient):Hooks {
  const engine=new PrivacyEngine(config);
  const transports=new Map<string,{origin?:string;zdr:boolean;requests:number}>();
  const sessionPostures=new Map<string,Posture>();
  async function scrub(value:unknown,session?:string,sensitiveFields:boolean|'schema'=true):Promise<unknown>{
    if(session)engine.note(session,value);
    let masked=value;
    if(broker){try{masked=await broker.scrub(value);}catch{throw new Error('PRIVACY_BROKER_UNAVAILABLE');}}
    if(session&&JSON.stringify(masked)!==JSON.stringify(value))engine.markSensitive(session);
    const clean=sensitiveFields==='schema'?engine.scrubSchema(masked):engine.scrub(masked,config.piiPolicy!=='off',sensitiveFields);
    if(config.piiPolicy==='block'&&JSON.stringify(value)!==JSON.stringify(clean))throw new Error('PRIVACY_CONTENT_BLOCKED');
    // warn uses safe unattended behavior: redact, never silently release originals.
    return clean;
  }
  async function scrubTool(value:unknown):Promise<unknown>{
    if(!value||typeof value!=='object'||Array.isArray(value))return scrub(value);
    const {parameters,input_schema,function:fn,functionDeclarations,...metadata}=value as Record<string,unknown>;
    const clean=await scrub(metadata) as Record<string,unknown>;
    if(parameters!==undefined)clean.parameters=await scrub(parameters,undefined,'schema');
    if(input_schema!==undefined)clean.input_schema=await scrub(input_schema,undefined,'schema');
    if(fn!==undefined)clean.function=await scrubTool(fn);
    if(functionDeclarations!==undefined)clean.functionDeclarations=Array.isArray(functionDeclarations)
      ?await Promise.all(functionDeclarations.map(scrubTool)):await scrub(functionDeclarations);
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
          scrub:async body=>{
            checkMedia(body);
            // Preserve schema declarations while inspecting instance examples
            // and defaults with ordinary contextual credential rules.
            if(body&&typeof body==='object'&&!Array.isArray(body)&&Array.isArray((body as Record<string,unknown>).tools)){
              const {tools,...content}=body as Record<string,unknown>;
              return {...await scrub(content) as Record<string,unknown>,tools:await Promise.all((tools as unknown[]).map(scrubTool))};
            }
            return scrub(body);
          },
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
      try {
        output.parameters=await scrub(output.parameters,undefined,'schema');
      } catch (error) {
        // OpenCode may pass a host-owned schema instance/proxy here rather than a
        // plain JSON object. It contains static tool metadata, not user payload;
        // preserve it so one non-plain schema cannot abort the whole model turn.
        if (!(error instanceof Error) || error.message!=='PRIVACY_SHAPE') throw error;
      }
    },
    'tool.execute.before':async(input,output)=>{
      engine.checkTool(input.sessionID,input.tool,output.args);
      if(!SECURE_TOOLS.has(input.tool)&&broker){
        let clean:unknown;try{clean=await broker.scrub(output.args);}catch{throw new Error('PRIVACY_BROKER_UNAVAILABLE');}
        if(JSON.stringify(clean)!==JSON.stringify(output.args)){engine.markSensitive(input.sessionID);throw new Error('PRIVACY_TOOL_BLOCKED');}
      }
    },
    'tool.execute.after':async(input,output)=>{
      if(!output)return;
      checkMedia(output);
      const clean=await scrub(output,input.sessionID) as typeof output;
      for(const key of Object.keys(output))if(!Object.hasOwn(clean,key))delete (output as Record<string,unknown>)[key];
      Object.assign(output,clean);
    },
    'chat.params':async(input)=>{
      const id=input.model.providerID;
      const observed=transports.get(id);
      const configured=input.provider.options?.baseURL;
      const base=typeof configured==='string'?configured:input.model.api.url;
      // Transport observations are provider-wide. A session's required policy
      // must exist before its first request, and must not borrow another
      // session's observation as proof of its own inference request.
      let next=providerPosture(id,base);
      if(config.enforceOpenRouterZdr&&id==='openrouter'){
        let origin:string;try{origin=new URL(base).origin;}catch{throw new Error('PRIVACY_PROVIDER_TARGET');}
        if(!observed)throw new Error('PRIVACY_ZDR_UNAVAILABLE');
        if(origin!=='https://openrouter.ai')throw new Error('PRIVACY_PROVIDER_TARGET');
        next={tier:'zdr-required',evidence:'ZDR constraints required on the configured guarded fetch path. Provider-wide observations are reported separately; no session-bound inference verification.'};
      }
      checkDowngrade(sessionPostures.get(input.sessionID),next,engine.hasSensitive(input.sessionID),config.downgradePolicy);
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
