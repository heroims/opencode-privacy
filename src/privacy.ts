import { redactPii, SECRET_TYPES } from './vendor/pi-privacy/pii/detect.js';
import { compileAllow } from './vendor/pi-privacy/pii/allow.js';
import { assessToolCall, sensitiveFileRefs } from './vendor/pi-privacy/ext/toolgate.js';
import type { PrivacyConfig } from './config.js';
import { sensitiveName, redactCredentialText } from './secrets.js';

const reference = /secret:\/\/[a-zA-Z0-9-]+/;
const completeReference=/^secret:\/\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const referenceSpans=/secret:\/\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![a-zA-Z0-9-])/g;
const LOCAL = new Set(['read','grep','glob','list','ls','edit','write','apply_patch']);
export const SECURE_TOOLS = new Set(['privacy_http','privacy_config_read','privacy_config_write']);

// Traversal does not stringify arbitrary objects or invoke their toJSON methods.
export function mapJson(value: unknown, transform: (text:string,key?:string)=>string, fieldMask?:(key:string,value:unknown)=>string|undefined): unknown {
  const seen = new Set<object>(); let count = 0;
  function walk(v: unknown, depth:number, key?:string):unknown {
    if (++count > 50000 || depth > 50) throw new Error('PRIVACY_SHAPE');
    if(key!==undefined){const masked=fieldMask?.(key,v);if(masked!==undefined)return masked;}
    if (typeof v === 'string') { if(v.length>4_000_000) throw new Error('PRIVACY_SIZE'); return transform(v,key); }
    if (v === null || v === undefined || typeof v === 'boolean' || typeof v === 'number') return v;
    if (typeof v !== 'object' || seen.has(v)) throw new Error('PRIVACY_SHAPE');
    if (!Array.isArray(v) && Object.getPrototypeOf(v) !== Object.prototype && Object.getPrototypeOf(v) !== null) throw new Error('PRIVACY_SHAPE');
    seen.add(v);
    let result:unknown;
    if (Array.isArray(v)) result=v.map(x=>walk(x,depth+1));
    else {
      const object: Record<string,unknown> = {};
      for (const [k,descriptor] of Object.entries(Object.getOwnPropertyDescriptors(v))) {
        if (!('value' in descriptor)) throw new Error('PRIVACY_SHAPE');
        const cleanKey=transform(k);
        if (Object.hasOwn(object,cleanKey)) throw new Error('PRIVACY_KEY_COLLISION');
        Object.defineProperty(object,cleanKey,{value:walk(descriptor.value,depth+1,k),enumerable:true,writable:true,configurable:true});
      }
      result=object;
    }
    seen.delete(v);return result;
  }
  return walk(value,0);
}
export class PrivacyEngine {
  private sessions = new Map<string,{tools:Set<string>; blocked:number; sensitive:boolean}>();
  constructor(readonly config: PrivacyConfig) {}
  private state(session:string) {
    let s=this.sessions.get(session);
    if(!s){ if(this.sessions.size>=1000) throw new Error('PRIVACY_SESSION_LIMIT'); s={tools:new Set(),blocked:0,sensitive:false};this.sessions.set(session,s); }
    return s;
  }
  forget(session:string){this.sessions.delete(session);}
  markSensitive(session:string){this.state(session).sensitive=true;}
  note(session:string,value:unknown){
    const clean=this.scrub(value,true);
    if(JSON.stringify(clean)!==JSON.stringify(value)||reference.test(JSON.stringify(value)??''))this.markSensitive(session);
  }
  hasSensitive(session:string){return this.state(session).sensitive;}
  scrub(value:unknown, includePii = this.config.piiPolicy !== 'off', sensitiveFields=true): unknown {
    const allow = compileAllow(this.config.piiAllow);
    const maskField=(key:string,v:unknown):string|undefined=>{
      if(sensitiveFields&&sensitiveName(key)&&v!==null&&v!==undefined&&v!==''&&!(typeof v==='string'&&completeReference.test(v)))return '«credential»';
      return undefined;
    };
    const scrubText=(text:string,skipPairs=false):string=>{
      // Decode complete JSON documents before inspecting fields, including numbers
      // and containers. Keep unchanged documents byte-for-byte intact.
      if(/^[\s]*[\[{]/.test(text)){
        let parsed:unknown;let json=false;try{parsed=JSON.parse(text);json=true;}catch{}
        if(json){const clean=mapJson(parsed,(s,key)=>scrubText(s,key===undefined),maskField);return JSON.stringify(clean)===JSON.stringify(parsed)?text:JSON.stringify(clean);}
      }
      // Inspect complete credential values before splitting reference spans.
      text=scrubCredentials(text,skipPairs);
      // Protect only complete reference spans; continue scanning adjacent text.
      let out='';let start=0;
      for(const match of text.matchAll(referenceSpans)){
        out+=scrubSegment(text.slice(start,match.index),skipPairs)+match[0];start=match.index!+match[0].length;
      }
      return out+scrubSegment(text.slice(start),skipPairs);
    };
    const scrubCredentials=(text:string,skipPairs=false):string=>{
      // Always redact credentials; a consumer PII allowlist must not bypass them.
      // Tool output is often text containing JSON, rather than a parsed object.
      // Scan every string token, including standalone array values, so matching
      // cannot begin at a closing quote. Consume escapes with the whole value.
      // A decoded array string is data, not a sibling JSON field declaration.
      // Complete nested JSON documents are handled above; do not reinterpret
      // bare quoted punctuation in an array as another object's credential.
      let out=skipPairs?text:text.replace(/("(?:\\.|[^"\\])*")(?:(\s*:\s*)("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null))?/g,
        (match,field:string,separator:string|undefined,encoded:string|undefined)=>{
          if(encoded===undefined)return match;
          try {
            const name:unknown=JSON.parse(field), value:unknown=JSON.parse(encoded);
            if(typeof name==='string' && maskField(name,value)!==undefined)
              return field+separator+'"«credential»"';
          } catch { /* Non-JSON text is handled by the assignment rules below. */ }
          return match;
        });
      return redactCredentialText(out);
    };
    const scrubSegment=(text:string,_skipPairs=false):string=>{
      let out=redactPii(text,SECRET_TYPES);
      if(includePii){out=redactPii(out,undefined,(type,v)=>!SECRET_TYPES.has(type)&&allow(type,v));out=out.replace(/(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)/g,match=>allow('phone',match)?match:'«cn-phone»');}
      return out;
    };
    return mapJson(value,text=>scrubText(text),maskField);
  }
  scrubSchema(value:unknown):unknown {
    const clean=this.scrub(value,this.config.piiPolicy!=='off',false);
    const instance=(v:unknown,property?:string)=>this.scrub(property?{[property]:v}:v);
    function unwrap(v:unknown,property?:string):unknown{return property?(v as Record<string,unknown>)[property]:v;}
    const walk=(v:unknown,property?:string):unknown=>{
      if(Array.isArray(v))return v.map(x=>walk(x,property));
      if(!v||typeof v!=='object')return v;
      const result:Record<string,unknown>={};
      for(const [key,child] of Object.entries(v)){
        let next:unknown;
        if(['default','const','enum','examples','example'].includes(key))next=(key==='enum'||key==='examples')&&Array.isArray(child)
          ?child.map(item=>unwrap(instance(item,property),property)):unwrap(instance(child,property),property);
        else if(key==='properties'&&child&&typeof child==='object'&&!Array.isArray(child)){
          const properties:Record<string,unknown>={};
          for(const [name,schema]of Object.entries(child))Object.defineProperty(properties,name,{value:walk(schema,name),enumerable:true,writable:true,configurable:true});
          next=properties;
        }else next=walk(child,property);
        Object.defineProperty(result,key,{value:next,enumerable:true,writable:true,configurable:true});
      }
      return result;
    };
    return walk(clean);
  }
  checkTool(session:string,name:string,args:unknown):void {
    const state=this.state(session);state.tools.add(name.replace(/[^\w.-]/g,'?').slice(0,100));
    const raw=JSON.stringify(args);
    if(typeof raw!=='string' || raw.length>4_000_000)throw new Error('PRIVACY_SHAPE');
    if(reference.test(raw)&&!SECURE_TOOLS.has(name)){state.blocked++;throw new Error('PRIVACY_REFERENCE_TOOL');}
    if(SECURE_TOOLS.has(name))return;
    const assessment=assessToolCall(name,args);
    const sensitive=JSON.stringify(this.scrub(args,true))!==raw;
    if(sensitive)state.sensitive=true;
    // Unknown/MCP tools may have a destination hidden in their implementation.
    const risky=!LOCAL.has(name);
    if(this.config.toolExfilPolicy!=='off' && risky && (sensitive || (assessment.egress && (assessment.sensitiveFiles?.length || sensitiveFileRefs(raw).length)))){
      state.blocked++;throw new Error('PRIVACY_TOOL_BLOCKED');
    }
  }
  status(session:string){const s=this.state(session);return {observedTools:[...s.tools].map(name=>({name,provenance:'unknown'})),blocked:s.blocked,sensitiveDetected:s.sensitive,scope:'observed calls only; not a network monitor'};}
}
