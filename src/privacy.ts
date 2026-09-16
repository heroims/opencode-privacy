import { detectPii, redactPii, SECRET_TYPES } from './vendor/pi-privacy/pii/detect.js';
import { compileAllow } from './vendor/pi-privacy/pii/allow.js';
import { assessToolCall, sensitiveFileRefs } from './vendor/pi-privacy/ext/toolgate.js';
import type { PrivacyConfig } from './config.js';

const sensitiveKey = /^(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|private[_-]?key|client[_-]?secret)$/i;
const reference = /secret:\/\/[a-zA-Z0-9-]+/;
const LOCAL = new Set(['read','grep','glob','list','ls','edit','write','apply_patch']);
export const SECURE_TOOLS = new Set(['privacy_http','privacy_config_read','privacy_config_write']);

// Traversal does not stringify arbitrary objects or invoke their toJSON methods.
export function mapJson(value: unknown, transform: (text:string,key?:string)=>string): unknown {
  const seen = new Set<object>(); let count = 0;
  function walk(v: unknown, depth:number, key?:string):unknown {
    if (++count > 50000 || depth > 50) throw new Error('PRIVACY_SHAPE');
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
  note(session:string,value:unknown){ if(this.scrub(value,true)!==value && JSON.stringify(this.scrub(value,true))!==JSON.stringify(value)) this.state(session).sensitive=true; }
  hasSensitive(session:string){return this.state(session).sensitive;}
  scrub(value:unknown, includePii = this.config.piiPolicy !== 'off'): unknown {
    const allow = compileAllow(this.config.piiAllow);
    return mapJson(value,(text,key)=>{
      if(key && sensitiveKey.test(key) && text && !/^secret:\/\/[a-zA-Z0-9-]+$/.test(text)) return '«credential»';
      // Always redact credentials; a consumer PII allowlist must not bypass them.
      let out=redactPii(text,SECRET_TYPES);
      out=out.replace(/\b(password|passwd|pwd|client_secret|api_key)\s*[:=]\s*(["']?)([^\s"'<>;,]+)\2/gi,(match,name,quote,value:string)=>value.startsWith('secret://')?match:`${name}=«credential»`);
      out=out.replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi,'$1«credential»@');
      if(includePii){out=redactPii(out,undefined,(type,v)=>!SECRET_TYPES.has(type)&&allow(type,v));out=out.replace(/(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)/g,'«cn-phone»');}
      return out;
    });
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
    if(this.config.toolExfilPolicy!=='off' && risky && (sensitive || (assessment.egress && sensitiveFileRefs(raw).length))){
      state.blocked++;throw new Error('PRIVACY_TOOL_BLOCKED');
    }
  }
  status(session:string){const s=this.state(session);return {observedTools:[...s.tools].map(name=>({name,provenance:'unknown'})),blocked:s.blocked,sensitiveDetected:s.sensitive,scope:'observed calls only; not a network monitor'};}
}
