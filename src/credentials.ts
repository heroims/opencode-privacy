import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mapJson } from './privacy.js';

const REF=/^secret:\/\/[a-f0-9-]{36}$/;
export class MemoryCredentialStore {
  protected values=new Map<string,string>();
  add(value:string):string {
    if(typeof value!=='string'||!value.length||value.length>65536||value.includes('secret://'))throw new Error('INVALID_CREDENTIAL');
    for(const [ref,known]of this.values)if(known===value)return ref;
    if(this.values.size>=1000)throw new Error('CREDENTIAL_LIMIT');
    const ref='secret://'+randomUUID();this.values.set(ref,value);return ref;
  }
  resolve(ref:string):string {const value=this.values.get(ref);if(value===undefined)throw new Error('UNKNOWN_REFERENCE');return value;}
  remove(ref:string):void {if(!this.values.delete(ref))throw new Error('UNKNOWN_REFERENCE');}
  references():string[]{return [...this.values.keys()];}
  async save():Promise<void>{}
  scrub(value:unknown):unknown {
    const matches=new Map<string,string>();
    for(const [ref,secret]of this.values){
      const forms=[secret,encodeURIComponent(secret),JSON.stringify(secret).slice(1,-1),Buffer.from(secret).toString('base64'),Buffer.from(secret).toString('base64url')];
      for(const form of forms)if(form)matches.set(form,ref);
    }
    if(!matches.size)return mapJson(value,text=>text);
    const pattern=[...matches.keys()].sort((a,b)=>b.length-a.length).map(s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('|');
    const matcher=new RegExp(`secret:\\/\\/[a-f0-9-]{36}|${pattern}`,'g');
    return mapJson(value,text=>text.replace(matcher,match=>REF.test(match)?match:matches.get(match)!));
  }
}

// Fixed program; secret data crosses stdin/stdout only, never shell/argv.
const KEYCHAIN_SCRIPT=String.raw`
import Foundation
import Security
let input = FileHandle.standardInput.readDataToEndOfFile()
guard let obj = try? JSONSerialization.jsonObject(with: input) as? [String: String], let action = obj["action"] else { exit(2) }
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "opencode-privacy.v1", kSecAttrAccount as String: "vault"]
if action == "get" {
  var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
  var result: CFTypeRef?
  let status = SecItemCopyMatching(q as CFDictionary, &result)
  if status == errSecItemNotFound { exit(0) }
  guard status == errSecSuccess, let data = result as? Data else { exit(3) }
  FileHandle.standardOutput.write(data)
} else if action == "set", let value = obj["value"], let data = value.data(using: .utf8) {
  let update: [String: Any] = [kSecValueData as String: data]
  var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
  if status == errSecItemNotFound {
    var q = query; q[kSecValueData as String] = data
    status = SecItemAdd(q as CFDictionary, nil)
  }
  guard status == errSecSuccess else { exit(3) }
} else { exit(2) }
`;
export type KeychainRunner=(args:string[],input:string)=>Promise<string>;
const runKeychain:KeychainRunner=async(args,input)=>{
  if(process.platform!=='darwin')throw new Error('KEYCHAIN_UNSUPPORTED');
  return new Promise((resolve,reject)=>{
    const child=spawn('/usr/bin/swift',args,{stdio:['pipe','pipe','pipe']});let output='';let finished=false;
    const timer=setTimeout(()=>{child.kill();fail();},30000);
    const fail=()=>{if(!finished){finished=true;clearTimeout(timer);reject(new Error('KEYCHAIN_FAILED'));}};
    child.on('error',fail);child.stdin.on('error',fail);
    child.stdout.on('data',chunk=>{output+=String(chunk);if(output.length>8_000_000){child.kill();fail();}});
    child.stderr.resume();
    child.on('close',code=>{if(finished)return;if(code!==0){fail();return;}finished=true;clearTimeout(timer);resolve(output);});
    child.stdin.end(input);
  });
};
export class KeychainCredentialStore extends MemoryCredentialStore {
  constructor(private runner:KeychainRunner=runKeychain){super();}
  async load():Promise<void>{
    try{
      const data=await this.runner(['-e',KEYCHAIN_SCRIPT],JSON.stringify({action:'get'}));
      if(!data){this.values.clear();return;}
      const parsed:unknown=JSON.parse(data);
      if(!Array.isArray(parsed)||parsed.length>1000)throw new Error();
      const next=new Map<string,string>();
      for(const entry of parsed){
        if(!Array.isArray(entry)||entry.length!==2||typeof entry[0]!=='string'||!REF.test(entry[0])||typeof entry[1]!=='string'||!entry[1]||entry[1].length>65536||next.has(entry[0]))throw new Error();
        next.set(entry[0],entry[1]);
      }
      this.values=next;
    }catch{throw new Error('KEYCHAIN_LOAD_FAILED');}
  }
  override async save():Promise<void>{
    try{await this.runner(['-e',KEYCHAIN_SCRIPT],JSON.stringify({action:'set',value:JSON.stringify([...this.values])}));}
    catch{throw new Error('KEYCHAIN_SAVE_FAILED');}
  }
}
