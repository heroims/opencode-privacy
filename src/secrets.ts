// Core credential rules are independent of PII policy and its allowlist.
const safeNames=new Set(['PASSWORD_STORE_DIR']);
export function sensitiveName(name:string):boolean {
  if(safeNames.has(name.toUpperCase()))return false;
  return /(?:^|[_-])(?:password|passwd|pwd|secret|token|credentials?|authorization|api[_-]?key|access[_-]?key|private[_-]?key)(?:$|[_-])/i.test(name)
    || /^(?:apikey|privatekey|clientsecret)$/i.test(name);
}

const prefixes:RegExp[]=[
  /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  /\bnpm_[A-Za-z0-9]{36,}\b/g,
  /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g,
  /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  /\b(?:gsk_|xai-|hf_|tvly-)[A-Za-z0-9_-]{20,}\b/g,
  /\b(?:dop_v1_|shpat_)[A-Za-z0-9_-]{32,}\b/g,
  /\bxapp-[A-Za-z0-9-]{10,}\b/g,
  /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----/g,
];
export function redactCredentialText(text:string):string {
  let out=text;
  for(const pattern of prefixes)out=out.replace(pattern,'«credential»');
  out=out.replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9+/._=-]+/gi,'«credential»');
  out=out.replace(/((?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|sftp|smtp|mssql):\/\/)[^\s/@:]+:[^\s/@]+@/gi,'$1«credential»@');
  out=out.replace(/([?&](?:access_token|refresh_token|api_key|token)=)[^\s&#"'<>]+/gi,'$1«credential»');
  // Consume complete quoted values, including spaces and escaped quotes.
  out=out.replace(/\b([A-Za-z_][A-Za-z0-9_-]*)\s*(?:=|:(?!\/\/))\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"'<>;,{}]+)/g,
    (match,name:string,encoded:string)=>{
      const value=/^["']/.test(encoded)?encoded.slice(1,-1):encoded;
      if(/^secret:\/\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value))return match;
      return sensitiveName(name)?`${name}=«credential»`:match;
    });
  return out;
}
