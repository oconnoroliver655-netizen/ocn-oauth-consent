import {BROWSER_OPERATIONS, validBrowserPayload} from "./browser-operation-policy.mjs";

// Existing single owner + existing Supabase queue + existing Windows Agent.
// No new Windows service, no new plugin, no extra secret on Render.
const EDGE="https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-owner-health-dispatch";
const OPERATIONS=[
  "file_read","file_read_lines","file_write","file_append",
  "powershell","exec","desktop_health","window_list","screenshot",
  "uia_tree","code_search","audit_recent","process_sessions",
  "terminal_sessions","desktop_lease_status",
  ...BROWSER_OPERATIONS
];
export const WINDOWS_TOOLS=[
  {
    name:"submit_windows_operation",
    description:"Run an owner-authorized Windows operation. IMPORTANT execution routing: noninteractive administrator/SYSTEM maintenance uses operation='powershell' and payload {run_as:'system',script:'...',timeout_seconds:30}; ordinary user scripts use run_as:'oliver' (the default). exec/process_start/terminal_start require explicit run_as:'system'. GUI/browser actions MUST stay in the limited interactive Desktop Agent, WITHOUT run_as. For simpler privileged scripts prefer the separate submit_admin_powershell tool. This is queued; poll_windows_operation with command_id and nonce for actual outcome. Never misreport 'queued' as completed.",
    inputSchema:{type:"object",properties:{
      operation:{type:"string",enum:OPERATIONS},
      payload:{type:"object",additionalProperties:true}
    },required:["operation","payload"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:false}
  },
  {
    name:"poll_windows_operation",
    description:"Return the result of an existing Windows command using its command_id and nonce. Read-only; never starts another command.",
    inputSchema:{type:"object",properties:{
      command_id:{type:"integer",minimum:1},
      nonce:{type:"string",pattern:"^[a-f0-9]{32}$"}
    },required:["command_id","nonce"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
  }
];
const pattern=/^[0-9a-f]{32}$/;
export function validWindowsCall(tool,args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  const keys=Object.keys(args).sort().join(",");
  if(tool==="poll_windows_operation")
    return keys==="command_id,nonce" && Number.isSafeInteger(args.command_id) &&
      args.command_id>0 && typeof args.nonce==="string" && pattern.test(args.nonce);
  if(tool==="submit_windows_operation")
    return keys==="operation,payload" && OPERATIONS.includes(args.operation) &&
      args.payload!==null&&typeof args.payload==="object"&&!Array.isArray(args.payload) &&
      (!BROWSER_OPERATIONS.includes(args.operation) ||
       validBrowserPayload(args.operation,args.payload));
  return false;
}
export async function callWindowsOperation(bearer,tool,args,{timeout_ms=30000}={}){
  if(typeof bearer!=="string"||!bearer.startsWith("Bearer ")||bearer.length>8200)
    return {unauthorized:true};
  if(!validWindowsCall(tool,args))return {error:"Invalid Windows operation arguments"};
  const payload=tool==="submit_windows_operation"?
    {action:tool,operation:args.operation,payload:args.payload}:
    {action:tool,command_id:args.command_id,nonce:args.nonce};
  try{
    const r=await fetch(EDGE,{method:"POST",
      headers:{"authorization":bearer,"content-type":"application/json"},
      body:JSON.stringify(payload),signal:AbortSignal.timeout(
        Number.isSafeInteger(timeout_ms)?Math.min(30000,Math.max(100,timeout_ms)):30000)});
    if(r.status===401)return {unauthorized:true};
    const response=await r.json();
    if(!r.ok||response?.ok!==true)return {error:response?.error||"Windows execution unavailable"};
    if(tool==="submit_windows_operation" &&
      (r.status!==202||!Number.isSafeInteger(response.command_id)||
        typeof response.nonce!=="string"||!pattern.test(response.nonce)||
        response.status!=="queued"))return {error:"Invalid Windows job receipt"};
    if(tool==="poll_windows_operation" &&
      (r.status!==200||!Number.isSafeInteger(response.command_id)||!response.status))
      return {error:"Invalid Windows result receipt"};
    return {value:response};
  }catch{return {error:"Windows execution service unavailable"};}
}

// One-call convenience for existing signed queue operations. An expired wait
// NEVER resubmits a task: the returned command_id and nonce remain pollable.
export const RUN_WINDOWS_TOOL={
  name:"run_windows_operation",
  description:"Submit one owner-authorized Windows task and wait up to 12 seconds for its verified receipt. Supports existing file, terminal, desktop and browser operation types; no additional permissions or execution worker. Returns terminal execution_state/detail when completed, otherwise the original command_id/nonce to continue with poll_windows_operation. Never interpret queued/claimed/running as success and never resubmit after a wait timeout.",
  inputSchema:{type:"object",properties:{
    operation:{type:"string",enum:OPERATIONS},
    payload:{type:"object",additionalProperties:true},
    wait_seconds:{type:"integer",minimum:0,maximum:12}
  },required:["operation","payload"],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:false}
};
// Queue terminal does not mean execution success. needs_review is an
// outcome-uncertain quarantine state and must never be automatically retried.
const TERMINAL_STATES=new Set(["completed","failed","cancelled","expired","needs_review"]);
export function validRunWindowsCall(args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  if(Object.keys(args).some(k=>!["operation","payload","wait_seconds"].includes(k)))return false;
  if("wait_seconds" in args && (!Number.isSafeInteger(args.wait_seconds)||
      args.wait_seconds<0||args.wait_seconds>12))return false;
  return validWindowsCall("submit_windows_operation",{operation:args.operation,payload:args.payload});
}
export async function runWindowsOperation(bearer,args,{
  invoke=callWindowsOperation,
  pause=ms=>new Promise(resolve=>setTimeout(resolve,ms)),
  now=()=>Date.now()
}={}){
  if(!validRunWindowsCall(args))return {error:"Invalid one-call Windows arguments"};
  const submitted=await invoke(bearer,"submit_windows_operation",
    {operation:args.operation,payload:args.payload});
  if(!submitted.value)return submitted;
  const original=submitted.value;
  const waitMs=(args.wait_seconds??8)*1000;
  if(!waitMs)return {value:{...original,terminal:false,wait_exhausted:true}};
  const deadline=now()+waitMs;
  while(now()<deadline){
    await pause(Math.min(600,Math.max(0,deadline-now())));
    const polled=await invoke(bearer,"poll_windows_operation",
      {command_id:original.command_id,nonce:original.nonce},
      {timeout_ms:Math.max(100,deadline-now())});
    if(polled.value){
      if(TERMINAL_STATES.has(polled.value.status))
        return {value:{...polled.value,command_id:original.command_id,
          nonce:original.nonce,terminal:true,wait_exhausted:false}};
    }else{
      // Submission is already committed; never hide its receipt or retry it.
      return {value:{...original,terminal:false,wait_interrupted:true,
        poll_error:polled.unauthorized?"AUTH_EXPIRED":"POLL_UNAVAILABLE"}};
    }
  }
  return {value:{...original,terminal:false,wait_exhausted:true}};
}

// Read-only, discoverable file operation. No shell, no new execution plane:
// the existing Windows Agent retains canonical path/authorization enforcement.
export const DIRECT_FILE_READ_TOOL={
  name:"read_file",
  description:"Read one absolute Windows file using OCN's owner-OAuth-bound native file_read agent operation; no PowerShell command or new permissions. Wait up to 12 seconds for a verified terminal receipt. If pending, use the SAME command_id/nonce with poll_windows_operation. Large files and denied paths follow the existing local agent limits.",
  inputSchema:{type:"object",properties:{
    path:{type:"string",minLength:3,maxLength:4096,
      description:"Absolute drive-qualified Windows path, e.g. D:\\projects\\README.md"},
    wait_seconds:{type:"integer",minimum:0,maximum:12}
  },required:["path"],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
};
export function validDirectFileReadCall(args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  if(Object.keys(args).some(k=>!["path","wait_seconds"].includes(k)))return false;
  // Reject relative, UNC/device and control-character paths at the MCP edge;
  // canonical containment and symlink checks remain the local agent's job.
  if(typeof args.path!=="string"||args.path.length<3||args.path.length>4096||
     !/^[A-Za-z]:[\\/]/.test(args.path)||/[\x00-\x1f\x7f]/.test(args.path))
    return false;
  return validRunWindowsCall({operation:"file_read",payload:{path:args.path},
    ...(args.wait_seconds===undefined?{}:{wait_seconds:args.wait_seconds})});
}
export function directFileReadToWindowsCall(args){
  if(!validDirectFileReadCall(args))throw new TypeError("Invalid file read arguments");
  return {operation:"file_read",payload:{path:args.path},
    wait_seconds:args.wait_seconds??8};
}

// Typed read-only tools reuse the exact authenticated native Windows agent.
// No shell fallback, new service, or alternate privilege plane is introduced.
const TEXT_ENCODINGS=new Set(["utf-8","utf-8-sig","gb18030","utf-16","utf-16-le","utf-16-be","latin-1"]);
function validReadOnlyPath(value){
  return typeof value==="string" && value.length>=3 && value.length<=4096 &&
    /^[A-Za-z]:[\\/]/.test(value) && !/[\x00-\x1f\x7f]/.test(value);
}
function validWait(args){
  return args.wait_seconds===undefined ||
    (Number.isSafeInteger(args.wait_seconds) &&
     args.wait_seconds>=0 && args.wait_seconds<=12);
}
export const DIRECT_FILE_LINES_TOOL={
  name:"read_file_lines",
  description:"Read a bounded page of lines from an absolute Windows file using OCN's owner-bound native file_read_lines operation. offset is a zero-based line index; a negative offset requests trailing lines under the installed agent's existing semantics. Returns content, total_lines and next_offset when completed, or the original command_id/nonce for polling. Never resubmit on timeout.",
  inputSchema:{type:"object",properties:{
    path:{type:"string",minLength:3,maxLength:4096},
    offset:{type:"integer",minimum:-1000,maximum:1000000},
    length:{type:"integer",minimum:1,maximum:1000},
    encoding:{type:"string",enum:[...TEXT_ENCODINGS]},
    wait_seconds:{type:"integer",minimum:0,maximum:12}
  },required:["path"],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
};
export function validDirectFileLinesCall(args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  if(Object.keys(args).some(k=>!["path","offset","length","encoding","wait_seconds"].includes(k)))
    return false;
  if(!validReadOnlyPath(args.path)||!validWait(args))return false;
  if(args.offset!==undefined && (!Number.isSafeInteger(args.offset)||
     args.offset< -1000||args.offset>1000000))return false;
  if(args.length!==undefined && (!Number.isSafeInteger(args.length)||
     args.length<1||args.length>1000))return false;
  if(args.encoding!==undefined && !TEXT_ENCODINGS.has(args.encoding))return false;
  return true;
}
export function directFileLinesToWindowsCall(args){
  if(!validDirectFileLinesCall(args))throw new TypeError("Invalid line read arguments");
  return {operation:"file_read_lines",payload:{
    path:args.path,offset:args.offset??0,length:args.length??100,
    encoding:args.encoding??"utf-8"
  },wait_seconds:args.wait_seconds??8};
}

export const DIRECT_CODE_SEARCH_TOOL={
  name:"search_code",
  description:"Search source/text under one absolute Windows file or directory using the existing owner-authorized native code_search operation. Supports literal or regex query, case sensitivity, filename glob and pagination. The Windows Agent enforces allowed paths and resource limits. Returns verified matches when completed or the original pollable command_id/nonce; never resubmits automatically.",
  inputSchema:{type:"object",properties:{
    path:{type:"string",minLength:3,maxLength:4096},
    query:{type:"string",minLength:1,maxLength:1024},
    use_regex:{type:"boolean"},
    case_sensitive:{type:"boolean"},
    filename_glob:{type:"string",maxLength:256},
    offset:{type:"integer",minimum:0,maximum:1000000},
    limit:{type:"integer",minimum:1,maximum:200},
    wait_seconds:{type:"integer",minimum:0,maximum:12}
  },required:["path","query"],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
};
export function validDirectCodeSearchCall(args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  if(Object.keys(args).some(k=>!["path","query","use_regex","case_sensitive",
      "filename_glob","offset","limit","wait_seconds"].includes(k)))return false;
  if(!validReadOnlyPath(args.path)||!validWait(args) ||
     typeof args.query!=="string"||args.query.length<1||args.query.length>1024 ||
     /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(args.query))return false;
  for(const flag of ["use_regex","case_sensitive"])
    if(args[flag]!==undefined && typeof args[flag]!=="boolean")return false;
  if(args.filename_glob!==undefined &&
     (typeof args.filename_glob!=="string"||args.filename_glob.length>256||
      /[\x00-\x1f\x7f]/.test(args.filename_glob)))return false;
  if(args.offset!==undefined && (!Number.isSafeInteger(args.offset)||
     args.offset<0||args.offset>1000000))return false;
  if(args.limit!==undefined && (!Number.isSafeInteger(args.limit)||
     args.limit<1||args.limit>200))return false;
  return true;
}
export function directCodeSearchToWindowsCall(args){
  if(!validDirectCodeSearchCall(args))throw new TypeError("Invalid code search arguments");
  return {operation:"code_search",payload:{
    path:args.path,query:args.query,
    use_regex:args.use_regex??false,
    case_sensitive:args.case_sensitive??false,
    filename_glob:args.filename_glob??"",
    offset:args.offset??0,limit:args.limit??50
  },wait_seconds:args.wait_seconds??8};
}

// Read-only session inventory using the existing owner-authorized Windows
// Agent. This does not start, stop or attach to any process/terminal.
const SESSION_OPERATIONS=new Map([
  ["list_process_sessions","process_sessions"],
  ["list_terminal_sessions","terminal_sessions"]
]);
export const DIRECT_SESSION_TOOLS=[...SESSION_OPERATIONS.keys()].map(name=>({
  name,
  description:name==="list_process_sessions"
    ?"List the existing native Windows process sessions (read only). Returns real session state only on verified completion, or the original command_id/nonce for polling. No process is started or terminated."
    :"List the existing native Windows terminal sessions (read only). Returns real terminal state only on verified completion, or the original command_id/nonce for polling. No terminal is started or terminated.",
  inputSchema:{type:"object",properties:{
    wait_seconds:{type:"integer",minimum:0,maximum:12}
  },additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
}));
export function validDirectSessionCall(name,args){
  return SESSION_OPERATIONS.has(name) && args!==null &&
    typeof args==="object" && !Array.isArray(args) &&
    Object.keys(args).every(k=>k==="wait_seconds") &&
    (args.wait_seconds===undefined ||
      (Number.isSafeInteger(args.wait_seconds) &&
       args.wait_seconds>=0 && args.wait_seconds<=12));
}
export function directSessionToWindowsCall(name,args){
  if(!validDirectSessionCall(name,args))throw new TypeError("Invalid session list arguments");
  return {operation:SESSION_OPERATIONS.get(name),payload:{},
    wait_seconds:args.wait_seconds??8};
}

// Discoverable alias for the existing owner-bound SYSTEM execution plane.
// It adds no elevated capability: the generic submit_windows_operation already
// supports this exact run_as value. Authentication and queue policy are unchanged.
export const ADMIN_POWERSHELL_TOOL={
  name:"submit_admin_powershell",
  description:"Run a noninteractive Windows PowerShell maintenance script as NT AUTHORITY\\SYSTEM via the existing Cloud Admin Agent. Use for Windows services, protected paths, scheduled tasks, and machine configuration. NOT for Chrome, windows, mouse, Flutter, GUI, or UAC secure desktop: use the Desktop Agent for interactive steps. Requires signed owner OAuth and existing local authorization policy. Returns only queued command_id and nonce; poll_windows_operation to get final status. Destructive or sensitive system changes still require appropriate authorization.",
  inputSchema:{type:"object",properties:{
    script:{type:"string",minLength:1,maxLength:131072},
    timeout_seconds:{type:"integer",minimum:1,maximum:1800},
    cwd:{type:"string",minLength:1,maxLength:4096}
  },required:["script"],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:false}
};
export function validAdminPowerShellCall(args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  const keys=Object.keys(args);
  if(keys.some(k=>!["script","timeout_seconds","cwd"].includes(k)))return false;
  if(typeof args.script!=="string"||!args.script.trim()||args.script.length>131072)return false;
  if("timeout_seconds" in args && (!Number.isInteger(args.timeout_seconds)||
      args.timeout_seconds<1||args.timeout_seconds>1800))return false;
  if("cwd" in args && (typeof args.cwd!=="string"||!args.cwd||args.cwd.length>4096))return false;
  return true;
}
export function adminPowerShellToWindowsCall(args){
  if(!validAdminPowerShellCall(args))throw new TypeError("Invalid admin PowerShell arguments");
  const payload={script:args.script,run_as:"system"};
  if(args.timeout_seconds!==undefined)payload.timeout_seconds=args.timeout_seconds;
  if(args.cwd!==undefined)payload.cwd=args.cwd;
  return {operation:"powershell",payload};
}
