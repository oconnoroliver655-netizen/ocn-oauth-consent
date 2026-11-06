import {BROWSER_OPERATIONS, validBrowserPayload} from "./browser-operation-policy.mjs";

// Existing single owner + existing Supabase queue + existing Windows Agent.
// No new Windows service, no new plugin, no extra secret on Render.
const EDGE="https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-owner-health-dispatch";
const OPERATIONS=[
  "file_read","file_read_lines","file_write","file_append",
  "powershell","exec","desktop_health","window_list","screenshot",
  "uia_tree","code_search","audit_recent","process_sessions","process_read",
  "terminal_sessions","terminal_read","desktop_lease_status",
  "desktop_lease_acquire","desktop_lease_renew","desktop_lease_release",
  ...BROWSER_OPERATIONS
];

const LEASE_OPERATIONS=new Set([
  "desktop_lease_acquire","desktop_lease_renew","desktop_lease_release"
]);
const validLeaseOwner=x=>typeof x==="string"&&
  /^[a-zA-Z0-9_.-]{3,128}$/.test(x);
const validLeaseId=x=>typeof x==="string"&&
  /^[a-zA-Z0-9_-]{20,80}$/.test(x);
export function validDesktopLeasePayload(operation,payload){
  if(!LEASE_OPERATIONS.has(operation)||!payload||
     typeof payload!=="object"||Array.isArray(payload))return false;
  const keys=Object.keys(payload);
  if(!validLeaseOwner(payload.owner))return false;
  if(operation==="desktop_lease_release")
    return keys.length===2 && keys.includes("owner") && keys.includes("lease_id") &&
      validLeaseId(payload.lease_id);
  const allowed=operation==="desktop_lease_acquire"?
    ["owner","ttl_seconds"]:["owner","lease_id","ttl_seconds"];
  if(keys.some(k=>!allowed.includes(k)))return false;
  if(operation==="desktop_lease_renew"&&!validLeaseId(payload.lease_id))return false;
  return payload.ttl_seconds===undefined ||
    (Number.isSafeInteger(payload.ttl_seconds)&&
     payload.ttl_seconds>=15&&payload.ttl_seconds<=300);
}

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
  },
  {
    name:"cancel_queued_windows_operation",
    description:"Atomically cancel one not-yet-claimed OCN Windows task. Requires the ORIGINAL command_id and nonce from submit/run. Only status=queued can change to cancelled. A claimed/uploading/completed task is NOT cancelled; the tool returns an explicit conflict, and its original receipt remains pollable. Duplicate calls for the same already-cancelled task are idempotent. It never stops a running process, resubmits a task or changes another task.",
    inputSchema:{type:"object",properties:{
      command_id:{type:"integer",minimum:1},
      nonce:{type:"string",pattern:"^[a-f0-9]{32}$"}
    },required:["command_id","nonce"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:false}
  }
];
const pattern=/^[0-9a-f]{32}$/;
export function validWindowsCall(tool,args){
  if(!args||typeof args!=="object"||Array.isArray(args))return false;
  const keys=Object.keys(args).sort().join(",");
  if(tool==="poll_windows_operation"||tool==="cancel_queued_windows_operation")
    return keys==="command_id,nonce" && Number.isSafeInteger(args.command_id) &&
      args.command_id>0 && typeof args.nonce==="string" && pattern.test(args.nonce);
  if(tool==="submit_windows_operation")
    return keys==="operation,payload" && OPERATIONS.includes(args.operation) &&
      args.payload!==null&&typeof args.payload==="object"&&!Array.isArray(args.payload) &&
      (!BROWSER_OPERATIONS.includes(args.operation) ||
       validBrowserPayload(args.operation,args.payload)) &&
      (!LEASE_OPERATIONS.has(args.operation) ||
       validDesktopLeasePayload(args.operation,args.payload));
  return false;
}
export async function callWindowsOperation(bearer,tool,args,{timeout_ms=30000,fetchFn=fetch}={}){
  if(typeof bearer!=="string"||!bearer.startsWith("Bearer ")||bearer.length>8200)
    return {unauthorized:true};
  if(!validWindowsCall(tool,args))return {error:"Invalid Windows operation arguments"};
  const payload=tool==="submit_windows_operation"?
    {action:tool,operation:args.operation,payload:args.payload}:
    {action:tool,command_id:args.command_id,nonce:args.nonce};
  try{
    const r=await fetchFn(EDGE,{method:"POST",
      headers:{"authorization":bearer,"content-type":"application/json"},
      body:JSON.stringify(payload),signal:AbortSignal.timeout(
        Number.isSafeInteger(timeout_ms)?Math.min(30000,Math.max(100,timeout_ms)):30000)});
    if(r.status===401)return {unauthorized:true};
    const response=await r.json();
    if(tool==="cancel_queued_windows_operation"){
      // A conflict is a valid, *negative* cancellation result, not success.
      if(r.status===409 && response?.ok===false &&
         response.command_id===args.command_id &&
         response.cancelled===false && typeof response.status==="string")
        return {conflict:response};
      if(!r.ok && r.status>=500)
        return {uncertain:{ok:false,command_id:args.command_id,
          cancelled:false,execution_outcome:"UNKNOWN",
          retry_same_reference:true,error:"CANCELLATION_RECEIPT_UNAVAILABLE"}};
    }
    if(!r.ok||response?.ok!==true)return {error:response?.error||"Windows execution unavailable"};
    if(tool==="submit_windows_operation" &&
      (r.status!==202||!Number.isSafeInteger(response.command_id)||
        typeof response.nonce!=="string"||!pattern.test(response.nonce)||
        response.status!=="queued"))return {error:"Invalid Windows job receipt"};
    if(tool==="poll_windows_operation" &&
      (r.status!==200||!Number.isSafeInteger(response.command_id)||!response.status))
      return {error:"Invalid Windows result receipt"};
    if(tool==="cancel_queued_windows_operation" &&
      (r.status!==200||response?.ok!==true ||
       response.command_id!==args.command_id || response.status!=="cancelled" ||
       response.cancelled!==true))
      return {error:"Invalid cancellation receipt"};
    return {value:response};
  }catch{
    if(tool==="cancel_queued_windows_operation")
      return {uncertain:{ok:false,command_id:args.command_id,
        cancelled:false,execution_outcome:"UNKNOWN",
        retry_same_reference:true,error:"CANCELLATION_RECEIPT_UNAVAILABLE"}};
    return {error:"Windows execution service unavailable"};
  }
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

// Explicit offsets make these session-output reads observational: the native
// Windows process and ConPTY readers advance their shared cursor ONLY for
// negative offsets. Session IDs are OCN's original signed operation nonces.
const SESSION_READ_OPERATIONS=new Map([
  ["read_process_output",{operation:"process_read",field:"session_id"}],
  ["read_terminal_output",{operation:"terminal_read",field:"terminal_id"}]
]);
export const SESSION_READ_TOOLS=[...SESSION_READ_OPERATIONS].map(([name,{field}])=>({
  name,
  description:name==="read_process_output"
    ?"Read up to 64 KiB of UTF-8 process output from an existing owner-created OCN session at an explicit byte offset, without changing the read cursor. Returns next_offset or the ORIGINAL task receipt for polling; no process launch, stdin or termination."
    :"Read up to 64 KiB of UTF-8 ConPTY output from an existing owner-created OCN terminal at an explicit byte offset, without changing the read cursor. Returns next_offset or the ORIGINAL task receipt for polling; no terminal launch, stdin or termination.",
  inputSchema:{type:"object",properties:{
    [field]:{type:"string",pattern:"^[0-9a-f]{32}$"},
    offset:{type:"integer",minimum:0,maximum:1000000000},
    max_bytes:{type:"integer",minimum:1,maximum:65536},
    wait_seconds:{type:"integer",minimum:0,maximum:12}
  },required:[field],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
}));
export function validSessionReadCall(name,args){
  const entry=SESSION_READ_OPERATIONS.get(name);
  if(!entry||!args||typeof args!=="object"||Array.isArray(args))return false;
  const allowed=[entry.field,"offset","max_bytes","wait_seconds"];
  if(Object.keys(args).some(k=>!allowed.includes(k)))return false;
  if(typeof args[entry.field]!=="string"||!pattern.test(args[entry.field]))
    return false;
  if(args.offset!==undefined && (!Number.isSafeInteger(args.offset)||
     args.offset<0||args.offset>1000000000))return false;
  if(args.max_bytes!==undefined && (!Number.isSafeInteger(args.max_bytes)||
     args.max_bytes<1||args.max_bytes>65536))return false;
  if(args.wait_seconds!==undefined && (!Number.isSafeInteger(args.wait_seconds)||
     args.wait_seconds<0||args.wait_seconds>12))return false;
  return true;
}
export function sessionReadToWindowsCall(name,args){
  if(!validSessionReadCall(name,args))throw new TypeError("Invalid session read arguments");
  const entry=SESSION_READ_OPERATIONS.get(name);
  return {operation:entry.operation,payload:{
    [entry.field]:args[entry.field],offset:args.offset??0,
    max_bytes:args.max_bytes??16384,wait_ms:0
  },wait_seconds:args.wait_seconds??8};
}


// Typed desktop observation: one owner-bound submission with a bounded wait.
// These tools do not focus windows, generate input or read screenshot pixels.
export const DESKTOP_OBSERVE_TOOLS=[
  {
    name:"desktop_window_list",
    description:"List bounded visible Windows top-level windows through the existing owner-OAuth Desktop Agent. No focus change or mouse input. Returns a terminal result or the original command_id/nonce for polling.",
    inputSchema:{type:"object",properties:{
      query:{type:"string",maxLength:80},
      limit:{type:"integer",minimum:1,maximum:100},
      wait_seconds:{type:"integer",minimum:0,maximum:12}
    },additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
  },
  {
    name:"desktop_uia_tree",
    description:"Read bounded UI Automation nodes under one exact live HWND. Read-only; never invokes a control or changes focus. Returns a verified result or the original command_id/nonce for polling.",
    inputSchema:{type:"object",properties:{
      hwnd:{type:"integer",minimum:1},
      max_depth:{type:"integer",minimum:0,maximum:6},
      max_nodes:{type:"integer",minimum:1,maximum:250},
      wait_seconds:{type:"integer",minimum:0,maximum:12}
    },required:["hwnd"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
  }
];
export function validDesktopObserveCall(name,args){
  if(!args||typeof args!=="object"||Array.isArray(args)||!validWait(args))return false;
  const keys=Object.keys(args);
  if(name==="desktop_window_list"){
    if(keys.some(k=>!["query","limit","wait_seconds"].includes(k)))return false;
    if(args.query!==undefined && (typeof args.query!=="string"||
       args.query.length>80||/[\x00-\x1f\x7f]/.test(args.query)))return false;
    return args.limit===undefined||
      (Number.isSafeInteger(args.limit)&&args.limit>=1&&args.limit<=100);
  }
  if(name==="desktop_uia_tree"){
    if(keys.some(k=>!["hwnd","max_depth","max_nodes","wait_seconds"].includes(k)))return false;
    if(!Number.isSafeInteger(args.hwnd)||args.hwnd<=0)return false;
    if(args.max_depth!==undefined &&
      (!Number.isSafeInteger(args.max_depth)||args.max_depth<0||args.max_depth>6))return false;
    return args.max_nodes===undefined ||
      (Number.isSafeInteger(args.max_nodes)&&args.max_nodes>=1&&args.max_nodes<=250);
  }
  return false;
}
export function desktopObserveToWindowsCall(name,args){
  if(!validDesktopObserveCall(name,args))
    throw new TypeError("Invalid desktop observation arguments");
  return name==="desktop_window_list"?
    {operation:"window_list",payload:{query:args.query??"",limit:args.limit??100},
      wait_seconds:args.wait_seconds??8}:
    {operation:"uia_tree",payload:{hwnd:args.hwnd,
      max_depth:args.max_depth??4,max_nodes:args.max_nodes??150},
      wait_seconds:args.wait_seconds??8};
}

// Desktop ownership is a coordination lease, not an OAuth or Windows privilege.
// Input operations are intentionally NOT exposed until the native agent enforces
// a positive active-lease + HWND/PID/foreground binding on every action.
export const DESKTOP_LEASE_TOOLS=[
  {
    name:"desktop_lease_acquire",
    description:"Acquire the existing exclusive Windows desktop input lease for a named OCN worker (15–300 seconds). No mouse/keyboard action. Returns the coordination lease ID only to the signed owner, or the original task receipt for polling.",
    inputSchema:{type:"object",properties:{
      owner:{type:"string",pattern:"^[a-zA-Z0-9_.-]{3,128}$"},
      ttl_seconds:{type:"integer",minimum:15,maximum:300},
      wait_seconds:{type:"integer",minimum:0,maximum:12}
    },required:["owner"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false}
  },
  {
    name:"desktop_lease_renew",
    description:"Renew only the caller's matching current desktop coordination lease. Does not touch windows or simulate input; receipt must be terminal verified.",
    inputSchema:{type:"object",properties:{
      owner:{type:"string",pattern:"^[a-zA-Z0-9_.-]{3,128}$"},
      lease_id:{type:"string",pattern:"^[a-zA-Z0-9_-]{20,80}$"},
      ttl_seconds:{type:"integer",minimum:15,maximum:300},
      wait_seconds:{type:"integer",minimum:0,maximum:12}
    },required:["owner","lease_id"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false}
  },
  {
    name:"desktop_lease_release",
    description:"Release only the matching current desktop coordination lease. The lease ID is never a substitute for OAuth identity. Pending tasks are never replayed.",
    inputSchema:{type:"object",properties:{
      owner:{type:"string",pattern:"^[a-zA-Z0-9_.-]{3,128}$"},
      lease_id:{type:"string",pattern:"^[a-zA-Z0-9_-]{20,80}$"},
      wait_seconds:{type:"integer",minimum:0,maximum:12}
    },required:["owner","lease_id"],additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false}
  }
];
export function validDesktopLeaseCall(name,args){
  if(!LEASE_OPERATIONS.has(name)||!args||typeof args!=="object"||
     Array.isArray(args)||!validWait(args))return false;
  const {wait_seconds,...payload}=args;
  return validDesktopLeasePayload(name,payload);
}
export function desktopLeaseToWindowsCall(name,args){
  if(!validDesktopLeaseCall(name,args))
    throw new TypeError("Invalid desktop lease arguments");
  const {wait_seconds,...payload}=args;
  return {operation:name,payload,wait_seconds:wait_seconds??8};
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
