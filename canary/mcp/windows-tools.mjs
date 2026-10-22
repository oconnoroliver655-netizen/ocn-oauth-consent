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
export async function callWindowsOperation(bearer,tool,args){
  if(typeof bearer!=="string"||!bearer.startsWith("Bearer ")||bearer.length>8200)
    return {unauthorized:true};
  if(!validWindowsCall(tool,args))return {error:"Invalid Windows operation arguments"};
  const payload=tool==="submit_windows_operation"?
    {action:tool,operation:args.operation,payload:args.payload}:
    {action:tool,command_id:args.command_id,nonce:args.nonce};
  try{
    const r=await fetch(EDGE,{method:"POST",
      headers:{"authorization":bearer,"content-type":"application/json"},
      body:JSON.stringify(payload),signal:AbortSignal.timeout(30000)});
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
