// Deterministic routing. This module does not grant Windows privileges.
const BROWSER=new Set(["browser_status","browser_connect","browser_tab_list","browser_snapshot",
 "browser_navigate","browser_click","browser_type","browser_navigate_back",
 "browser_tab_select","browser_disconnect"]);
const DESKTOP=new Set(["desktop_health","window_list","screenshot","uia_tree","desktop_lease_status"]);
const TYPED=new Set(["file_read","file_read_lines","file_write","file_append","code_search",
 "audit_recent","process_sessions","terminal_sessions"]);
const SYSTEM_LAUNCH=new Set(["exec","process_start","terminal_start"]);
const INTENTS=new Set(["auto","user","system_maintenance","interactive_admin"]);
const MAINTENANCE=new Set(["start-service","stop-service","restart-service","set-service",
 "new-service","remove-service","register-scheduledtask","unregister-scheduledtask",
 "set-scheduledtask","disable-scheduledtask","enable-scheduledtask",
 "enable-windowsoptionalfeature","disable-windowsoptionalfeature"]);
const isObj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const deny=reason=>Object.freeze({status:"refused",reason});
const planned=(execution_plane,operation,payload,reason)=>Object.freeze({
 status:"planned",execution_plane,operation,payload:Object.freeze({...payload}),reason});
function simpleServiceCommand(script){
 if(typeof script!=="string"||script.length>131072||!script.trim())return null;
 // Never auto-elevate compound commands, PowerShell expressions, pipelines or quoting.
 if(/[\r\n;|&\x60$#(){}<>"']/u.test(script))return null;
 const m=/^\s*([a-z][a-z\d-]*)\s+([a-z\d_.:-]+)\s*$/iu.exec(script);
 return m?m[1].toLowerCase():null;
}
export function planWindowsRoute(job){
 if(!isObj(job)||typeof job.operation!=="string"||
   Object.keys(job).some(k=>!["operation","payload","intent"].includes(k)))return deny("INVALID_JOB");
 const {operation}=job,payload=job.payload??{},intent=job.intent??"auto";
 if(!isObj(payload)||!INTENTS.has(intent))return deny("INVALID_PARAMETERS");
 if("run_as" in payload)return deny("RUN_AS_OWNED_BY_ROUTER");
 if(intent==="interactive_admin")return deny("INTERACTIVE_ADMIN_EXECUTOR_NOT_DEPLOYED");
 if(BROWSER.has(operation)||DESKTOP.has(operation)){
   if(intent==="system_maintenance")return deny("INTERACTIVE_CANNOT_USE_SESSION_0");
   return planned("desktop-user",operation,payload,"Requires logged-on user session");
 }
 if(operation==="powershell"){
   if(typeof payload.script!=="string"||!payload.script.trim()||payload.script.length>131072)
     return deny("INVALID_SCRIPT");
   if(Object.keys(payload).some(k=>!["script","cwd","timeout_seconds"].includes(k)))
     return deny("INVALID_POWERSHELL_FIELD");
   if(payload.timeout_seconds!==undefined&&(!Number.isInteger(payload.timeout_seconds)||
      payload.timeout_seconds<1||payload.timeout_seconds>1800))return deny("INVALID_TIMEOUT");
   if(payload.cwd!==undefined&&(typeof payload.cwd!=="string"||!payload.cwd.trim()))
      return deny("INVALID_WORKING_DIRECTORY");
   const inferred=intent==="auto"&&MAINTENANCE.has(simpleServiceCommand(payload.script));
   if(intent==="system_maintenance"||inferred)return planned("cloud-admin",operation,
     {...payload,run_as:"system"},inferred?"Single unambiguous maintenance cmdlet":"Explicit system maintenance");
   return planned("user-shell",operation,{...payload,run_as:"oliver"},"Least privilege");
 }
 if(SYSTEM_LAUNCH.has(operation)){
   if(intent!=="system_maintenance")return deny("EXPLICIT_SYSTEM_INTENT_REQUIRED");
   return planned("cloud-admin",operation,{...payload,run_as:"system"},"Explicit SYSTEM process");
 }
 if(TYPED.has(operation)){
   if(intent==="user")return deny("TYPED_OPERATION_OWNED_BY_SERVICE");
   return planned("cloud-admin",operation,payload,"Existing Cloud Admin typed command");
 }
 return deny("UNSUPPORTED_OPERATION");
}
export function toExistingWindowsCall(job){
 const plan=planWindowsRoute(job);
 if(plan.status!=="planned")return plan;
 return Object.freeze({status:"planned",tool:"submit_windows_operation",
  arguments:Object.freeze({operation:plan.operation,payload:plan.payload}),
  execution_plane:plan.execution_plane,reason:plan.reason});
}
