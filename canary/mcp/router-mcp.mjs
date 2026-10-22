import {toExistingWindowsCall} from "./route-policy.mjs";
const OPS=["powershell","exec","file_read","file_read_lines","file_write","file_append",
 "code_search","audit_recent","process_sessions","terminal_sessions",
 "desktop_health","window_list","screenshot","uia_tree","desktop_lease_status",
 "browser_status","browser_connect","browser_tab_list","browser_snapshot",
 "browser_navigate","browser_click","browser_type","browser_navigate_back",
 "browser_tab_select","browser_disconnect"];
const ALLOWED=new Set(OPS), INTENTS=new Set(["auto","user","system_maintenance","interactive_admin"]);
export const ROUTED_WINDOWS_TOOL={
 name:"submit_routed_windows_operation",
 description:"Use this deterministic router for Windows tasks. It chooses Cloud Admin SYSTEM for a single explicit Windows-service/task management command or for noninteractive machine maintenance with intent='system_maintenance'; otherwise PowerShell uses the limited user account. Browser, UIA, screenshots and windows always stay in the interactive Desktop Agent. An elevated interactive GUI executor is NOT deployed, so intent='interactive_admin' refuses without side effects. The router cannot grant privileges, bypass UAC, or override local authorization. The result means queued only: poll_windows_operation for terminal status.",
 inputSchema:{type:"object",properties:{
   operation:{type:"string",enum:OPS},
   payload:{type:"object",additionalProperties:true},
   intent:{type:"string",enum:[...INTENTS]}
 },required:["operation","payload"],additionalProperties:false},
 securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
 annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:false}
};
export function validRoutedCall(args){
 return args!==null&&typeof args==="object"&&!Array.isArray(args)&&
   Object.keys(args).every(k=>["operation","payload","intent"].includes(k))&&
   ALLOWED.has(args.operation)&&!!args.payload&&typeof args.payload==="object"&&
   !Array.isArray(args.payload)&&(args.intent===undefined||INTENTS.has(args.intent));
}
export function prepareRoutedWindowsRequest(args){
 if(!validRoutedCall(args))return {ok:false,error:"INVALID_ROUTED_WINDOWS_ARGUMENTS"};
 const plan=toExistingWindowsCall(args);
 if(plan.status!=="planned")return {ok:false,error:plan.reason};
 return {ok:true,operation:plan.arguments.operation,payload:plan.arguments.payload,
   execution_plane:plan.execution_plane};
}
