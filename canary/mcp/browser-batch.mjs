import {randomUUID} from "node:crypto";
import {validBrowserPayload} from "./browser-operation-policy.mjs";

const CAPS=new Set(["vision","pdf","devtools","testing","network","storage","config"]);
const SENSITIVE=new Set([
  "browser_run_code_unsafe","browser_evaluate","browser_cdp_send",
  "browser_route","browser_route_list","browser_storage_state",
  "browser_configure","browser_network_set"
]);
const TARGET_DIR="D:\\ChatGPT-Local-Bridge\\staging\\ocn-playwright-full";
const CLIENT="D:\\ChatGPT-Local-Bridge\\tools\\ocn_playwright_user\\ocn_playwright_extended.py";
const USER="oliver";
const PERSISTENT_TOOLS=new Set([
  "browser_navigate","browser_snapshot","browser_click","browser_type",
  "browser_navigate_back","browser_tab_list","browser_tab_select",
  "browser_tabs","browser_wait_for","browser_find"
]);

function validPersistentStep(step){
  const {tool,arguments:args}=step;
  if(!PERSISTENT_TOOLS.has(tool))return false;
  if(tool==="browser_tabs"){
    if(args.action==="list")return Object.keys(args).length===1;
    if(args.action==="select")return Object.keys(args).length===2&&
      validBrowserPayload("browser_tab_select",{index:args.index});
    if(args.action==="new")return Object.keys(args).length===1||
      (Object.keys(args).length===2&&
       /^https?:\/\//.test(args.url)&&validBrowserPayload("browser_navigate",{url:args.url}));
    return false;
  }
  if(tool==="browser_wait_for"){
    if(Object.keys(args).length!==1)return false;
    if(typeof args.text==="string")return args.text.length>0&&args.text.length<=512;
    return typeof args.time==="number"&&Number.isFinite(args.time)&&
      args.time>0&&args.time<=20;
  }
  if(tool==="browser_find")return Object.keys(args).length===1&&
    typeof args.text==="string"&&args.text.length>0&&args.text.length<=512;
  if(tool==="browser_navigate"&&!/^https?:\/\//.test(args.url))return false;
  return validBrowserPayload(tool,args);
}

export const BROWSER_BATCH_TOOL={
  name:"browser_batch",
  description:"Execute 1-12 owner-authorized Playwright steps in Chrome Profile 6. By default each call is a separate short-lived MCP session (legacy behavior). Set reuse_session=true for 1-8 ordinary page/tab steps to use the owner-bound persistent BrowserSessionHost: its tabs survive between browser_batch calls, and the batch holds one browser lock. Advanced capabilities and file/download workflows retain the legacy one-shot mode. Returns a QUEUED command_id and nonce; poll_windows_operation for completion. Do not replay a failed state-changing batch without a page-state check.",
  inputSchema:{
    type:"object",
    properties:{
      steps:{type:"array",minItems:1,maxItems:12,items:{
        type:"object",properties:{
          tool:{type:"string",pattern:"^browser_[a-z][a-z0-9_]{0,80}$"},
          arguments:{type:"object",additionalProperties:true}
        },required:["tool","arguments"],additionalProperties:false
      }},
      capabilities:{type:"array",items:{type:"string",enum:[...CAPS]},uniqueItems:true},
      reuse_session:{type:"boolean",description:"Opt into the persistent Chrome Profile 6 session; 1-8 ordinary page/tab steps only."},
      unsafe_approved:{type:"boolean",description:"Only true after explicit approval for browser code execution, CDP, storage or traffic interception."}
    },
    required:["steps"],additionalProperties:false
  },
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:true}
};

function plainObject(value){return value!==null&&typeof value==="object"&&!Array.isArray(value);}
function exactKeys(obj,allowed){return Object.keys(obj).every(x=>allowed.includes(x));}

export function validBrowserBatch(args){
  if(!plainObject(args)||!exactKeys(args,["steps","capabilities","unsafe_approved","reuse_session"]))return false;
  if(!Array.isArray(args.steps)||args.steps.length<1||args.steps.length>12)return false;
  if(args.unsafe_approved!==undefined&&typeof args.unsafe_approved!=="boolean")return false;
  if(args.reuse_session!==undefined&&typeof args.reuse_session!=="boolean")return false;
  const caps=args.capabilities??[];
  if(!Array.isArray(caps)||caps.length>CAPS.size||caps.some(x=>!CAPS.has(x))||
     (new Set(caps)).size!==caps.length)return false;
  for(const step of args.steps){
    if(!plainObject(step)||Object.keys(step).length!==2||!exactKeys(step,["tool","arguments"])||
       typeof step.tool!=="string"||!/^browser_[a-z][a-z0-9_]{0,80}$/.test(step.tool)||
       !plainObject(step.arguments))return false;
    if(SENSITIVE.has(step.tool)&&args.unsafe_approved!==true)return false;
    // Browser file selection requires a path array (or no paths to cancel).
    if(step.tool==="browser_file_upload"&&"paths" in step.arguments&&
       (!Array.isArray(step.arguments.paths)||step.arguments.paths.length>30||
        step.arguments.paths.some(p=>typeof p!=="string"||p.length>32767)))return false;
  }
  if(args.reuse_session===true){
    if(args.steps.length>8||caps.length>0||args.unsafe_approved===true)return false;
    if(args.steps.some(step=>!validPersistentStep(step)))return false;
  }
  const size=Buffer.byteLength(JSON.stringify(args),"utf8");
  // Keep the encoded command well below the Windows CreateProcess 32767 character limit.
  return size<=15500;
}
export function buildBrowserBatchRequest(args,{id=randomUUID()}={}){
  if(!validBrowserBatch(args))throw new TypeError("INVALID_BROWSER_BATCH");
  if(args.reuse_session===true){
    return {operation:"browser_batch_persistent",payload:{steps:args.steps}};
  }
  if(!/^[a-f0-9-]{36}$/.test(id))throw new TypeError("INVALID_JOB_ID");
  const filename="ocn-browser-batch-"+id+".json";
  const legacyArgs={steps:args.steps};
  if(args.capabilities!==undefined)legacyArgs.capabilities=args.capabilities;
  if(args.unsafe_approved!==undefined)legacyArgs.unsafe_approved=args.unsafe_approved;
  const encoded=Buffer.from(JSON.stringify(legacyArgs),"utf8").toString("base64");
  // Only server-authored constants and Base64 enter PowerShell. No untrusted
  // JSON string is interpolated as source code. The JSON is deleted on completion.
  const script=[
    "$ErrorActionPreference='Stop'",
    "$dir='"+TARGET_DIR+"'",
    "$file=Join-Path $dir '"+filename+"'",
    "try {",
    "  [IO.File]::WriteAllBytes($file,[Convert]::FromBase64String('"+encoded+"'))",
    "  & python '"+CLIENT+"' --request $file",
    "  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
    "} finally {",
    "  if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }",
    "}"
  ].join(";\n");
  // One queue item; the existing user Agent retains claim, outbox and replay protections.
  return {operation:"powershell",payload:{
    run_as:USER,script,timeout_seconds:Math.min(480,180+40*args.steps.length),cwd:TARGET_DIR
  }};
}
