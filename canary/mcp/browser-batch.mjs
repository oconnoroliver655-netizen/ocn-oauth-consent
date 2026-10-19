import {randomUUID} from "node:crypto";

const CAPS=new Set(["vision","pdf","devtools","testing","network","storage","config"]);
const SENSITIVE=new Set([
  "browser_run_code_unsafe","browser_evaluate","browser_cdp_send",
  "browser_route","browser_route_list","browser_storage_state",
  "browser_configure","browser_network_set"
]);
const TARGET_DIR="D:\\ChatGPT-Local-Bridge\\staging\\ocn-playwright-full";
const CLIENT="D:\\ChatGPT-Local-Bridge\\tools\\ocn_playwright_user\\ocn_playwright_extended.py";
const USER="oliver";

export const BROWSER_BATCH_TOOL={
  name:"browser_batch",
  description:"Execute 1-12 owner-authorized official Playwright MCP browser_* steps together on the existing Chrome Profile 6, including browser_file_upload, file drag-and-drop, screenshots, PDF export (pdf capability), dialogs and tabs. For short verified downloads, use browser_download_watch -> browser_click -> browser_download_verify. For long transfers, use browser_download_watch_async before the click; its job_id can be checked later with browser_download_status_async. The separate non-admin scheduled worker records durable file size/SHA-256 receipts without blocking the Agent claim loop. Uses the existing limited Windows user Agent. Returns a QUEUED command_id and nonce; poll_windows_operation for the actual result. No separate Chrome, SYSTEM or administrator access. Some code/network/storage tools require unsafe_approved=true. Uploading to a remote website may disclose selected files to that website.",
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
  if(!plainObject(args)||!exactKeys(args,["steps","capabilities","unsafe_approved"]))return false;
  if(!Array.isArray(args.steps)||args.steps.length<1||args.steps.length>12)return false;
  if(args.unsafe_approved!==undefined&&typeof args.unsafe_approved!=="boolean")return false;
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
  const size=Buffer.byteLength(JSON.stringify(args),"utf8");
  // Keep the encoded command well below the Windows CreateProcess 32767 character limit.
  return size<=15500;
}
export function buildBrowserBatchRequest(args,{id=randomUUID()}={}){
  if(!validBrowserBatch(args))throw new TypeError("INVALID_BROWSER_BATCH");
  if(!/^[a-f0-9-]{36}$/.test(id))throw new TypeError("INVALID_JOB_ID");
  const filename="ocn-browser-batch-"+id+".json";
  const encoded=Buffer.from(JSON.stringify(args),"utf8").toString("base64");
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
