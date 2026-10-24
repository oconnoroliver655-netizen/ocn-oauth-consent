// Owner-OAuth REA MCP proxy. No REA runtime or credentials run on Render.
// All requests go through the signed existing Windows queue into the limited
// interactive owner session, where the isolated REA MCP bridge is installed.
import {callWindowsOperation} from "./windows-tools.mjs";

const ROOT="D:\\ChatGPT-Local-Bridge\\maintenance\\rea-integration";
const SCRIPT=ROOT+"\\rea-ocn.ps1";
const USER="oliver";
const LANES=["primary","secondary","tertiary"];
const ID=/^[0-9a-f]{32}$/;
const NAME=/^[a-zA-Z][a-zA-Z0-9_]{0,127}$/;
const promptMeta=[
  ["rea_status","Read REA V5 bridge health, session-lane readiness and catalog availability. Does not run analysis.",{},[],"Status"],
  ["rea_list_tools","List all locally registered REA tool names and descriptions; optional filter. For schemas use rea_describe_tool.",{filter:{type:"string",maxLength:120}},[],"List"],
  ["rea_describe_tool","Return the full input schema of a named REA tool.",{tool:{type:"string",pattern:NAME.source}},["tool"],"Describe"],
  ["rea_submit_tool","Queue any of the 207 REA tools by exact name, full arguments object and optional session lane. Returns a queued OCN command; poll_windows_operation for the REA request ID, then rea_poll for the finished REA receipt. Remote execution and changes, where permitted by REA, require owner OAuth.",{
    tool:{type:"string",pattern:NAME.source},
    arguments:{type:"object",additionalProperties:true},
    lane:{type:"string",enum:LANES}
  },["tool","arguments"],"Submit"],
  ["rea_poll","Read the local, complete REA execution receipt for a request ID. Large result payloads use integrity-checked chunks.",{request_id:{type:"string",pattern:ID.source}},["request_id"],"Poll"],
  ["rea_chunk","Read a numbered base64 result chunk and its SHA-256; reassemble and verify against rea_poll manifest.",{
    request_id:{type:"string",pattern:ID.source},
    chunk_index:{type:"integer",minimum:0,maximum:100000}
  },["request_id","chunk_index"],"Chunk"],
  ["rea_cancel","Request cancellation of a queued or in-flight REA task. Queued tasks are cancelled before dispatch; in-flight cancellation is best effort and does not guarantee child-process termination.",{request_id:{type:"string",pattern:ID.source}},["request_id"],"Cancel"],
  ["rea_list_prompts","List the six native REA MCP prompts and their required arguments.",{},[],"Prompts"],
  ["rea_get_prompt","Retrieve one native REA MCP prompt by name and optional prompt arguments. Does not execute the plan within that prompt.",{
    prompt_name:{type:"string",pattern:NAME.source},
    arguments:{type:"object",additionalProperties:true},
    lane:{type:"string",enum:LANES}
  },["prompt_name"],"GetPrompt"]
];
const mapping=new Map(promptMeta.map(([name,,schema,required,mode])=>[name,{schema,required,mode}]));
const readOnly=new Set(["rea_status","rea_list_tools","rea_describe_tool","rea_poll","rea_chunk","rea_list_prompts","rea_get_prompt"]);
export const REA_TOOLS=promptMeta.map(([name,description,properties,required])=>({
  name,description,
  inputSchema:{type:"object",properties,required,additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:readOnly.has(name),destructiveHint:name==="rea_submit_tool"||name==="rea_cancel",openWorldHint:name==="rea_submit_tool"}
}));
function object(v){return v!==null&&typeof v==="object"&&!Array.isArray(v);}
export function validReaCall(name,args){
  const spec=mapping.get(name);
  if(!spec||!object(args))return false;
  if(Object.keys(args).some(k=>!Object.hasOwn(spec.schema,k))||
     spec.required.some(k=>!Object.hasOwn(args,k)))return false;
  for(const [key,value] of Object.entries(args)){
    if(key==="tool"||key==="prompt_name"){
      if(typeof value!=="string"||!NAME.test(value))return false;
    }else if(key==="request_id"){
      if(typeof value!=="string"||!ID.test(value))return false;
    }else if(key==="filter"){
      if(typeof value!=="string"||value.length>120)return false;
    }else if(key==="lane"){
      if(!LANES.includes(value))return false;
    }else if(key==="chunk_index"){
      if(!Number.isSafeInteger(value)||value<0||value>100000)return false;
    }else if(key==="arguments"){
      if(!object(value))return false;
    }else return false;
  }
  // Sized to stay within Windows CreateProcess's command-line length limit.
  return Buffer.byteLength(JSON.stringify(args),"utf8")<=9600;
}
export function buildReaWindowsRequest(name,args){
  if(!validReaCall(name,args))throw new TypeError("INVALID_REA_REQUEST");
  const mode=mapping.get(name).mode;
  const data={Mode:mode};
  if(args.tool!==undefined)data.Tool=args.tool;
  if(args.prompt_name!==undefined)data.PromptName=args.prompt_name;
  if(args.filter!==undefined)data.Filter=args.filter;
  if(args.request_id!==undefined)data.RequestId=args.request_id;
  if(args.chunk_index!==undefined)data.ChunkIndex=args.chunk_index;
  if(args.lane!==undefined)data.Lane=args.lane;
  if(args.arguments!==undefined)data.ArgumentsJson=JSON.stringify(args.arguments);
  const b64=Buffer.from(JSON.stringify(data),"utf8").toString("base64");
  // Untrusted input is ONLY Base64 data; it is never inserted into PowerShell source.
  const script=[
    "$ErrorActionPreference='Stop'",
    "$json=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+b64+"'))",
    "$data=$json | ConvertFrom-Json",
    "$params=@{Mode=[string]$data.Mode}",
    "foreach($k in @('Tool','PromptName','Filter','RequestId','ChunkIndex','Lane','ArgumentsJson')){",
    " if($data.PSObject.Properties.Name -contains $k){$params[$k]=$data.$k}",
    "}",
    "& '"+SCRIPT+"' @params",
    "if(!$?){exit 1}"
  ].join(";\n");
  return {operation:"powershell",payload:{run_as:USER,script,timeout_seconds:25,cwd:ROOT}};
}
export async function callReaTool(bearer,name,args,delegate=callWindowsOperation){
  if(!validReaCall(name,args))return {error:"Invalid REA tool arguments"};
  return delegate(bearer,"submit_windows_operation",buildReaWindowsRequest(name,args));
}
