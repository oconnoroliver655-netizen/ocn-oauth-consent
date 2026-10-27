import {validBrowserPayload} from "./browser-operation-policy.mjs";
const CAPS=new Set(["vision","pdf","devtools"]);
const EXTRA=Object.freeze({
  browser_mouse_click_xy:"vision",browser_mouse_down:"vision",
  browser_mouse_drag_xy:"vision",browser_mouse_move_xy:"vision",
  browser_mouse_up:"vision",browser_mouse_wheel:"vision",
  browser_pdf_save:"pdf",browser_annotate:"devtools",
  browser_hide_highlight:"devtools",browser_highlight:"devtools",
  browser_resume:"devtools",browser_start_recording:"devtools",
  browser_start_tracing:"devtools",browser_start_video:"devtools",
  browser_stop_recording:"devtools",browser_stop_tracing:"devtools",
  browser_stop_video:"devtools",browser_video_chapter:"devtools",
  browser_video_hide_actions:"devtools",browser_video_show_actions:"devtools"
});
const SENSITIVE=new Set([
  "browser_run_code_unsafe","browser_evaluate","browser_cdp_send",
  "browser_route","browser_route_list","browser_storage_state",
  "browser_configure","browser_network_set"
]);
export const BROWSER_BATCH_TOOL={
  name:"browser_batch",
  description:"Execute 1-12 owner-authorized Playwright steps in ONE persistent Chrome Profile 6 MCP session. Tabs persist across calls; uploads, downloads, vision/pdf/devtools all use the same serialized host. Supported advanced capabilities must be requested per job; browser script execution requires unsafe_approved=true. Poll command_id and nonce to terminal completion. Never blindly replay unknown partial browser effects.",
  inputSchema:{
    type:"object",properties:{
      steps:{type:"array",minItems:1,maxItems:12,items:{
        type:"object",properties:{
          tool:{type:"string",pattern:"^browser_[a-z][a-z0-9_]{0,80}$"},
          arguments:{type:"object",additionalProperties:true}
        },required:["tool","arguments"],additionalProperties:false
      }},
      capabilities:{type:"array",items:{type:"string",enum:[...CAPS]},uniqueItems:true},
      reuse_session:{type:"boolean",description:"Deprecated; accepted but every call now uses one persistent session."},
      unsafe_approved:{type:"boolean",description:"Explicit approval required for script/CDP/network/storage tools."}
    },required:["steps"],additionalProperties:false
  },
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:true}
};
function plain(value){return value!==null&&typeof value==="object"&&!Array.isArray(value);}
export function validBrowserBatch(args){
  if(!plain(args)||Object.keys(args).some(x=>!["steps","capabilities","unsafe_approved","reuse_session"].includes(x)))return false;
  if(!Array.isArray(args.steps)||args.steps.length<1||args.steps.length>12)return false;
  if(args.unsafe_approved!==undefined&&typeof args.unsafe_approved!=="boolean")return false;
  if(args.reuse_session!==undefined&&typeof args.reuse_session!=="boolean")return false;
  const caps=args.capabilities??[];
  if(!Array.isArray(caps)||caps.length>CAPS.size||caps.some(x=>!CAPS.has(x))||new Set(caps).size!==caps.length)return false;
  for(const step of args.steps){
    if(!plain(step)||Object.keys(step).length!==2||!Object.hasOwn(step,"tool")||!Object.hasOwn(step,"arguments")||
       typeof step.tool!=="string"||!/^browser_[a-z][a-z0-9_]{0,80}$/.test(step.tool)||!plain(step.arguments))return false;
    if(SENSITIVE.has(step.tool)&&args.unsafe_approved!==true)return false;
    if(EXTRA[step.tool]&&!caps.includes(EXTRA[step.tool]))return false;
    if((step.tool==="browser_file_upload"||step.tool==="browser_drop")&&"paths" in step.arguments&&
       (!Array.isArray(step.arguments.paths)||step.arguments.paths.length>30||
         step.arguments.paths.some(p=>typeof p!=="string"||p.length>32767)))return false;
  }
  const payload={steps:args.steps};
  if(args.capabilities!==undefined)payload.capabilities=args.capabilities;
  if(args.unsafe_approved!==undefined)payload.unsafe_approved=args.unsafe_approved;
  return new TextEncoder().encode(JSON.stringify(args)).length<=15500 &&
         validBrowserPayload("browser_batch_unified",payload);
}
export function buildBrowserBatchRequest(args){
  if(!validBrowserBatch(args))throw new TypeError("INVALID_BROWSER_BATCH");
  const payload={steps:args.steps};
  if(args.capabilities!==undefined)payload.capabilities=args.capabilities;
  if(args.unsafe_approved!==undefined)payload.unsafe_approved=args.unsafe_approved;
  return {operation:"browser_batch_unified",payload};
}
