import {makeHandler, createBackend as createCiBackend, TOOLS as CI_TOOLS} from "./pr529-ci-guard.mjs";
import {WINDOWS_TOOLS,validWindowsCall,callWindowsOperation,ADMIN_POWERSHELL_TOOL,validAdminPowerShellCall,adminPowerShellToWindowsCall} from "./windows-tools.mjs";
import {ROUTED_WINDOWS_TOOL,validRoutedCall,prepareRoutedWindowsRequest} from "./router-mcp.mjs";
import {BROWSER_BATCH_TOOL,validBrowserBatch,buildBrowserBatchRequest} from "./browser-batch.mjs";
import {REA_TOOLS,validReaCall,callReaTool} from "./rea-tools.mjs";
import {MEMORY_TOOLS,validMemoryCall,callMemoryTool} from "./memory-tools.mjs";
import {OPTIONAL_DIAGNOSTIC_TOOL,validOptionalDiagnosticCall,prepareOptionalDiagnostic,planOptionalDiagnosticAdmission} from "./optional-diagnostic-admission.mjs";
const ciBackend = createCiBackend();
// Owner OAuth MCP endpoint: public ping and owner-bound Windows operations.
// Authentication remains in the signed Supabase OAuth validator.
// Authentication for each protected call remains in Supabase's signed ES256
// token validator, not in client-supplied JSON or this publicly exposed host.
import { createServer } from "node:http";
const DIRECT_BROWSER_OPERATIONS = Object.freeze([
  "browser_status","browser_connect","browser_tab_list","browser_snapshot"
]);
const DIRECT_BROWSER_TOOLS = DIRECT_BROWSER_OPERATIONS.map(name=>({
  name,
  description: "Owner-OAuth-bound browser operation. Queues execution exclusively in the existing limited interactive Windows Agent and returns command_id/nonce. Poll with poll_windows_operation; this does not establish Chrome connection by itself.",
  inputSchema: {type:"object",properties:{},additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{
    readOnlyHint:name!=="browser_connect",
    destructiveHint:false,
    openWorldHint:false
  }
}));
const PORT = Number(process.env.PORT || 10000);
const ORIGIN = process.env.OCN_PUBLIC_ORIGIN || "";
// Explicit browser origins only; OAuth bearer and owner checks are unchanged.
const TRUSTED_BROWSER_ORIGINS = new Set(["https://chatgpt.com","https://chat.openai.com"]);
// Bounded rejection telemetry only; never log Authorization, cookies, or request bodies.
let originAuditWindow = 0;
let originAuditCount = 0;
function auditRejectedBrowserOrigin(req) {
  const now = Date.now();
  if (now - originAuditWindow >= 60_000) { originAuditWindow = now; originAuditCount = 0; }
  if (originAuditCount++ >= 12) return;
  const raw = String(req.headers.origin ?? "");
  let safeOrigin = raw === "null" ? "null" : "noncanonical";
  try {
    const u = new URL(raw);
    if (raw.length <= 160 && u.origin === raw &&
        (u.protocol === "https:" || u.protocol === "http:") &&
        /^[a-z0-9.-]{1,120}$/i.test(u.hostname)) safeOrigin = raw;
  } catch { /* preserve noncanonical classification */ }
  console.warn(JSON.stringify({
    event:"ocn_origin_forbidden",
    route:req.url === "/mcp-oauth" ? "mcp-oauth" : "other",
    origin:safeOrigin,
    reason:req.url === "/mcp-ci-guard" ? "privileged_route_disallows_browser_origin" : "origin_not_allowlisted"
  }));
}
const VERSIONS = new Set(["2025-03-26","2025-06-18","2025-11-25","2026-07-28"]);
const ISSUER = "https://ouxniljtjxnrkwakkvbv.supabase.co/auth/v1";
// No application-layer fixed JSON body byte limit. Transport/runtime capacity still applies.
const HEALTH_EDGE = "https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-owner-health-dispatch";
const QUEUE_PRESSURE_TOOL = Object.freeze({
  name:"queue_pressure_status",
  description:"Read-only owner-OAuth queue pressure summary (no Windows task is submitted). Advisory: defer only optional duplicate diagnostics when congested; never block heartbeats, completion receipts or owner-authorized recovery.",
  inputSchema:{type:"object",properties:{},additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
});
function resource() {
  try {
    const u = new URL(ORIGIN);
    if (u.protocol !== "https:" || u.origin !== ORIGIN || u.pathname !== "/" ||
        u.username || u.password || u.search || u.hash) return null;
  } catch { return null; }
  return {resource:ORIGIN,authorization_servers:[ISSUER],scopes_supported:["openid","email"]};
}
function respond(res,status,value,extra={}) {
  res.writeHead(status,{
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    "content-security-policy":"default-src 'none'",
    ...(res._ocnTrustedBrowserOrigin ? {
      "access-control-allow-origin":res._ocnTrustedBrowserOrigin,
      "vary":"Origin"
    } : {}),
    ...(value===null?{}:{"content-type":"application/json; charset=utf-8"}),
    ...extra,
  });
  res.end(value===null?"":JSON.stringify(value));
}
const err=(id,code,message)=>({jsonrpc:"2.0",id,error:{code,message}});
const ok=(id,result)=>({jsonrpc:"2.0",id,result});
function toolList(oauthProbe=false){
  const listed = [
    {name:"ping",description:"Public protocol canary; no machine access.",
      inputSchema:{type:"object",properties:{},additionalProperties:false},
      securitySchemes:[{type:"noauth"}],
      annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}}
  ];
  if (oauthProbe) listed.push({
    name:"owner_auth_probe",
    description:"Check a signed, current owner OAuth session. Does not grant Windows tools.",
    inputSchema:{type:"object",properties:{},additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
  });
  if (oauthProbe) for (const [name,description,properties,required] of [
    ["submit_machine_health","Request a bounded owner/device-specific Windows health diagnostic; no files or shell.",{},[]],
    ["poll_machine_health","Check only a matching device-health command receipt and minimal readiness.",{
      command_id:{type:"integer",minimum:1},
      nonce:{type:"string",pattern:"^[0-9a-f]{32}$"}
    },["command_id","nonce"]]
  ]) listed.push({
    name,description,
    inputSchema:{type:"object",properties,required,additionalProperties:false},
    securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
    annotations:{readOnlyHint:name==="poll_machine_health",destructiveHint:false,openWorldHint:false}
  });
  // Reuse the already-installed OCN OAuth Probe plugin; no new ChatGPT plugin required.
  if (oauthProbe) listed.push(...CI_TOOLS,...WINDOWS_TOOLS,...DIRECT_BROWSER_TOOLS,BROWSER_BATCH_TOOL,...REA_TOOLS,...MEMORY_TOOLS,ADMIN_POWERSHELL_TOOL,ROUTED_WINDOWS_TOOL,QUEUE_PRESSURE_TOOL,OPTIONAL_DIAGNOSTIC_TOOL);
  return listed;
}
function ownerChallenge(){
  const challenge='Bearer resource_metadata="'+ORIGIN+
    '/.well-known/oauth-protected-resource", error="invalid_token", error_description="Verified owner OAuth session required", scope="openid email"';
  return {content:[{type:"text",text:"Verified owner OAuth session required."}],
          isError:true,_meta:{"mcp/www_authenticate":[challenge]}};
}
async function callHealthEdge(bearer,action,args){
  if (!bearer.startsWith("Bearer ") || bearer.length>8200) return {unauthorized:true};
  try{
    const payload=action==="poll_machine_health" ?
      {action,command_id:args.command_id,nonce:args.nonce} : {action};
    const response=await fetch(HEALTH_EDGE,{
      method:"POST",
      headers:{"content-type":"application/json","authorization":bearer},
      body:JSON.stringify(payload),
      signal:AbortSignal.timeout(8500),
    });
    const body=await response.json();
    if (response.status===401) return {unauthorized:true};
    if (response.status===429) return {error:"Device health diagnostic rate-limited"};
    if (!([200,202].includes(response.status) && body?.ok===true))
      return {error:"Device health diagnostic unavailable"};
    if (action==="submit_machine_health"){
      if (response.status!==202 || !Number.isSafeInteger(body.command_id) ||
          typeof body.nonce!=="string" || !/^[0-9a-f]{32}$/.test(body.nonce) ||
          body.status!=="queued") return {error:"Invalid health queue receipt"};
      return {value:{command_id:body.command_id,nonce:body.nonce,status:"queued"}};
    }
    if (response.status!==200 || !Number.isSafeInteger(body.command_id) ||
        !["queued","claimed","completed","failed","cancelled","expired"].includes(body.status) ||
        typeof body.ready!=="boolean") return {error:"Invalid health status receipt"};
    return {value:{command_id:body.command_id,status:body.status,ready:body.ready}};
  }catch{return {error:"Device health diagnostic unavailable"};}
}
async function callQueuePressureEdge(bearer) {
  if (!bearer.startsWith("Bearer ") || bearer.length>8200) return {unauthorized:true};
  try {
    const r = await fetch(HEALTH_EDGE,{
      method:"POST",headers:{"content-type":"application/json","authorization":bearer},
      body:JSON.stringify({action:"queue_pressure_status"}),
      signal:AbortSignal.timeout(8500)
    });
    if(r.status===401)return {unauthorized:true};
    if(r.status!==200)return {error:"Queue pressure telemetry unavailable"};
    const x=await r.json();
    if(x?.ok!==true || x.mutated_state!==false ||
       typeof x.reason!=="string" ||
       typeof x.advisory_admit_nonessential_diagnostics!=="boolean" ||
       typeof x.active_queue_complete!=="boolean" ||
       !x.counts || !["queued","claimed","running"].every(k=>
         Number.isSafeInteger(x.counts[k]) && x.counts[k]>=0))
      return {error:"Queue pressure telemetry invalid"};
    // Keep responses to the exact metadata schema, independent of edge extensions.
    return {value:{
      ok:true,mutated_state:false,reason:x.reason.slice(0,80),
      advisory_admit_nonessential_diagnostics:x.advisory_admit_nonessential_diagnostics,
      heartbeat_age_s:Number.isInteger(x.heartbeat_age_s)?x.heartbeat_age_s:null,
      agent_phase:typeof x.agent_phase==="string"?x.agent_phase.slice(0,64):null,
      claims_enabled:typeof x.claims_enabled==="boolean"?x.claims_enabled:null,
      active_queue_complete:x.active_queue_complete,
      counts:{queued:x.counts.queued,claimed:x.counts.claimed,running:x.counts.running},
      oldest_queued_age_s:Number.isInteger(x.oldest_queued_age_s)?x.oldest_queued_age_s:null,
      oldest_claimed_age_s:Number.isInteger(x.oldest_claimed_age_s)?x.oldest_claimed_age_s:null,
      near_expiry_queued:Number.isInteger(x.near_expiry_queued)?x.near_expiry_queued:0
    }};
  }catch{return {error:"Queue pressure telemetry unavailable"};}
}
async function handle(req,res){
  const meta=resource();
  if (req.url==="/healthz" && req.method==="GET")
    return respond(res,200,{healthy:true,privileged:false,oauth_enabled:false});
  if (!meta) return respond(res,503,{error:"Pinned HTTPS resource missing"});
  if (req.headers.host!==new URL(ORIGIN).host)
    return respond(res,421,{error:"Unrecognized Host"});
  if (req.headers.origin!==undefined){
    if (!TRUSTED_BROWSER_ORIGINS.has(req.headers.origin) || req.url==="/mcp-ci-guard") {
      auditRejectedBrowserOrigin(req);
      return respond(res,403,{error:"Untrusted browser origin"});
    }
    res._ocnTrustedBrowserOrigin=req.headers.origin;
  }
  // Preflight only for OAuth discovery and MCP routes, never privileged bypasses.
  if (req.method==="OPTIONS" && res._ocnTrustedBrowserOrigin){
    if (!["/.well-known/oauth-protected-resource","/mcp","/mcp-oauth"].includes(req.url))
      return respond(res,405,{error:"Unsupported preflight path"});
    return respond(res,204,null,{
      "access-control-allow-methods":"GET, POST, OPTIONS",
      "access-control-allow-headers":"authorization, content-type, accept, mcp-protocol-version",
      "access-control-max-age":"300"
    });
  }
  if (req.url==="/.well-known/oauth-protected-resource")
    return req.method==="GET" ? respond(res,200,meta) : respond(res,405,{error:"Method not allowed"});
  // PR529 guard has an independent, owner-OAuth-bound entrypoint.
  if (req.url === "/mcp-ci-guard")
    return makeHandler({origin:ORIGIN})(req,res);
  const oauthProbePath = req.url === "/mcp-oauth";
  if (req.url!=="/mcp" && !oauthProbePath)
    return respond(res,404,{error:"Not found"});
  if (req.method!=="POST") return respond(res,405,{error:"MCP requires POST"});
  if (req.headers["content-type"]?.split(";")[0]?.trim()?.toLowerCase()!=="application/json")
    return respond(res,415,{error:"Expected JSON"});
  const accept=String(req.headers.accept||"");
  if (!accept.includes("application/json")||!accept.includes("text/event-stream"))
    return respond(res,406,{error:"MCP Accept required"});
  if (req.headers["mcp-protocol-version"] &&
      !VERSIONS.has(req.headers["mcp-protocol-version"]))
    return respond(res,400,err(null,-32600,"Unsupported protocol version"));
  // One MCP request remains one JSON-RPC message (no client-side chunking).
  // Avoid arbitrary size rejection; Node/Render may still enforce their own limits.
  const chunks=[];
  for await (const chunk of req){
    chunks.push(chunk);
  }
  let message;
  try{message=JSON.parse(Buffer.concat(chunks).toString("utf8"));}
  catch{return respond(res,400,err(null,-32700,"Parse error"));}
  if (!message || typeof message!=="object" || Array.isArray(message) || message.jsonrpc!=="2.0")
    return respond(res,400,err(null,-32600,"Invalid JSON-RPC"));
  const id=message.id, method=message.method;
  const notification=method==="notifications/initialized";
  if (!notification && !(typeof id==="string" && id.length<=100 || Number.isSafeInteger(id)))
    return respond(res,400,err(null,-32600,"Request ID required"));
  if (message.params!==undefined &&
      (!message.params || typeof message.params!=="object" || Array.isArray(message.params)))
    return respond(res,400,err(id,-32602,"Invalid params"));
  if (notification) return respond(res,202,null);
  if (method==="initialize"){
    const ver=message.params?.protocolVersion;
    if (!VERSIONS.has(ver)) return respond(res,200,err(id,-32602,"Unsupported protocol"));
    return respond(res,200,ok(id,{
      protocolVersion:ver,
      capabilities:{tools:{listChanged:false}},
      serverInfo:{name:"ocn-unprivileged-ping-canary",version:"0.1.0"}
    }));
  }
  if (method==="ping") return respond(res,200,ok(id,{}));
  if (method==="tools/list")
    return respond(res,200,ok(id,{tools:toolList(oauthProbePath)}));
  if (method!=="tools/call") return respond(res,200,err(id,-32601,"Method not found"));
  if (!message.params || typeof message.params!=="object" ||
      !message.params.arguments || typeof message.params.arguments!=="object" ||
      Array.isArray(message.params.arguments))
    return respond(res,200,ok(id,{content:[{type:"text",text:"Invalid tool arguments"}],isError:true}));
  const args=message.params.arguments;
  const tool=message.params.name;
  const keys=Object.keys(args).sort().join(",");
  const exactEmpty=(keys==="");
  const validCall=tool==="poll_machine_health" ?
    keys==="command_id,nonce" && Number.isSafeInteger(args.command_id) &&
    args.command_id>0 && typeof args.nonce==="string" && /^[0-9a-f]{32}$/.test(args.nonce) :
    (oauthProbePath && tool==="cancel_stale_pr529_ci") ?
      (exactEmpty || (keys==="max_cancellations" &&
        Number.isInteger(args.max_cancellations) && args.max_cancellations>=1 &&
        args.max_cancellations<=25)) :
    (oauthProbePath && (tool==="submit_windows_operation" || tool==="poll_windows_operation")) ?
      validWindowsCall(tool,args) :
    (oauthProbePath && tool==="submit_routed_windows_operation") ? validRoutedCall(args) :
    (oauthProbePath && tool==="submit_admin_powershell") ? validAdminPowerShellCall(args) :
    (oauthProbePath && tool==="submit_optional_diagnostic") ? validOptionalDiagnosticCall(args) :
    (oauthProbePath && tool==="browser_batch") ? validBrowserBatch(args) :
    (oauthProbePath && typeof tool==="string" && tool.startsWith("rea_")) ? validReaCall(tool,args) :
    (oauthProbePath && typeof tool==="string" && tool.startsWith("memory_")) ? validMemoryCall(tool,args) : exactEmpty;
  if (!validCall)
    return respond(res,200,ok(id,{content:[{type:"text",text:"Invalid tool arguments"}],isError:true}));
  if (message.params.name==="ping")
    return respond(res,200,ok(id,{content:[{type:"text",text:'{"pong":true,"privileged":false}'}],
      structuredContent:{pong:true,privileged:false},isError:false}));
  if (message.params.name==="owner_auth_probe" && oauthProbePath){
    // A real signed owner/session check is required; never accept a dummy bearer.
    // The validator is separately pinned and has NO machine-control actions.
    let verified=false;
    const bearer=String(req.headers.authorization||"");
    if (bearer.startsWith("Bearer ") && bearer.length<=8200) {
      try {
        const result=await fetch(
          "https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-oauth-validator",{
          method:"POST",
          headers:{"content-type":"application/json","authorization":bearer},
          body:JSON.stringify({action:"owner_auth_probe"}),
          signal:AbortSignal.timeout(6000),
        });
        const body=await result.json();
        verified=result.status===200 && body?.ok===true && body?.owner_verified===true &&
          body?.machine_control===false;
      } catch {
        verified=false;
      }
    }
    if (verified) return respond(res,200,ok(id,{
      content:[{type:"text",text:"Verified owner OAuth session. No machine permissions."}],
      structuredContent:{owner_verified:true,privileged:false},isError:false
    }));
    const challenge='Bearer resource_metadata="'+ORIGIN+
      '/.well-known/oauth-protected-resource", error="invalid_token", error_description="Verified owner OAuth session required", scope="openid email"';
    return respond(res,200,ok(id,{
      content:[{type:"text",text:"Authentication required. No machine permissions."}],
      isError:true,
      _meta:{"mcp/www_authenticate":[challenge]}
    }));
  }
  if (oauthProbePath && tool==="submit_optional_diagnostic") {
    // Separate opt-in lane: never reject or alter legacy owner-authorized
    // submissions, completion receipts, heartbeat or emergency recovery.
    const bearer=String(req.headers.authorization||"");
    const pressure=await callQueuePressureEdge(bearer);
    if(pressure.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    const plan=planOptionalDiagnosticAdmission(pressure.value);
    if(!plan.admitted) {
      const deferred={deferred:true,queued:false,reason:plan.reason,
        operation:args.operation};
      return respond(res,200,ok(id,{
        content:[{type:"text",text:JSON.stringify(deferred)}],
        structuredContent:deferred,isError:false
      }));
    }
    const request=prepareOptionalDiagnostic(args);
    if(!validWindowsCall("submit_windows_operation",request))
      return respond(res,200,ok(id,{
        content:[{type:"text",text:"Invalid optional diagnostic"}],isError:true
      }));
    const dispatched=await callWindowsOperation(bearer,"submit_windows_operation",request);
    if(dispatched.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(dispatched.value) {
      const receipt={...dispatched.value,admission_mode:"optional_preflight"};
      return respond(res,200,ok(id,{
        content:[{type:"text",text:JSON.stringify(receipt)}],
        structuredContent:receipt,isError:false
      }));
    }
    return respond(res,200,ok(id,{
      content:[{type:"text",text:dispatched.error||"Optional diagnostic unavailable"}],
      isError:true
    }));
  }
  if (oauthProbePath && tool==="queue_pressure_status") {
    const result=await callQueuePressureEdge(String(req.headers.authorization||""));
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Queue pressure telemetry unavailable"}],
      isError:true
    }));
  }
  if (oauthProbePath && (tool==="submit_machine_health" || tool==="poll_machine_health")){
    const result=await callHealthEdge(String(req.headers.authorization||""),tool,args);
    if (result.unauthorized) return respond(res,200,ok(id,ownerChallenge()));
    if (result.value) return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Device diagnostic unavailable"}],isError:true
    }));
  }
  // Direct discoverable browser tools are narrow aliases of the same signed
  // Windows queue operation. Never spawn or control Chrome in this public host.
  // A receipt means only "queued", not a completed browser operation.
  if (oauthProbePath && DIRECT_BROWSER_OPERATIONS.includes(tool)) {
    const result=await callWindowsOperation(String(req.headers.authorization||""),
      "submit_windows_operation",{operation:tool,payload:{}});
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Browser operation unavailable"}],isError:true
    }));
  }
  // Extended Playwright tools are delivered as one typed owner/device-bound
  // browser_batch_unified queue operation. Render never starts Chrome or reads
  // local files, and reuse_session cannot opt out of the durable host.
  if (oauthProbePath && tool==="browser_batch") {
    const prepared=buildBrowserBatchRequest(args);
    const result=await callWindowsOperation(String(req.headers.authorization||""),
      "submit_windows_operation",prepared);
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Browser batch unavailable"}],isError:true
    }));
  }
  // Native memory tool names reuse the EXISTING owner-OAuth and Windows queue.
  // These return queued command IDs, never assert the memory result is complete.
  if (oauthProbePath && MEMORY_TOOLS.some(x=>x.name===tool)) {
    const result=await callMemoryTool(String(req.headers.authorization||""),tool,args);
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Local memory operation unavailable"}],isError:true
    }));
  }
  // REA is dispatched only through existing Supabase-verified owner OAuth and
  // the limited Windows Agent. No Render-side REA process, file access or secret.
  if (oauthProbePath && REA_TOOLS.some(x=>x.name===tool)) {
    const result=await callReaTool(String(req.headers.authorization||""),tool,args);
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"REA dispatch unavailable"}],isError:true
    }));
  }
  // Discoverable Cloud Admin route. Translate strict inputs into the SAME signed
  // owner/device-bound Windows operation used by the legacy generic tool.
  if(oauthProbePath && tool==="submit_admin_powershell"){
    const prepared=adminPowerShellToWindowsCall(args);
    const result=await callWindowsOperation(String(req.headers.authorization||""),
      "submit_windows_operation",prepared);
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Cloud Admin PowerShell unavailable"}],isError:true
    }));
  }
  // Deterministic routing into the existing signed owner-bound Windows queue.
  // This selects an execution plane; local service authorization stays intact.
  if(oauthProbePath && tool==="submit_routed_windows_operation"){
    const p=prepareRoutedWindowsRequest(args);
    if(!p.ok)return respond(res,200,ok(id,{
      content:[{type:"text",text:p.error}],isError:true
    }));
    const target={operation:p.operation,payload:p.payload};
    if(!validWindowsCall("submit_windows_operation",target))
      return respond(res,200,ok(id,{
        content:[{type:"text",text:"Unsupported or invalid routed Windows operation"}],isError:true
      }));
    const result=await callWindowsOperation(String(req.headers.authorization||""),
      "submit_windows_operation",target);
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Routed operation unavailable"}],isError:true
    }));
  }
  // Submit to the previously bound Windows Agent, with signed owner OAuth.
  if (oauthProbePath && (tool==="submit_windows_operation" || tool==="poll_windows_operation")){
    const result=await callWindowsOperation(String(req.headers.authorization||""),tool,args);
    if(result.unauthorized)return respond(res,200,ok(id,ownerChallenge()));
    if(result.value)return respond(res,200,ok(id,{
      content:[{type:"text",text:JSON.stringify(result.value)}],
      structuredContent:result.value,isError:false
    }));
    return respond(res,200,ok(id,{
      content:[{type:"text",text:result.error||"Windows operation unavailable"}],
      isError:true
    }));
  }
  // CI Guard is owner-bound and disabled for writes until separately configured.
  if (oauthProbePath && (tool==="inspect_pr529_ci" || tool==="cancel_stale_pr529_ci")) {
    if (!(await ciBackend.authenticated(String(req.headers.authorization||""))))
      return respond(res,200,ok(id,ownerChallenge()));
    try {
      const data=tool==="inspect_pr529_ci" ? await ciBackend.scan() :
        await ciBackend.cancel(args.max_cancellations??15);
      return respond(res,200,ok(id,{
        content:[{type:"text",text:JSON.stringify(data)}],
        structuredContent:data,isError:false
      }));
    } catch(e) {
      const message=e?.message==="GITHUB_NOT_CONFIGURED" ?
        "GitHub Actions credential has not been configured" :
        e?.message==="WRITES_DISABLED" ?
        "CI Guard cancellation remains disabled" :
        "CI Guard unavailable or request denied";
      return respond(res,200,ok(id,{
        content:[{type:"text",text:message}],isError:true
      }));
    }
  }
  return respond(res,200,ok(id,{content:[{type:"text",text:"Unknown tool"}],isError:true}));
}
// Temporary, opt-in, read-only GitHub credential preflight.
// No token, response body, commit SHA, or error message enters the logs.
async function runPr529CredentialPreflight(){
  const api="https://api.github.com/repos/oconnoroliver655-netizen/chatgpt-local-bridge";
  let pullRead=false,actionsRead=false;
  try {
    const pr=await ciBackend.github("GET",api+"/pulls/529");
    pullRead=pr?.state==="open" &&
      pr?.head?.ref==="feature/ocn-owner-bound-mcp-files-20261013" &&
      /^[a-f0-9]{40}$/i.test(pr?.head?.sha||"");
  } catch {}
  try {
    const runs=await ciBackend.github("GET",api+"/actions/runs?per_page=1");
    actionsRead=Array.isArray(runs?.workflow_runs);
  } catch {}
  console.log(JSON.stringify({
    event:"PR529_CREDENTIAL_PREFLIGHT",
    pull_request_read:pullRead,actions_read:actionsRead,mutations:false
  }));
}
export function start(port=PORT){
  const server=createServer((req,res)=>{
    handle(req,res).catch(()=>respond(res,500,{error:"Internal error"}));
  });
  server.listen(port,"0.0.0.0");
  if(process.env.PR529_CREDENTIAL_PREFLIGHT==="true"){
    server.once("listening",()=>{void runPr529CredentialPreflight().catch(()=>{
      console.log(JSON.stringify({event:"PR529_CREDENTIAL_PREFLIGHT",status:"unavailable",mutations:false}));
    });});
  }
  return server;
}
if (process.argv[1] && import.meta.url===new URL("file://"+process.argv[1]).href) start();
