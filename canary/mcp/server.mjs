import {makeHandler} from "./pr529-ci-guard.mjs";
// Owner OAuth MCP endpoint: unprivileged probe plus strictly bounded
// read-only Windows health diagnostic; no file, desktop, shell or admin tools.
// Authentication for each protected call remains in Supabase's signed ES256
// token validator, not in client-supplied JSON or this publicly exposed host.
import { createServer } from "node:http";
const PORT = Number(process.env.PORT || 10000);
const ORIGIN = process.env.OCN_PUBLIC_ORIGIN || "";
const VERSIONS = new Set(["2025-03-26","2025-06-18","2025-11-25","2026-07-28"]);
const ISSUER = "https://ouxniljtjxnrkwakkvbv.supabase.co/auth/v1";
const LIMIT = 8192;
const HEALTH_EDGE = "https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-owner-health-dispatch";
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
async function handle(req,res){
  const meta=resource();
  if (req.url==="/healthz" && req.method==="GET")
    return respond(res,200,{healthy:true,privileged:false,oauth_enabled:false});
  if (!meta) return respond(res,503,{error:"Pinned HTTPS resource missing"});
  if (req.headers.host!==new URL(ORIGIN).host)
    return respond(res,421,{error:"Unrecognized Host"});
  if (req.headers.origin!==undefined)
    return respond(res,403,{error:"Browser origins disabled"});
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
  if (Number(req.headers["content-length"]||0)>LIMIT)
    return respond(res,413,{error:"Body too large"});
  let length=0;
  const chunks=[];
  for await (const chunk of req){
    length+=chunk.length;
    if (length>LIMIT) return respond(res,413,{error:"Body too large"});
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
    exactEmpty;
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
  return respond(res,200,ok(id,{content:[{type:"text",text:"Unknown tool"}],isError:true}));
}
export function start(port=PORT){
  const server=createServer((req,res)=>{
    handle(req,res).catch(()=>respond(res,500,{error:"Internal error"}));
  });
  return server.listen(port,"0.0.0.0");
}
if (process.argv[1] && import.meta.url===new URL("file://"+process.argv[1]).href) start();
