// Public, unprivileged MCP canary; no Windows, database, file, or shell tools.
// The owner_auth_probe always rejects including when a bearer is supplied.
import { createServer } from "node:http";
const PORT = Number(process.env.PORT || 10000);
const ORIGIN = process.env.OCN_PUBLIC_ORIGIN || "";
const VERSIONS = new Set(["2025-03-26","2025-06-18","2025-11-25","2026-07-28"]);
const ISSUER = "https://ouxniljtjxnrkwakkvbv.supabase.co/auth/v1";
const LIMIT = 8192;
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
function toolList(){
  return [
    {name:"ping",description:"Public protocol canary; no machine access.",
      inputSchema:{type:"object",properties:{},additionalProperties:false},
      securitySchemes:[{type:"noauth"}],
      annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
    {name:"owner_auth_probe",description:"OAuth handshake only; ALWAYS denies access.",
      inputSchema:{type:"object",properties:{},additionalProperties:false},
      securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
      annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}}
  ];
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
  if (req.url!=="/mcp") return respond(res,404,{error:"Not found"});
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
  if (method==="tools/list") return respond(res,200,ok(id,{tools:toolList()}));
  if (method!=="tools/call") return respond(res,200,err(id,-32601,"Method not found"));
  if (!message.params || typeof message.params!=="object" ||
      !message.params.arguments || typeof message.params.arguments!=="object" ||
      Array.isArray(message.params.arguments) || Object.keys(message.params.arguments).length!==0)
    return respond(res,200,ok(id,{content:[{type:"text",text:"Invalid tool arguments"}],isError:true}));
  if (message.params.name==="ping")
    return respond(res,200,ok(id,{content:[{type:"text",text:'{"pong":true,"privileged":false}'}],
      structuredContent:{pong:true,privileged:false},isError:false}));
  if (message.params.name==="owner_auth_probe"){
    const challenge='Bearer resource_metadata="'+ORIGIN+
      '/.well-known/oauth-protected-resource", error="invalid_token", scope="openid email"';
    return respond(res,401,err(id,-32001,"OAuth setup incomplete; no access granted"),
      {"www-authenticate":challenge});
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
