import test from "node:test";
import assert from "node:assert/strict";

const base = "https://ocn-mcp-ping-canary.onrender.com";
const options = {"accept":"application/json, text/event-stream", "content-type":"application/json",
                 "mcp-protocol-version":"2025-06-18"};
const rpc = async (method,params={}) => {
  const response = await fetch(base+"/mcp",{
    method:"POST",headers:options,signal:AbortSignal.timeout(45000),
    body:JSON.stringify({jsonrpc:"2.0",id:101,method,params})
  });
  return {status:response.status,headers:response.headers,body:await response.json()};
};

test("live Render Free service reports not privileged", {timeout:50000},async()=>{
  const response=await fetch(base+"/healthz",{signal:AbortSignal.timeout(45000)});
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.healthy,true);
  assert.equal(body.privileged,false);
  assert.equal(body.oauth_enabled,false);
});

test("OAuth resource metadata is pinned to real HTTPS resource", {timeout:50000},async()=>{
  const r=await fetch(base+"/.well-known/oauth-protected-resource",
                      {signal:AbortSignal.timeout(45000)});
  assert.equal(r.status,200);
  const data=await r.json();
  assert.equal(data.resource,base);
  assert.deepEqual(data.scopes_supported,["openid","email"]);
  assert.deepEqual(data.authorization_servers,
    ["https://ouxniljtjxnrkwakkvbv.supabase.co/auth/v1"]);
});

test("real MCP initialize responds to a compliant Streamable HTTP client",{timeout:50000},async()=>{
  const {status,body}=await rpc("initialize",{
    protocolVersion:"2025-06-18",capabilities:{},clientInfo:{name:"ocn-live-smoke",version:"1"}
  });
  assert.equal(status,200);
  assert.equal(body.jsonrpc,"2.0");
  assert.equal(body.id,101);
  assert.equal(body.result.protocolVersion,"2025-06-18");
  assert.ok(body.result.capabilities.tools);
});

test("tool discovery shows ONLY the unprivileged ping + denied probe",{timeout:50000},async()=>{
  const result=await rpc("tools/list");
  assert.equal(result.status,200);
  assert.deepEqual(result.body.result.tools.map(t=>t.name),["ping"]);
  assert.deepEqual(result.body.result.tools[0].securitySchemes,[{type:"noauth"}]);
  assert.equal(result.body.result.tools[0].annotations.readOnlyHint,true);
  assert.ok(result.body.result.tools.every(t=>t.annotations.destructiveHint===false));
});

test("public ping works over actual Render HTTPS without credentials",{timeout:50000},async()=>{
  const r=await rpc("tools/call",{name:"ping",arguments:{}});
  assert.equal(r.status,200);
  assert.deepEqual(r.body.result.structuredContent,{pong:true,privileged:false});
});

test("owner probe MUST refuse unauthenticated caller",{timeout:50000},async()=>{
  const r=await rpc("tools/call",{name:"owner_auth_probe",arguments:{}});
  assert.equal(r.status,401);
  assert.match(r.headers.get("www-authenticate"),/oauth-protected-resource/);
  assert.equal(r.body.error.code,-32001);
});

test("untrusted access to unlisted machine tool is refused",{timeout:50000},async()=>{
  const r=await rpc("tools/call",{name:"windows_powershell",arguments:{}});
  assert.equal(r.status,200);
  assert.equal(r.body.result.isError,true);
});

test("GET /mcp cannot launch arbitrary sessions",{timeout:50000},async()=>{
  const r=await fetch(base+"/mcp",{signal:AbortSignal.timeout(45000)});
  assert.equal(r.status,405);
});
