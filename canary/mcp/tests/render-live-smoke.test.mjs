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

test("OAuth probe is hidden on the existing ping-only MCP URL",{timeout:50000},async()=>{
  const r=await rpc("tools/list");
  assert.deepEqual(r.body.result.tools.map(t=>t.name),["ping"]);
});
test("separate OAuth test path advertises protected tool and always challenges",{timeout:50000},async()=>{
  const opts={...options};
  const scan=await fetch(base+"/mcp-oauth",{method:"POST",headers:opts,
    signal:AbortSignal.timeout(45000),
    body:JSON.stringify({jsonrpc:"2.0",id:111,method:"tools/list",params:{}})});
  assert.equal(scan.status,200);
  const tools=(await scan.json()).result.tools;
  assert.deepEqual(tools.map(t=>t.name),["ping","owner_auth_probe"]);
  assert.deepEqual(tools[1].securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  for(const token of ["","Bearer forged"]){
    const headers={...opts,...(token?{authorization:token}:{})};
    const response=await fetch(base+"/mcp-oauth",{method:"POST",headers,
      signal:AbortSignal.timeout(45000),
      body:JSON.stringify({jsonrpc:"2.0",id:112,method:"tools/call",
        params:{name:"owner_auth_probe",arguments:{}}})});
    assert.equal(response.status,200);
    const data=await response.json();
    assert.equal(data.result.isError,true);
    assert.match(data.result._meta["mcp/www_authenticate"][0],/oauth-protected-resource/);
    assert.match(data.result._meta["mcp/www_authenticate"][0],/error="invalid_token"/);
  }
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
