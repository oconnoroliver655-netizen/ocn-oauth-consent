import {test,after} from "node:test";
import assert from "node:assert/strict";
import {request as nodeRequest} from "node:http";
const ORIGIN="https://ocn-mcp-canary.onrender.com";
process.env.OCN_PUBLIC_ORIGIN=ORIGIN;
// Import after env initialization: the public origin is pinned on startup.
const {start}=await import("../server.mjs");
const server=start(0);
await new Promise(r=>server.once("listening",r));
after(()=>server.close());
const base="http://127.0.0.1:"+server.address().port;
async function httpFetch(url,{method="GET",headers={},body}={}){
  return await new Promise((resolve,reject)=>{
    const req=nodeRequest(url,{method,headers},res=>{
      const chunks=[];
      res.on("data",chunk=>chunks.push(chunk));
      res.on("end",()=>{
        const data=Buffer.concat(chunks).toString("utf8");
        resolve({status:res.statusCode,headers:{get:key=>res.headers[key.toLowerCase()]||null},
          json:async()=>JSON.parse(data)});
      });
    });
    req.on("error",reject);
    req.end(body);
  });
}


function headers(custom={}){
  return {"content-type":"application/json","accept":"application/json, text/event-stream",
    "mcp-protocol-version":"2025-11-25",host:new URL(ORIGIN).host,...custom};
}
async function rpc(method,params={},id=1,custom={}){
  return httpFetch(base+"/mcp",{method:"POST",headers:headers(custom),
    body:JSON.stringify({jsonrpc:"2.0",id,method,params})});
}
test("health exposes no secrets or authority", async()=>{
  const r=await httpFetch(base+"/healthz");
  assert.equal(r.status,200);
  assert.deepEqual(await r.json(),{healthy:true,privileged:false,oauth_enabled:false});
});
test("metadata publishes pinned resource and valid issuer",async()=>{
  const r=await httpFetch(base+"/.well-known/oauth-protected-resource",{headers:{host:new URL(ORIGIN).host}});
  assert.equal(r.status,200);
  const m=await r.json();
  assert.equal(m.resource,ORIGIN);
  assert.deepEqual(m.scopes_supported,["openid","email"]);
  assert.match(m.authorization_servers[0],/supabase.co\/auth\/v1$/);
});
test("initialize responds with supported protocol and tool capability",async()=>{
  const r=await rpc("initialize",{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"test",version:"1"}});
  assert.equal(r.status,200);
  const body=await r.json();
  assert.equal(body.result.protocolVersion,"2025-11-25");
  assert.ok(body.result.capabilities.tools);
});
test("tool list has no device file terminal or shell tools",async()=>{
  const r=await rpc("tools/list");assert.equal(r.status,200);
  const b=await r.json();
  assert.deepEqual(b.result.tools.map(t=>t.name),["ping"]);
});
test("anonymous ping is harmless",async()=>{
  const r=await rpc("tools/call",{name:"ping",arguments:{}});
  assert.equal(r.status,200);
  assert.deepEqual((await r.json()).result.structuredContent,{pong:true,privileged:false});
});
test("OAuth probe is NOT listed on the existing ping-only endpoint",async()=>{
  const r=await rpc("tools/list");
  assert.deepEqual((await r.json()).result.tools.map(t=>t.name),["ping"]);
});
test("OAuth test route advertises protected probe and returns MCP tool-level challenge",async()=>{
  const listing=await httpFetch(base+"/mcp-oauth",{method:"POST",headers:headers(),
    body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list",params:{}})});
  assert.equal(listing.status,200);
  const list=(await listing.json()).result.tools;
  assert.deepEqual(list.map(t=>t.name),["ping","owner_auth_probe","submit_machine_health","poll_machine_health"]);
  assert.deepEqual(list.slice(2).map(t=>t.annotations.destructiveHint),[false,false]);
  assert.deepEqual(list[1].securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  for(const auth of [{},{"authorization":"Bearer forged"}]){
    const r=await httpFetch(base+"/mcp-oauth",{method:"POST",headers:headers(auth),
      body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",
        params:{name:"owner_auth_probe",arguments:{}}})});
    assert.equal(r.status,200);
    const response=await r.json();
    assert.equal(response.result.isError,true);
    assert.match(response.result._meta["mcp/www_authenticate"][0],/resource_metadata=/);
    assert.match(response.result._meta["mcp/www_authenticate"][0],/error="invalid_token"/);
    assert.match(response.result._meta["mcp/www_authenticate"][0],/error_description=/);
  }
});
test("health-only tools require signed owner and never expose file/shell",async()=>{
  for(const [name,args] of [
    ["submit_machine_health",{}],
    ["poll_machine_health",{command_id:42,nonce:"a".repeat(32)}]
  ]){
    const r=await httpFetch(base+"/mcp-oauth",{method:"POST",headers:headers(),
      body:JSON.stringify({jsonrpc:"2.0",id:8,method:"tools/call",params:{name,arguments:args}})});
    assert.equal(r.status,200);
    const b=(await r.json()).result;
    assert.equal(b.isError,true);
    assert.match(b._meta["mcp/www_authenticate"][0],/invalid_token/);
  }
  for(const invalid of [
    {name:"submit_machine_health",arguments:{path:"D:\\\\secret.txt"}},
    {name:"poll_machine_health",arguments:{command_id:1,nonce:"bad"}},
    {name:"poll_machine_health",arguments:{command_id:1,nonce:"a".repeat(32),extra:true}},
    {name:"submit_file_write",arguments:{}}
  ]){
    const r=await httpFetch(base+"/mcp-oauth",{method:"POST",headers:headers(),
      body:JSON.stringify({jsonrpc:"2.0",id:9,method:"tools/call",params:invalid})});
    assert.equal((await r.json()).result.isError,true);
  }
});
test("origin and host constraints deny unsolicited callers",async()=>{
  for(const h of [{origin:"https://example.net"},{host:"untrusted.example"}]){
    const r=await rpc("tools/list",{},1,h);
    assert.ok([403,421].includes(r.status));
  }
});
test("unknown tool never triggers any side effects",async()=>{
  const r=await rpc("tools/call",{name:"run_shell",arguments:{}});
  assert.equal(r.status,200);
  assert.equal((await r.json()).result.isError,true);
});
test("invalid protocol and content-type fail",async()=>{
  assert.equal((await rpc("tools/list",{},1,{"mcp-protocol-version":"next"})).status,400);
  assert.equal((await rpc("tools/list",{},1,{"content-type":"text/plain"})).status,415);
});
test("mcp rejects GET, unknown routes and malformed JSON",async()=>{
  const get=await httpFetch(base+"/mcp",{headers:{host:new URL(ORIGIN).host}});
  assert.equal(get.status,405);
  const nowhere=await httpFetch(base+"/notfound",{headers:{host:new URL(ORIGIN).host}});
  assert.equal(nowhere.status,404);
  const bad=await httpFetch(base+"/mcp",{method:"POST",headers:headers(),body:"{"});
  assert.equal(bad.status,400);
  assert.equal((await bad.json()).error.code,-32700);
});
test("request cap enforces bounded JSON size",async()=>{
  const r=await rpc("tools/list",{filler:"x".repeat(10000)});
  assert.equal(r.status,413);
});
