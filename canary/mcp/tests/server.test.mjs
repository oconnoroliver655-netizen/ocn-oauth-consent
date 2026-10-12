import {test,after} from "node:test";
import assert from "node:assert/strict";
import {start} from "../server.mjs";

const ORIGIN="https://ocn-mcp-canary.onrender.com";
process.env.OCN_PUBLIC_ORIGIN=ORIGIN;
// Server module captures origin at import time. The deploy env must therefore
// be present before start; tests spawn with OCN_PUBLIC_ORIGIN already set.
const server=start(0);
await new Promise(r=>server.once("listening",r));
after(()=>server.close());
const base="http://127.0.0.1:"+server.address().port;

function headers(custom={}){
  return {"content-type":"application/json","accept":"application/json, text/event-stream",
    "mcp-protocol-version":"2025-11-25",host:new URL(ORIGIN).host,...custom};
}
async function rpc(method,params={},id=1,custom={}){
  return fetch(base+"/mcp",{method:"POST",headers:headers(custom),
    body:JSON.stringify({jsonrpc:"2.0",id,method,params})});
}
test("health exposes no secrets or authority", async()=>{
  const r=await fetch(base+"/healthz");
  assert.equal(r.status,200);
  assert.deepEqual(await r.json(),{healthy:true,privileged:false,oauth_enabled:false});
});
test("metadata publishes pinned resource and valid issuer",async()=>{
  const r=await fetch(base+"/.well-known/oauth-protected-resource",{headers:{host:new URL(ORIGIN).host}});
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
  assert.deepEqual(b.result.tools.map(t=>t.name),["ping","owner_auth_probe"]);
});
test("anonymous ping is harmless",async()=>{
  const r=await rpc("tools/call",{name:"ping",arguments:{}});
  assert.equal(r.status,200);
  assert.deepEqual((await r.json()).result.structuredContent,{pong:true,privileged:false});
});
test("OAuth probe rejects both anonymous and bearer callers",async()=>{
  for(const h of [{},{"authorization":"Bearer arbitrary"}]){
    const r=await rpc("tools/call",{name:"owner_auth_probe",arguments:{}},1,h);
    assert.equal(r.status,401);
    assert.match(r.headers.get("www-authenticate"),/oauth-protected-resource/);
    assert.equal((await r.json()).error.code,-32001);
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
  const get=await fetch(base+"/mcp",{headers:{host:new URL(ORIGIN).host}});
  assert.equal(get.status,405);
  const nowhere=await fetch(base+"/notfound",{headers:{host:new URL(ORIGIN).host}});
  assert.equal(nowhere.status,404);
  const bad=await fetch(base+"/mcp",{method:"POST",headers:headers(),body:"{"});
  assert.equal(bad.status,400);
  assert.equal((await bad.json()).error.code,-32700);
});
test("request cap enforces bounded JSON size",async()=>{
  const r=await rpc("tools/list",{filler:"x".repeat(10000)});
  assert.equal(r.status,413);
});
