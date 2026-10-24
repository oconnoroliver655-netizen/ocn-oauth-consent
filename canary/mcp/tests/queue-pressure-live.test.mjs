import test from "node:test";
import assert from "node:assert/strict";

const base="https://ocn-mcp-ping-canary.onrender.com";
const headers={
  "accept":"application/json, text/event-stream",
  "content-type":"application/json",
  "mcp-protocol-version":"2025-06-18"
};
async function rpc(path,name,args,authorization) {
  const h={...headers};
  if(authorization)h.authorization=authorization;
  const request=name==="tools/list" ?
    {jsonrpc:"2.0",id:711,method:"tools/list",params:{}}:
    {jsonrpc:"2.0",id:711,method:"tools/call",params:{name,arguments:args}};
  const response=await fetch(base+path,{
    method:"POST",headers:h,
    signal:AbortSignal.timeout(45000),
    body:JSON.stringify(request)
  });
  return {status:response.status,body:await response.json()};
}

test("live owner OAuth tool directory includes metadata-only pressure tool",{
  timeout:55000
},async()=>{
  const r=await rpc("/mcp-oauth","tools/list",{});
  assert.equal(r.status,200);
  assert.equal(r.body.jsonrpc,"2.0");
  const tools=r.body.result?.tools;
  assert.ok(Array.isArray(tools));
  const pressure=tools.filter(t=>t.name==="queue_pressure_status");
  assert.equal(pressure.length,1);
  assert.deepEqual(pressure[0].securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(pressure[0].annotations.readOnlyHint,true);
  assert.equal(pressure[0].annotations.destructiveHint,false);
  assert.equal(pressure[0].inputSchema.type,"object");
  assert.equal(pressure[0].inputSchema.additionalProperties,false);
});

test("queue pressure tool is not exposed on public unprivileged MCP endpoint",{
  timeout:55000
},async()=>{
  const r=await rpc("/mcp","tools/list",{});
  assert.equal(r.status,200);
  assert.deepEqual(r.body.result.tools.map(t=>t.name),["ping"]);
});

test("live owner telemetry requires signed OAuth before any queue read",{
  timeout:110000
},async()=>{
  for(const auth of [undefined,"Bearer forged"]){
    const r=await rpc("/mcp-oauth","queue_pressure_status",{},auth);
    assert.equal(r.status,200);
    assert.equal(r.body.result?.isError,true);
    const challenges=r.body.result?._meta?.["mcp/www_authenticate"];
    assert.ok(Array.isArray(challenges) && challenges.length>=1);
    assert.match(challenges[0],/error="invalid_token"/);
    assert.equal(r.body.result?.structuredContent,undefined);
  }
});
