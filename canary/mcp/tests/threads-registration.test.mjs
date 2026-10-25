import {test,after} from "node:test";
import assert from "node:assert/strict";
import {request as httpRequest} from "node:http";
process.env.OCN_PUBLIC_ORIGIN="https://ocn-mcp-canary.onrender.com";
const {start}=await import("./server.mjs");
const server=start(0);
await new Promise(r=>server.once("listening",r));
after(()=>server.close());
const base="http://127.0.0.1:"+server.address().port;
async function rpc(path,method,params={}){
  return await new Promise((resolve,reject)=>{
    const r=httpRequest(base+path,{method:"POST",headers:{host:"ocn-mcp-canary.onrender.com",
      "content-type":"application/json","accept":"application/json, text/event-stream"}},res=>{
      const chunks=[];
      res.on("data",c=>chunks.push(c));
      res.on("end",()=>resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
    });
    r.on("error",reject);
    r.end(JSON.stringify({jsonrpc:"2.0",id:1,method,params}));
  });
}
test("public MCP endpoint does not list Threads tools",async()=>{
  const out=await rpc("/mcp","tools/list");
  assert.deepEqual(out.result.tools.map(t=>t.name),["ping"]);
});
test("owner OAuth MCP endpoint registers all 18 Threads tools",async()=>{
  const out=await rpc("/mcp-oauth","tools/list");
  const threads=out.result.tools.filter(t=>t.name.startsWith("threads_"));
  assert.equal(threads.length,18);
  assert.ok(threads.every(t=>t.securitySchemes[0].type==="oauth2"));
});
test("unauthenticated status and publishing reject with signed owner challenge",async()=>{
  for(const [name,args] of [["threads_connection_status",{}],
    ["threads_publish_text",{text:"test",confirm:true}]]){
    const out=await rpc("/mcp-oauth","tools/call",{name,arguments:args});
    assert.equal(out.result.isError,true);
    assert.match(out.result._meta["mcp/www_authenticate"][0],/invalid_token/);
  }
});
test("invalid Threads args reject without contacting owner validator or Meta",async()=>{
  const out=await rpc("/mcp-oauth","tools/call",{name:"threads_delete_post",arguments:{media_id:"abc",confirm:true}});
  assert.equal(out.result.isError,true);
  assert.match(out.result.content[0].text,/Invalid tool arguments/);
});
