import test from "node:test";
import assert from "node:assert/strict";
import {request} from "node:http";
process.env.OCN_PUBLIC_ORIGIN="https://rea-mcp.test.invalid";
const {start}=await import("./server.mjs");
const server=start(0);
await new Promise(resolve=>server.once("listening",resolve));
const port=server.address().port;
async function rpc(path,method,params={},headers={}){
 const body=JSON.stringify({jsonrpc:"2.0",id:1,method,params});
 const h={"host":"rea-mcp.test.invalid","content-type":"application/json",
   "accept":"application/json, text/event-stream",...headers};
 return new Promise((resolve,reject)=>{
  const req=request({hostname:"127.0.0.1",port,path,method:"POST",headers:h},res=>{
   const chunks=[];res.on("data",x=>chunks.push(x));
   res.on("end",()=>{try{resolve({status:res.statusCode,json:JSON.parse(Buffer.concat(chunks).toString())})}catch(e){reject(e)}})
  });
  req.on("error",reject);req.end(body);
 });
}
test.after(async()=>{await new Promise(resolve=>server.close(resolve));});
test("only OAuth endpoint advertises nine REA tools",async()=>{
 const open=await rpc("/mcp","tools/list",{});
 const secured=await rpc("/mcp-oauth","tools/list",{});
 assert.equal(open.status,200);
 assert.equal(secured.status,200);
 assert.equal(open.json.result.tools.some(t=>t.name==="rea_submit_tool"),false);
 const selected=secured.json.result.tools.filter(t=>t.name.startsWith("rea_"));
 assert.equal(selected.length,9);
 for(const tool of selected)assert.equal(tool.securitySchemes[0].type,"oauth2");
});
test("missing OAuth bearer is never allowed to schedule a REA job",async()=>{
 const res=await rpc("/mcp-oauth","tools/call",
  {name:"rea_status",arguments:{}});
 assert.equal(res.status,200);
 assert.equal(res.json.result.isError,true);
 assert.match(JSON.stringify(res.json.result),/Verified owner OAuth session required/);
});
test("reject adversarial request before touching downstream queue",async()=>{
 const res=await rpc("/mcp-oauth","tools/call",
  {name:"rea_submit_tool",arguments:{tool:"bad;Write-Host",arguments:{}}});
 assert.equal(res.json.result.isError,true);
 assert.match(JSON.stringify(res.json.result),/Invalid tool arguments/);
});
test("authorized request calls existing owner OAuth queue and yields queued acknowledgment",async()=>{
 const original=globalThis.fetch;
 let seen;
 globalThis.fetch=async(url,options)=>{
  seen={url:String(url),headers:options.headers,body:JSON.parse(options.body)};
  return new Response(JSON.stringify({ok:true,command_id:904,nonce:"b".repeat(32),status:"queued"}),{status:202,headers:{"content-type":"application/json"}});
 };
 try{
  const res=await rpc("/mcp-oauth","tools/call",
   {name:"rea_describe_tool",arguments:{tool:"inspect_binary_layout"}},
   {authorization:"Bearer owner-mocked-test"});
  assert.equal(res.status,200);
  assert.equal(res.json.result.structuredContent.status,"queued");
  assert.equal(seen.headers.authorization,"Bearer owner-mocked-test");
  assert.equal(seen.body.action,"submit_windows_operation");
  assert.equal(seen.body.operation,"powershell");
  assert.equal(seen.body.payload.run_as,"oliver");
  assert.equal(seen.body.payload.script.includes("inspect_binary_layout"),false);
  assert.equal(seen.url.endsWith("/ocn-owner-health-dispatch"),true);
 }finally{globalThis.fetch=original}
});
