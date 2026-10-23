import {test} from "node:test";
import assert from "node:assert/strict";
import {MEMORY_TOOLS,validMemoryCall,buildMemoryWindowsRequest,callMemoryTool} from "./memory-tools.mjs";
const id="1".repeat(32);
const good={project:"ocn",kind:"decision",title:"中文记忆",body:"Verified memory content",source:"user 2026-10-23"};
test("exposes exactly seven OAuth-protected tools",()=>{
 assert.equal(MEMORY_TOOLS.length,7);
 assert.equal(new Set(MEMORY_TOOLS.map(t=>t.name)).size,7);
 for(const t of MEMORY_TOOLS){
  assert.equal(t.inputSchema.additionalProperties,false);
  assert.deepEqual(t.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.match(t.description,/QUEUES/);
 }
});
test("enforces allowlisted fields, projects, categories and sizes",()=>{
 assert.equal(validMemoryCall("memory_search",{query:"notes",script:"whoami"}),false);
 assert.equal(validMemoryCall("memory_search",{query:"notes",project:"../private"}),false);
 assert.equal(validMemoryCall("memory_get",{memory_id:"invalid"}),false);
 assert.equal(validMemoryCall("memory_save",{...good,path:"C:\\secret"}),false);
 assert.equal(validMemoryCall("memory_save",{...good,kind:"arbitrary"}),false);
 assert.equal(validMemoryCall("memory_save",{...good,body:"a".repeat(12001)}),false);
 assert.equal(validMemoryCall("memory_save",{...good,project:123}),false);
 assert.equal(validMemoryCall("memory_update",{memory_id:id,expected_version:0,body:"x"}),false);
});
test("delete requires explicit user_confirmed flag",()=>{
 assert.equal(validMemoryCall("memory_delete",{memory_id:id,expected_version:1}),false);
 assert.equal(validMemoryCall("memory_delete",{memory_id:id,expected_version:1,user_confirmed:false}),false);
 assert.equal(validMemoryCall("memory_delete",{memory_id:id,expected_version:1,user_confirmed:true}),true);
});
test("untrusted text is data, not executable PowerShell source",()=>{
 const query="something $(Remove-Item C:\\\\*) ; ' quote";
 assert.equal(validMemoryCall("memory_search",{query}),true);
 const operation=buildMemoryWindowsRequest("memory_search",{query});
 assert.equal(operation.operation,"powershell");
 assert.equal(operation.payload.run_as,"oliver");
 assert.equal(operation.payload.script.includes(query),false);
 assert.equal(operation.payload.script.includes("Invoke-Expression"),false);
 const encoded=operation.payload.script.match(/FromBase64String\('([^']+)'\)/)?.[1];
 assert.deepEqual(JSON.parse(Buffer.from(encoded,"base64").toString("utf8")),{name:"memory_search",args:{query}});
});
test("all seven tools map to fixed local memory MCP client",()=>{
 const tests=[["memory_status",{}],["memory_search",{query:"项目",project:"ocn",limit:4}],
  ["memory_get",{memory_id:id}],["memory_save",good],
  ["memory_update",{memory_id:id,expected_version:1,body:"changed"}],
  ["memory_delete",{memory_id:id,expected_version:1,user_confirmed:true}],["memory_backup",{}]];
 for(const [name,args] of tests){
  assert.equal(validMemoryCall(name,args),true,name);
  const r=buildMemoryWindowsRequest(name,args);
  assert.equal(r.payload.cwd,"D:\\ChatGPT-Local-Bridge");
  assert.equal(r.payload.timeout_seconds,40);
  assert.match(r.payload.script,/ocn_memory_mcp_client_v1\.py/);
 }
});
test("delegates to existing owner OAuth queue with queued semantics",async()=>{
 let sent;
 const r=await callMemoryTool("Bearer test","memory_search",{query:"x"},async(...args)=>{
  sent=args;return {value:{status:"queued",command_id:99,nonce:"a".repeat(32)}};
 });
 assert.equal(sent[1],"submit_windows_operation");
 assert.equal(sent[2].operation,"powershell");
 assert.equal(r.value.status,"queued");
});
