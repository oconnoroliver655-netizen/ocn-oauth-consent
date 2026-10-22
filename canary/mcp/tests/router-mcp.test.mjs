import test from "node:test";
import assert from "node:assert/strict";
import {ROUTED_WINDOWS_TOOL,validRoutedCall,prepareRoutedWindowsRequest} from "../router-mcp.mjs";
test("OAuth tool discovery metadata is scoped to owner",()=>{
 assert.equal(ROUTED_WINDOWS_TOOL.name,"submit_routed_windows_operation");
 assert.deepEqual(ROUTED_WINDOWS_TOOL.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
 assert.equal(ROUTED_WINDOWS_TOOL.annotations.destructiveHint,true);
 assert.equal(ROUTED_WINDOWS_TOOL.inputSchema.additionalProperties,false);
});
test("simple service task routes SYSTEM over original signed queue",()=>{
 const q=prepareRoutedWindowsRequest({operation:"powershell",payload:{script:"Stop-Service Spooler"}});
 assert.deepEqual(q,{ok:true,operation:"powershell",payload:{script:"Stop-Service Spooler",run_as:"system"},execution_plane:"cloud-admin"});
});
test("browser operation stays in limited user session",()=>{
 const q=prepareRoutedWindowsRequest({operation:"browser_status",payload:{}});
 assert.deepEqual(q,{ok:true,operation:"browser_status",payload:{},execution_plane:"desktop-user"});
});
test("explicit administrative request routes to SYSTEM",()=>{
 const q=prepareRoutedWindowsRequest({operation:"powershell",intent:"system_maintenance",payload:{script:"whoami /user"}});
 assert.equal(q.payload.run_as,"system");
});
test("interactive admin request refused with a meaningful reason",()=>{
 const job={operation:"window_list",intent:"interactive_admin",payload:{}};
 assert.equal(validRoutedCall(job),true);
 assert.deepEqual(prepareRoutedWindowsRequest(job),{ok:false,error:"INTERACTIVE_ADMIN_EXECUTOR_NOT_DEPLOYED"});
});
test("other rejected jobs never dispatch",()=>{
 const cases=[
 {operation:"powershell",payload:{script:"whoami",run_as:"system"}},
 {operation:"browser_status",intent:"system_maintenance",payload:{}},
 {operation:"exec",payload:{argv:["whoami.exe"]}},
 ];
 for(const job of cases){
  assert.equal(validRoutedCall(job),true);
  assert.equal(prepareRoutedWindowsRequest(job).ok,false);
 }
});
test("schema-invalid operations and fields fail",()=>{
 const cases=[{operation:"bogus",payload:{}},
 {operation:"powershell",payload:[]},
 {operation:"powershell",payload:{script:"x"},extra:1},
 {operation:"powershell",payload:{} ,intent:"something"},
 {},null];
 for(const job of cases)assert.equal(validRoutedCall(job),false);
});
