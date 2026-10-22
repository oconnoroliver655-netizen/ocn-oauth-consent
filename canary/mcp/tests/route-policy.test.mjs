import test from "node:test";
import assert from "node:assert/strict";
import {planWindowsRoute as plan,toExistingWindowsCall} from "../route-policy.mjs";
test("single service cmdlet routes to Cloud Admin",()=>{
 const p=plan({operation:"powershell",payload:{script:"Restart-Service Spooler"}});
 assert.equal(p.status,"planned");assert.equal(p.execution_plane,"cloud-admin");assert.equal(p.payload.run_as,"system");
});
test("regular PowerShell stays limited",()=>{
 const p=plan({operation:"powershell",payload:{script:"Get-Service Spooler"}});
 assert.equal(p.payload.run_as,"oliver");assert.equal(p.execution_plane,"user-shell");
});
test("compound or ambiguous PowerShell is not auto-elevated",()=>{
 for(const script of ["Get-Service | Stop-Service","Get-Service; Stop-Service Spooler",
  "Restart-Service $(Get-Service Spooler)","Restart-Service 'Spooler'",
  "Restart-Service Spooler -Force","& Restart-Service Spooler",
  "Restart-Service Spooler\nGet-Process","powershell -enc something"]){
   assert.equal(plan({operation:"powershell",payload:{script}}).payload.run_as,"oliver",script);
 }
});
test("explicit system maintenance supports complex scripts",()=>{
 const p=plan({operation:"powershell",intent:"system_maintenance",payload:{script:"Get-Service; Get-Process"}});
 assert.equal(p.payload.run_as,"system");
});
test("caller user intent overrides heuristic",()=>{
 const p=plan({operation:"powershell",intent:"user",payload:{script:"Restart-Service Spooler"}});
 assert.equal(p.payload.run_as,"oliver");
});
test("interactive desktop and browser stay in owner user session",()=>{
 for(const operation of ["window_list","screenshot","uia_tree","browser_status","browser_click"]){
   const p=plan({operation,payload:{}});
   assert.equal(p.execution_plane,"desktop-user");assert.equal("run_as" in p.payload,false);
   assert.equal(plan({operation,payload:{},intent:"system_maintenance"}).status,"refused");
 }
});
test("identity cannot be provided by user payload",()=>{
 for(const run_as of ["system","oliver","Administrator"]){
   assert.deepEqual(plan({operation:"powershell",payload:{script:"whoami",run_as}}),
    {status:"refused",reason:"RUN_AS_OWNED_BY_ROUTER"});
 }
});
test("SYSTEM command launches require explicit intent",()=>{
 assert.equal(plan({operation:"exec",payload:{argv:["whoami.exe"]}}).status,"refused");
 assert.equal(plan({operation:"exec",intent:"system_maintenance",payload:{argv:["whoami.exe"]}}).payload.run_as,"system");
});
test("privileged GUI cannot start before acceptance",()=>{
 assert.deepEqual(plan({operation:"window_list",intent:"interactive_admin",payload:{}}),
 {status:"refused",reason:"INTERACTIVE_ADMIN_EXECUTOR_NOT_DEPLOYED"});
});
test("typed Cloud Admin operations preserve required payload",()=>{
 const p=plan({operation:"file_read_lines",payload:{path:"C:\\Windows\\win.ini",offset:0,length:4}});
 assert.equal(p.execution_plane,"cloud-admin");assert.equal("run_as" in p.payload,false);
});
test("bad jobs reject without side effects",()=>{
 const samples=[null,{},[],{operation:"other"}, {operation:"powershell",payload:{script:""}},
 {operation:"powershell",payload:{script:"x".repeat(131073)}},
 {operation:"powershell",payload:{script:"x",timeout_seconds:0}},
 {operation:"powershell",payload:{script:"x",timeout_seconds:1801}},
 {operation:"powershell",payload:{script:"x",unknown:1}},
 {operation:"powershell",payload:{script:"x"},unknown:1},
 {operation:"powershell",intent:"root",payload:{script:"x"}}];
 for(const job of samples)assert.equal(plan(job).status,"refused");
});
test("adapter uses existing queue only",()=>{
 const r=toExistingWindowsCall({operation:"powershell",intent:"system_maintenance",payload:{script:"whoami"}});
 assert.equal(r.tool,"submit_windows_operation");
 assert.deepEqual(r.arguments,{operation:"powershell",payload:{script:"whoami",run_as:"system"}});
});
test("rejected jobs are not dispatchable",()=>{
 const p=toExistingWindowsCall({operation:"browser_status",intent:"system_maintenance",payload:{}});
 assert.equal(p.status,"refused");assert.equal("tool" in p,false);
});
