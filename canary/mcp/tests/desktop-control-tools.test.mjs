import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {
  DESKTOP_OBSERVE_TOOLS,validDesktopObserveCall,desktopObserveToWindowsCall,
  DESKTOP_LEASE_TOOLS,validDesktopLeaseCall,desktopLeaseToWindowsCall,
  validDesktopLeasePayload,validWindowsCall,runWindowsOperation
} from "../windows-tools.mjs";
import {planWindowsRoute} from "../route-policy.mjs";

const owner="ocn_worker_alpha";
const lease_id="a".repeat(32);
const now=()=>0;

test("typed desktop observations are owner-bound, read-only, and individually bounded",()=>{
  assert.deepEqual(DESKTOP_OBSERVE_TOOLS.map(t=>t.name),
    ["desktop_window_list","desktop_uia_tree"]);
  for(const tool of DESKTOP_OBSERVE_TOOLS){
    assert.deepEqual(tool.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
    assert.equal(tool.annotations.readOnlyHint,true);
    assert.equal(tool.annotations.destructiveHint,false);
    assert.equal(tool.inputSchema.properties.wait_seconds.maximum,12);
  }
  assert.deepEqual(desktopObserveToWindowsCall("desktop_window_list",{}),
    {operation:"window_list",payload:{query:"",limit:100},wait_seconds:8});
  assert.deepEqual(desktopObserveToWindowsCall("desktop_uia_tree",{hwnd:12345,wait_seconds:0}),
    {operation:"uia_tree",payload:{hwnd:12345,max_depth:4,max_nodes:150},wait_seconds:0});
  assert.deepEqual(desktopObserveToWindowsCall("desktop_uia_tree",
    {hwnd:12345,max_depth:2,max_nodes:50,wait_seconds:3}),
    {operation:"uia_tree",payload:{hwnd:12345,max_depth:2,max_nodes:50},wait_seconds:3});
});
test("observation rejects global UIA root, privilege metadata, overbroad capture and bad types",()=>{
  for(const invalid of [null,[],{hwnd:0},{hwnd:-1},{hwnd:"99"},
    {hwnd:1,run_as:"system"},{hwnd:1,script:"whoami"},
    {hwnd:1,max_depth:7},{hwnd:1,max_nodes:251},{hwnd:1,wait_seconds:13},
    {hwnd:1,wait_seconds:1.5}]){
    assert.equal(validDesktopObserveCall("desktop_uia_tree",invalid),false,
      JSON.stringify(invalid));
  }
  for(const invalid of [{query:"x\nx"},{query:"x".repeat(81)},
    {query:1},{limit:0},{limit:101},{limit:"10"},
    {run_as:"system"},{payload:{}},{wait_seconds:-1},{wait_seconds:13}]){
    assert.equal(validDesktopObserveCall("desktop_window_list",invalid),false,
      JSON.stringify(invalid));
  }
  assert.equal(validDesktopObserveCall("mouse_click",{}),false);
  assert.throws(()=>desktopObserveToWindowsCall("desktop_uia_tree",{hwnd:0}),TypeError);
});
test("desktop lease tools do not grant GUI inputs or privilege and match native operation names",()=>{
  assert.deepEqual(DESKTOP_LEASE_TOOLS.map(t=>t.name),
    ["desktop_lease_acquire","desktop_lease_renew","desktop_lease_release"]);
  for(const t of DESKTOP_LEASE_TOOLS){
    assert.deepEqual(t.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
    assert.equal(t.annotations.destructiveHint,false);
    assert.equal(t.inputSchema.properties.wait_seconds.maximum,12);
  }
  assert.deepEqual(desktopLeaseToWindowsCall("desktop_lease_acquire",{owner}),
    {operation:"desktop_lease_acquire",payload:{owner},wait_seconds:8});
  assert.deepEqual(desktopLeaseToWindowsCall("desktop_lease_renew",
    {owner,lease_id,ttl_seconds:60,wait_seconds:0}),
    {operation:"desktop_lease_renew",payload:{owner,lease_id,ttl_seconds:60},wait_seconds:0});
  assert.deepEqual(desktopLeaseToWindowsCall("desktop_lease_release",
    {owner,lease_id,wait_seconds:2}),
    {operation:"desktop_lease_release",payload:{owner,lease_id},wait_seconds:2});
  for(const t of DESKTOP_LEASE_TOOLS){
    const args=t.name==="desktop_lease_acquire"?{owner}:{owner,lease_id};
    assert.equal(validDesktopLeaseCall(t.name,args),true);
    assert.equal(validWindowsCall("submit_windows_operation",{
      operation:t.name,payload:args}),true);
    assert.equal(planWindowsRoute({operation:t.name,payload:args}).execution_plane,
      "desktop-user");
    assert.equal(planWindowsRoute({
      operation:t.name,payload:args,intent:"system_maintenance"
    }).status,"refused");
  }
});
test("lease rejects invented owner, fake lease ID, high TTL and arbitrary payload",()=>{
  for(const [name,payload] of [
    ["desktop_lease_acquire",{}],
    ["desktop_lease_acquire",{owner:"x"}],
    ["desktop_lease_acquire",{owner:"admin root"}],
    ["desktop_lease_acquire",{owner,ttl_seconds:301}],
    ["desktop_lease_acquire",{owner,ttl_seconds:14}],
    ["desktop_lease_acquire",{owner,run_as:"system"}],
    ["desktop_lease_acquire",{owner,script:"whoami"}],
    ["desktop_lease_renew",{owner}],
    ["desktop_lease_renew",{owner,lease_id:"abc"}],
    ["desktop_lease_renew",{owner,lease_id,ttl_seconds:"90"}],
    ["desktop_lease_release",{owner,lease_id,ttl_seconds:90}],
    ["desktop_lease_release",{owner,lease_id,run_as:"system"}]
  ]){
    assert.equal(validDesktopLeasePayload(name,payload),false,
      JSON.stringify({name,payload}));
    assert.equal(validWindowsCall("submit_windows_operation",{
      operation:name,payload}),false);
  }
  assert.equal(validDesktopLeaseCall("desktop_lease_acquire",{owner,wait_seconds:13}),false);
  assert.equal(validDesktopLeaseCall("desktop_lease_release",
    {owner,lease_id,wait_seconds:-1}),false);
  assert.throws(()=>desktopLeaseToWindowsCall("desktop_lease_release",
    {owner,lease_id:"bad"}),TypeError);
  assert.equal(validWindowsCall("submit_windows_operation",{
    operation:"mouse_click",payload:{x:50,y:50}}),false);
});
test("native desktop read and lease wait never resubmit or reinterpret a queued receipt",async()=>{
  const calls=[];
  const queue={ok:true,command_id:124,nonce:"f".repeat(32),status:"queued"};
  const request=desktopObserveToWindowsCall("desktop_window_list",
    {query:"Notepad",limit:25,wait_seconds:0});
  const response=await runWindowsOperation("Bearer test",request,{
    invoke:async(_,name,args)=>{calls.push({name,args});return {value:queue}},
    now
  });
  assert.equal(response.value.terminal,false);
  assert.equal(response.value.command_id,124);
  assert.equal(response.value.nonce,queue.nonce);
  assert.deepEqual(calls,[{name:"submit_windows_operation",
    args:{operation:"window_list",payload:{query:"Notepad",limit:25}}}]);
  calls.length=0;
  let elapsed=0;
  const leased=await runWindowsOperation("Bearer test",
    desktopLeaseToWindowsCall("desktop_lease_acquire",{owner,wait_seconds:1}),{
      invoke:async(_,name,args)=>{
        calls.push(name);
        return {value:name==="submit_windows_operation"?queue:
          {ok:true,command_id:124,status:"needs_review",
           execution_outcome:"UNKNOWN",retry_safe:false}};
      },
      pause:async n=>{elapsed+=n;},now:()=>elapsed
    });
  assert.equal(leased.value.status,"needs_review");
  assert.equal(leased.value.execution_outcome,"UNKNOWN");
  assert.deepEqual(calls,["submit_windows_operation","poll_windows_operation"]);
});
test("Edge lease boundary is present, but native pointer and keyboard input stay unexposed",()=>{
  const edge=readFileSync(new URL(
    "../../../supabase/functions/ocn-owner-health-dispatch/index.ts",import.meta.url),"utf8");
  const ops=edge.slice(edge.indexOf("const WINDOWS_OPS = new Set(["),edge.indexOf("const TERMINAL ="));
  for(const name of ["desktop_lease_acquire","desktop_lease_renew","desktop_lease_release"])
    assert.ok(ops.includes(name));
  for(const name of ["mouse_click","keyboard_type","key_press","uia_invoke","uia_set_value"])
    assert.ok(!ops.includes('"'+name+'"'));
  const validator=edge.slice(edge.indexOf("function validWindowsPayload("),
    edge.indexOf("async function submitWindows("));
  assert.ok(validator.includes('operation==="desktop_lease_acquire"'));
  assert.ok(validator.includes("payload.ttl_seconds>=15"));
  assert.ok(validator.includes("keys.some(k=>!allowed.includes(k))"));
  assert.ok(validator.includes("lease_id"));
  assert.ok(!ops.includes("run_as"));
  const render=readFileSync(new URL("../windows-tools.mjs",import.meta.url),"utf8");
  const renderOps=render.slice(render.indexOf("const OPERATIONS=["),render.indexOf("export const WINDOWS_TOOLS"));
  for(const name of ["mouse_click","keyboard_type","key_press","uia_invoke","uia_set_value"])
    assert.ok(!renderOps.includes('"'+name+'"'));
  const server=readFileSync(new URL("../server.mjs",import.meta.url),"utf8");
  for(const tag of ["...DESKTOP_OBSERVE_TOOLS","...DESKTOP_LEASE_TOOLS",
    "validDesktopObserveCall(tool,args)","validDesktopLeaseCall(tool,args)",
    "desktopObserveToWindowsCall(tool,args)","desktopLeaseToWindowsCall(tool,args)"])
    assert.ok(server.includes(tag));
});
