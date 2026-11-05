import test from "node:test";
import assert from "node:assert/strict";
import {RUN_WINDOWS_TOOL,validRunWindowsCall,runWindowsOperation}
  from "../windows-tools.mjs";

const nonce="a".repeat(32);
const queued={ok:true,command_id:91,nonce,status:"queued"};
const complete={ok:true,command_id:91,status:"completed",
  execution_state:"SUCCEEDED",detail:{returncode:0,stdout:"ok"}};

test("one-call tool exposes existing signed owner boundary and bounded wait",()=>{
  assert.equal(RUN_WINDOWS_TOOL.name,"run_windows_operation");
  assert.deepEqual(RUN_WINDOWS_TOOL.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(RUN_WINDOWS_TOOL.annotations.destructiveHint,true);
  assert.equal(RUN_WINDOWS_TOOL.inputSchema.properties.wait_seconds.maximum,12);
});
test("strict arguments never allow arbitrary operations or unbounded waits",()=>{
  for(const bad of [
    null,[],{}, {operation:"shell",payload:{}},
    {operation:"file_read",payload:null},
    {operation:"file_read",payload:{},wait_seconds:-1},
    {operation:"file_read",payload:{},wait_seconds:13},
    {operation:"file_read",payload:{},wait_seconds:1.5},
    {operation:"file_read",payload:{},extra:"unused"},
    {operation:"browser_navigate",payload:{url:"javascript:alert(1)"}}
  ]) assert.equal(validRunWindowsCall(bad),false,JSON.stringify(bad));
  assert.equal(validRunWindowsCall({operation:"file_read",payload:{path:"C:\\test.txt"}}),true);
});
test("completed result returns verified receipt without a second submission",async()=>{
  const calls=[];
  let ms=0;
  const invoke=async(_,name,args)=>{
    calls.push({name,args});
    return {value:name==="submit_windows_operation"?queued:complete};
  };
  const r=await runWindowsOperation("Bearer mocked",{operation:"file_read",
    payload:{path:"C:\\test.txt"},wait_seconds:2},{
    invoke,pause:async d=>{ms+=d},now:()=>ms
  });
  assert.equal(r.value.terminal,true);
  assert.equal(r.value.wait_exhausted,false);
  assert.equal(r.value.status,"completed");
  assert.equal(r.value.execution_state,"SUCCEEDED");
  assert.equal(r.value.nonce,nonce);
  assert.equal(calls.filter(x=>x.name==="submit_windows_operation").length,1);
  assert.deepEqual(calls[1].args,{command_id:91,nonce});
});
test("timeout exposes same pollable ID/nonce and never resubmits",async()=>{
  const calls=[];
  let ms=0;
  const invoke=async(_,name,args)=>{
    calls.push(name);
    return {value:name==="submit_windows_operation"?queued:{ok:true,command_id:91,status:"claimed"}};
  };
  const r=await runWindowsOperation("Bearer mocked",{
    operation:"file_read",payload:{path:"C:\\test.txt"},wait_seconds:1
  },{invoke,pause:async d=>{ms+=d},now:()=>ms});
  assert.equal(r.value.terminal,false);
  assert.equal(r.value.wait_exhausted,true);
  assert.equal(r.value.command_id,91);
  assert.equal(r.value.nonce,nonce);
  assert.equal(calls.filter(x=>x==="submit_windows_operation").length,1);
});
test("zero-wait returns queued original receipt with no polling",async()=>{
  const calls=[];
  const r=await runWindowsOperation("Bearer mocked",
    {operation:"desktop_health",payload:{},wait_seconds:0},{
      invoke:async(_,tool)=>{calls.push(tool);return {value:queued}}
    });
  assert.equal(r.value.wait_exhausted,true);
  assert.deepEqual(calls,["submit_windows_operation"]);
});
test("poll failure preserves committed submission without retrying",async()=>{
  const calls=[];
  const r=await runWindowsOperation("Bearer mocked",
    {operation:"file_read",payload:{path:"C:\\test.txt"},wait_seconds:2},{
      invoke:async(_,tool)=>{
        calls.push(tool);
        return tool==="submit_windows_operation"?{value:queued}:{error:"timeout"};
      },pause:async()=>{}
    });
  assert.equal(r.value.wait_interrupted,true);
  assert.equal(r.value.poll_error,"POLL_UNAVAILABLE");
  assert.equal(r.value.nonce,nonce);
  assert.deepEqual(calls,["submit_windows_operation","poll_windows_operation"]);
});
test("unauthorized submission is not converted into a queued receipt",async()=>{
  const r=await runWindowsOperation("Bearer mocked",
    {operation:"file_read",payload:{path:"C:\\test.txt"}},{
      invoke:async()=>({unauthorized:true})
    });
  assert.deepEqual(r,{unauthorized:true});
});
test("failed terminal status remains failed, not successful",async()=>{
  let ms=0;
  const r=await runWindowsOperation("Bearer mocked",
    {operation:"powershell",payload:{script:"exit 3"},wait_seconds:1},{
      invoke:async(_,tool)=>({value:tool==="submit_windows_operation"?queued:{
        ok:true,command_id:91,status:"failed",execution_state:"FAILED",detail:{returncode:3}
      }}),pause:async d=>{ms+=d},now:()=>ms
    });
  assert.equal(r.value.terminal,true);
  assert.equal(r.value.status,"failed");
  assert.equal(r.value.execution_state,"FAILED");
});
