import test from "node:test";
import assert from "node:assert/strict";
import {RUN_WINDOWS_TOOL,validRunWindowsCall,runWindowsOperation,
  DIRECT_FILE_READ_TOOL,validDirectFileReadCall,directFileReadToWindowsCall,
  DIRECT_FILE_LINES_TOOL,validDirectFileLinesCall,directFileLinesToWindowsCall,
  DIRECT_CODE_SEARCH_TOOL,validDirectCodeSearchCall,directCodeSearchToWindowsCall,
  DIRECT_SESSION_TOOLS,validDirectSessionCall,directSessionToWindowsCall}
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

test("typed file reader is read-only and preserves the existing native operation",()=>{
  const path=String.raw`D:\projects\中文 文档.txt`;
  assert.equal(DIRECT_FILE_READ_TOOL.name,"read_file");
  assert.equal(DIRECT_FILE_READ_TOOL.annotations.readOnlyHint,true);
  assert.equal(DIRECT_FILE_READ_TOOL.annotations.destructiveHint,false);
  assert.deepEqual(DIRECT_FILE_READ_TOOL.securitySchemes,
    [{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(validDirectFileReadCall({path}),true);
  assert.deepEqual(directFileReadToWindowsCall({path,wait_seconds:3}),
    {operation:"file_read",payload:{path},wait_seconds:3});
  assert.equal(directFileReadToWindowsCall({path}).wait_seconds,8);
});

test("typed reader rejects untrusted paths and extra control fields",()=>{
  const invalid=[
    null,[],{}, {path:"relative.txt"}, {path:"C:relative.txt"},
    {path:"/etc/passwd"}, {path:String.raw`\\server\share.txt`},
    {path:String.raw`\\?\C:\secret`},
    {path:"D:\\folder\nsecret"}, {path:"D:\0bad"},
    {path:"D:\\valid.txt",wait_seconds:13},
    {path:"D:\\valid.txt",wait_seconds:-1},
    {path:"D:\\valid.txt",wait_seconds:1.5},
    {path:"D:\\valid.txt",run_as:"system"},
    {path:"D:\\valid.txt",payload:{script:"whoami"}}
  ];
  for(const args of invalid)assert.equal(validDirectFileReadCall(args),false,
    JSON.stringify(args));
  assert.throws(()=>directFileReadToWindowsCall({path:"relative.txt"}),TypeError);
});

test("typed reader never submits a script or resubmits a pending read",async()=>{
  const path=String.raw`D:\projects\README.md`;
  const prepared=directFileReadToWindowsCall({path,wait_seconds:0});
  const calls=[];
  const r=await runWindowsOperation("Bearer mocked",prepared,{
    invoke:async(_,tool,args)=>{calls.push({tool,args});return {value:queued}}
  });
  assert.equal(r.value.terminal,false);
  assert.equal(r.value.command_id,91);
  assert.equal(r.value.nonce,nonce);
  assert.equal(calls.length,1);
  assert.equal(calls[0].tool,"submit_windows_operation");
  assert.deepEqual(calls[0].args,{operation:"file_read",payload:{path}});
});

test("outcome-uncertain needs_review stops wait, retains task identity and never retries",async()=>{
  let now=0;
  const calls=[];
  const claimed={ok:true,command_id:91,status:"needs_review",
    execution_outcome:"UNKNOWN",review_required:true,retry_safe:false};
  const r=await runWindowsOperation("Bearer mocked",{
    operation:"file_write",payload:{path:"C:\\test.txt",content:"no replay"},wait_seconds:2
  },{
    invoke:async(_,tool,args)=>{
      calls.push({tool,args});
      return {value:tool==="submit_windows_operation"?queued:claimed};
    },
    now:()=>now,pause:async ms=>{now+=ms;}
  });
  assert.equal(r.value.status,"needs_review");
  assert.equal(r.value.terminal,true); // queue lifecycle only, not execution success
  assert.equal(r.value.execution_outcome,"UNKNOWN");
  assert.equal(r.value.review_required,true);
  assert.equal(r.value.retry_safe,false);
  assert.equal(r.value.command_id,91);
  assert.equal(r.value.nonce,nonce);
  assert.equal(calls.filter(x=>x.tool==="submit_windows_operation").length,1);
  assert.equal(calls.filter(x=>x.tool==="poll_windows_operation").length,1);
});

test("typed line read has bounded read-only schema and native payload fidelity",()=>{
  const path=String.raw`D:\项目\代码\计划.txt`;
  assert.equal(DIRECT_FILE_LINES_TOOL.name,"read_file_lines");
  assert.equal(DIRECT_FILE_LINES_TOOL.annotations.readOnlyHint,true);
  assert.equal(DIRECT_FILE_LINES_TOOL.annotations.destructiveHint,false);
  assert.equal(DIRECT_FILE_LINES_TOOL.inputSchema.properties.length.maximum,1000);
  assert.deepEqual(DIRECT_FILE_LINES_TOOL.securitySchemes,
    [{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(validDirectFileLinesCall({path,offset:10,length:16,encoding:"gb18030"}),true);
  assert.deepEqual(directFileLinesToWindowsCall({path,offset:10,length:16,encoding:"gb18030",wait_seconds:2}),
    {operation:"file_read_lines",payload:{path,offset:10,length:16,encoding:"gb18030"},wait_seconds:2});
  assert.deepEqual(directFileLinesToWindowsCall({path}),{
    operation:"file_read_lines",payload:{path,offset:0,length:100,encoding:"utf-8"},wait_seconds:8});
  assert.equal(validDirectFileLinesCall({path,offset:-12}),true);
});
test("typed line reader rejects traversal-shaped paths, invalid limits and privilege metadata",()=>{
  const p="C:\\projects\\README.md";
  for(const args of [
    null,{},[],{path:"README.md"},{path:"C:relative.txt"},
    {path:String.raw`\\server\share.txt`},
    {path:"C:\\foo\nbar.txt"},{path:p,offset:-1001},
    {path:p,offset:1000001},{path:p,offset:1.5},
    {path:p,length:0},{path:p,length:1001},{path:p,length:"5"},
    {path:p,encoding:"rot13"},{path:p,wait_seconds:13},
    {path:p,run_as:"system"},{path:p,payload:{script:"whoami"}}
  ]) assert.equal(validDirectFileLinesCall(args),false,JSON.stringify(args));
  assert.throws(()=>directFileLinesToWindowsCall({path:"relative"}),TypeError);
});
test("typed code search binds exact query and pagination to native owner agent",()=>{
  const path=String.raw`D:\项目\代码`;
  const query="file_read_lines";
  assert.equal(DIRECT_CODE_SEARCH_TOOL.name,"search_code");
  assert.equal(DIRECT_CODE_SEARCH_TOOL.annotations.readOnlyHint,true);
  assert.equal(DIRECT_CODE_SEARCH_TOOL.annotations.destructiveHint,false);
  assert.deepEqual(DIRECT_CODE_SEARCH_TOOL.securitySchemes,
    [{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(validDirectCodeSearchCall({path,query,use_regex:true,filename_glob:"*.py",offset:20,limit:2}),true);
  assert.deepEqual(directCodeSearchToWindowsCall({path,query,use_regex:true,filename_glob:"*.py",offset:20,limit:2,wait_seconds:3}),
    {operation:"code_search",payload:{path,query,use_regex:true,case_sensitive:false,filename_glob:"*.py",offset:20,limit:2},wait_seconds:3});
  assert.deepEqual(directCodeSearchToWindowsCall({path,query}),
    {operation:"code_search",payload:{path,query,use_regex:false,case_sensitive:false,filename_glob:"",offset:0,limit:50},wait_seconds:8});
});
test("code search never forwards arbitrary shell, unsupported flags or unbounded input",()=>{
  const p="D:\\projects",query="needle";
  for(const args of [
    null,{},[],{path:p},{path:p,query:""},{path:"/etc/passwd",query},
    {path:String.raw`\\?\C:\Windows`,query},
    {path:p,query,limit:0},{path:p,query,limit:201},
    {path:p,query,offset:-1},{path:p,query,offset:1000001},
    {path:p,query,use_regex:"true"},{path:p,query,case_sensitive:1},
    {path:p,query,filename_glob:5},{path:p,query,wait_seconds:20},
    {path:p,query,run_as:"system"},
    {path:p,query:"a".repeat(1025)}
  ]) assert.equal(validDirectCodeSearchCall(args),false,JSON.stringify(args).slice(0,150));
});
test("typed read-only tools preserve pending task IDs and never submit twice",async()=>{
  const paths=[
    directFileLinesToWindowsCall({path:"D:\\projects\\readme.txt",offset:0,length:10,wait_seconds:0}),
    directCodeSearchToWindowsCall({path:"D:\\projects",query:"test",limit:2,wait_seconds:0})
  ];
  for(const request of paths){
    const calls=[];
    const r=await runWindowsOperation("Bearer mocked",request,{
      invoke:async(_,name,args)=>{calls.push({name,args});return {value:queued};}
    });
    assert.equal(r.value.command_id,91);
    assert.equal(r.value.nonce,nonce);
    assert.equal(r.value.terminal,false);
    assert.equal(calls.length,1);
    assert.equal(calls[0].name,"submit_windows_operation");
    assert.deepEqual(calls[0].args,{operation:request.operation,payload:request.payload});
  }
});

test("session inventory exposes two owner-authenticated read-only tools",()=>{
  assert.deepEqual(DIRECT_SESSION_TOOLS.map(x=>x.name),
    ["list_process_sessions","list_terminal_sessions"]);
  for(const t of DIRECT_SESSION_TOOLS){
    assert.equal(t.annotations.readOnlyHint,true);
    assert.equal(t.annotations.destructiveHint,false);
    assert.deepEqual(t.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
    assert.equal(validDirectSessionCall(t.name,{}),true);
    assert.deepEqual(directSessionToWindowsCall(t.name,{}),{
      operation:t.name==="list_process_sessions"?"process_sessions":"terminal_sessions",
      payload:{},wait_seconds:8
    });
    assert.equal(directSessionToWindowsCall(t.name,{wait_seconds:0}).wait_seconds,0);
  }
});
test("session inventory strictly rejects extra side-effect parameters and illegal wait",()=>{
  for(const t of ["list_process_sessions","list_terminal_sessions"]){
    for(const args of [null,[],{script:"whoami"},{path:"C:\\"},
      {run_as:"system"},{wait_seconds:-1},{wait_seconds:13},
      {wait_seconds:1.5},{wait_seconds:"5"},{confirm:true}]){
      assert.equal(validDirectSessionCall(t,args),false,JSON.stringify(args));
    }
    assert.throws(()=>directSessionToWindowsCall(t,{run_as:"system"}),TypeError);
  }
  assert.equal(validDirectSessionCall("terminate_process",{}),false);
});
test("session listing follows one native queued submit, preserving original receipt",async()=>{
  for(const name of ["list_process_sessions","list_terminal_sessions"]){
    const args=directSessionToWindowsCall(name,{wait_seconds:0});
    const calls=[];
    const result=await runWindowsOperation("Bearer mocked",args,{
      invoke:async(_,tool,payload)=>{calls.push({tool,payload});return {value:queued};}
    });
    assert.equal(result.value.command_id,91);
    assert.equal(result.value.nonce,nonce);
    assert.equal(result.value.terminal,false);
    assert.deepEqual(calls,[{tool:"submit_windows_operation",
      payload:{operation:args.operation,payload:{}}}]);
  }
});
