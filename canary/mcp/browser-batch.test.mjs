import test from "node:test";
import assert from "node:assert/strict";
import {validBrowserBatch,buildBrowserBatchRequest} from "./browser-batch.mjs";
import {validBrowserPayload as validRenderPayload} from "./browser-operation-policy.mjs";
import {validBrowserPayload as validEdgePayload} from "../../supabase/functions/ocn-owner-health-dispatch/browser-operation-policy.mjs";

const base={steps:[
  {tool:"browser_click",arguments:{target:"#file"}},
  {tool:"browser_file_upload",arguments:{paths:["D:\\ChatGPT-Local-Bridge\\staging\\ocn-playwright-full\\sample-upload.txt"]}},
  {tool:"browser_snapshot",arguments:{}}
]};

function assertConsistent(request, expected){
  assert.equal(validBrowserBatch(request),expected,"public MCP validator");
  const {reuse_session:unused,...payload}=request;
  assert.equal(validRenderPayload("browser_batch_unified",payload),expected,"Render router");
  assert.equal(validEdgePayload("browser_batch_unified",payload),expected,"Supabase Edge router");
}

test("uploads use the typed, owner-bound persistent route without shell interpolation",()=>{
  assertConsistent(base,true);
  const queued=buildBrowserBatchRequest({...base,reuse_session:false});
  assert.equal(queued.operation,"browser_batch_unified");
  assert.deepEqual(queued.payload,base);
  assert.equal(Object.hasOwn(queued.payload,"script"),false);
  assert.equal(Object.hasOwn(queued.payload,"run_as"),false);
});

test("browser code, CDP, interception and storage need explicit opt-in",()=>{
  for(const tool of ["browser_run_code_unsafe","browser_evaluate","browser_cdp_send","browser_route","browser_storage_state"]){
    const req={steps:[{tool,arguments:{}}]};
    assertConsistent(req,false);
    assertConsistent({...req,unsafe_approved:true},true);
  }
});

test("vision, PDF and DevTools tools require matching capabilities",()=>{
  for(const [tool,capability] of [
    ["browser_mouse_click_xy","vision"],
    ["browser_pdf_save","pdf"],
    ["browser_start_tracing","devtools"]
  ]){
    const req={steps:[{tool,arguments:{}}]};
    assertConsistent(req,false);
    assertConsistent({...req,capabilities:[capability]},true);
  }
  assertConsistent({steps:[{tool:"browser_snapshot",arguments:{}}],capabilities:["testing"]},false);
  assertConsistent({steps:[{tool:"browser_snapshot",arguments:{}}],capabilities:["pdf","pdf"]},false);
});

test("reject non-browser operations, private URLs and oversized data",()=>{
  for(const tool of ["powershell","file_read","browser_upload;rm -rf /","browser_"])
    assertConsistent({steps:[{tool,arguments:{}}]},false);
  assertConsistent({steps:[{tool:"browser_type",arguments:{text:"x".repeat(16000)}}]},false);
  assertConsistent({steps:[]},false);
  assert.equal(validBrowserBatch({steps:[{tool:"browser_snapshot",arguments:{}}],extra:"bad"}),false);
  for(const url of ["file:///C:/Windows","http://localhost:3000","http://127.0.0.1/admin",
    "http://192.168.1.1","https://user:pass@example.com","chrome://settings/passwords/"])
    assertConsistent({steps:[{tool:"browser_navigate",arguments:{url}}]},false);
  assertConsistent({steps:[{tool:"browser_navigate",arguments:{url:"https://example.com"}}]},true);
  assertConsistent({steps:[{tool:"browser_navigate",arguments:{url:"chrome://version/"}}]},true);
  assertConsistent({steps:[{tool:"browser_tabs",arguments:{action:"new",url:"chrome://version/"}}]},false);
});

test("malformed uploads fail; user text stays in structured JSON data",()=>{
  assertConsistent({steps:[{tool:"browser_file_upload",arguments:{paths:"secret"}}]},false);
  const adversarial={steps:[{tool:"browser_type",arguments:{text:"'; Write-Host ATTACK #"}}]};
  assertConsistent(adversarial,true);
  const queued=buildBrowserBatchRequest(adversarial);
  assert.deepEqual(queued.payload.steps,adversarial.steps);
  assert.equal(Object.hasOwn(queued.payload,"script"),false);
});

test("synchronous and durable background download tools share one session",()=>{
  const req={steps:[
    {tool:"browser_download_watch",arguments:{directory:"D:\\Downloads"}},
    {tool:"browser_click",arguments:{target:"#download"}},
    {tool:"browser_download_verify",arguments:{
      directory:"D:\\Downloads",filename:"fixture.txt",
      expected_sha256:"a".repeat(64),timeout_seconds:25,min_bytes:1
    }}
  ]};
  const start={steps:[
    {tool:"browser_download_watch_async",arguments:{directory:"D:\\Downloads",filename:"large.zip",timeout_seconds:21600,min_bytes:1}},
    {tool:"browser_click",arguments:{target:"#download"}}
  ]};
  const check={steps:[{tool:"browser_download_status_async",arguments:{job_id:"0".repeat(32)}}]};
  for(const payload of [req,start,check]){
    assertConsistent(payload,true);
    assert.equal(buildBrowserBatchRequest(payload).operation,"browser_batch_unified");
  }
});

test("deprecated reuse_session flag never opts a call out of persistence",()=>{
  for(const reuse_session of [true,false]){
    const request={steps:[{tool:"browser_tab_list",arguments:{}}],reuse_session};
    assert.equal(validBrowserBatch(request),true);
    assert.equal(buildBrowserBatchRequest(request).operation,"browser_batch_unified");
  }
});
