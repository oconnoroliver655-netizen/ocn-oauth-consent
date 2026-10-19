import test from "node:test";
import assert from "node:assert/strict";
import {validBrowserBatch,buildBrowserBatchRequest} from "./browser-batch.mjs";
const base={steps:[
  {tool:"browser_click",arguments:{target:"#file"}},
  {tool:"browser_file_upload",arguments:{paths:["D:\\\\ChatGPT-Local-Bridge\\\\staging\\\\ocn-playwright-full\\\\sample-upload.txt"]}},
  {tool:"browser_snapshot",arguments:{}},
]};
test("approved upload batch encodes only Base64 and uses the limited user",()=>{
  assert.equal(validBrowserBatch(base),true);
  const r=buildBrowserBatchRequest(base,{id:"01234567-89ab-4cde-a234-0123456789ab"});
  assert.equal(r.operation,"powershell");
  assert.equal(r.payload.run_as,"oliver");
  assert.equal(r.payload.timeout_seconds,300);
  assert.equal(r.payload.script.includes("sample-upload.txt"),false);
  assert.equal(r.payload.script.includes("ocn_playwright_extended.py"),true);
  assert.equal(r.payload.script.includes("Remove-Item"),true);
});
test("browser code, CDP and interception need opt-in",()=>{
  for(const tool of ["browser_run_code_unsafe","browser_evaluate","browser_cdp_send","browser_route"]){
    const req={steps:[{tool,arguments:{}}]};
    assert.equal(validBrowserBatch(req),false);
    assert.equal(validBrowserBatch({...req,unsafe_approved:true}),true);
  }
});
test("reject non-browser operations and oversized data",()=>{
  for(const tool of ["powershell","file_read","browser_upload;rm -rf /","browser_"]){
    assert.equal(validBrowserBatch({steps:[{tool,arguments:{}}]}),false);
  }
  assert.equal(validBrowserBatch({steps:[{tool:"browser_type",arguments:{text:"x".repeat(16000)}}]}),false);
  assert.equal(validBrowserBatch({steps:[]}),false);
  assert.equal(validBrowserBatch({steps:[{tool:"browser_snapshot",arguments:{}}],extra:"bad"}),false);
});
test("prevent malformed upload and prevent command substitution",()=>{
  assert.equal(validBrowserBatch({steps:[{tool:"browser_file_upload",arguments:{paths:"secret"}}]}),false);
  const adversarial={steps:[{tool:"browser_type",arguments:{text:"'; Write-Host ATTACK #"}}]};
  assert.equal(validBrowserBatch(adversarial),true);
  const r=buildBrowserBatchRequest(adversarial,{id:"01234567-89ab-4cde-a234-0123456789ab"});
  assert.equal(r.payload.script.includes("Write-Host ATTACK"),false);
});

test("allow signed owner browser download watch, click and hash verification",()=>{
  const req={steps:[
    {tool:"browser_download_watch",arguments:{directory:"D:\\\\Downloads"}},
    {tool:"browser_click",arguments:{target:"#download"}},
    {tool:"browser_download_verify",arguments:{
      directory:"D:\\\\Downloads",filename:"fixture.txt",
      expected_sha256:"a".repeat(64),timeout_seconds:25,min_bytes:1
    }}
  ]};
  assert.equal(validBrowserBatch(req),true);
  const queued=buildBrowserBatchRequest(req,{id:"01234567-89ab-4cde-a234-0123456789ab"});
  assert.equal(queued.payload.run_as,"oliver");
  assert.equal(queued.payload.timeout_seconds,300);
  assert.equal(queued.payload.script.includes("fixture.txt"),false);
});

test("accept detached background download watcher and durable status without unsafe mode",()=>{
  const start={steps:[
    {tool:"browser_download_watch_async",arguments:{
      directory:"D:\\\\Downloads",filename:"large-archive.zip",
      timeout_seconds:21600,min_bytes:1
    }},
    {tool:"browser_click",arguments:{target:"#download"}}
  ]};
  const check={steps:[{tool:"browser_download_status_async",arguments:{
    job_id:"0".repeat(32)}}]};
  assert.equal(validBrowserBatch(start),true);
  assert.equal(validBrowserBatch(check),true);
  assert.equal(buildBrowserBatchRequest(start,{id:"01234567-89ab-4cde-a234-0123456789ab"}).payload.run_as,"oliver");
  assert.equal(buildBrowserBatchRequest(check,{id:"01234567-89ab-4cde-a234-0123456789ab"}).payload.timeout_seconds,220);
});
