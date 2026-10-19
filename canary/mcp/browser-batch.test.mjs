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
  assert.equal(r.payload.timeout_seconds,540);
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
