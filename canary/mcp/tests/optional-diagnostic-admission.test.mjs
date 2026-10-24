import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {
  OPTIONAL_DIAGNOSTIC_TOOL,
  validOptionalDiagnosticCall,
  prepareOptionalDiagnostic,
  planOptionalDiagnosticAdmission
} from "../optional-diagnostic-admission.mjs";
const good={
  ok:true,mutated_state:false,active_queue_complete:true,
  reason:"NO_CURRENT_QUEUE_PRESSURE",
  advisory_admit_nonessential_diagnostics:true,
  heartbeat_age_s:2,claims_enabled:true,
  counts:{queued:0,claimed:0,running:0}
};
test("advertises a strict opt-in OAuth protected tool",()=>{
  assert.equal(OPTIONAL_DIAGNOSTIC_TOOL.name,"submit_optional_diagnostic");
  assert.deepEqual(OPTIONAL_DIAGNOSTIC_TOOL.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(OPTIONAL_DIAGNOSTIC_TOOL.annotations.readOnlyHint,false);
  assert.equal(OPTIONAL_DIAGNOSTIC_TOOL.annotations.destructiveHint,false);
  assert.equal(OPTIONAL_DIAGNOSTIC_TOOL.inputSchema.additionalProperties,false);
});
test("only four fixed read-only diagnostic operations are permitted",()=>{
  for (const operation of ["desktop_health","process_sessions","terminal_sessions","desktop_lease_status"]) {
    assert.equal(validOptionalDiagnosticCall({operation}),true);
    assert.deepEqual(prepareOptionalDiagnostic({operation}),{operation,payload:{}});
  }
});
test("rejects shell, mutation, GUI and caller-supplied arbitrary payload",()=>{
  const inputs=[
    {operation:"powershell"}, {operation:"exec"}, {operation:"file_read"},
    {operation:"file_write"}, {operation:"browser_batch"}, {operation:"screenshot"},
    {operation:"desktop_health",payload:{run_as:"system"}},
    {operation:"desktop_health",device:"other"},
    {operation:"desktop_health",timeout_seconds:500},
    {},[],null, {operation:5}
  ];
  for(const input of inputs) {
    assert.equal(validOptionalDiagnosticCall(input),false);
    assert.throws(()=>prepareOptionalDiagnostic(input),TypeError);
  }
});
test("healthy complete telemetry grants optional admission",()=>{
  assert.deepEqual(planOptionalDiagnosticAdmission(good),{
    admitted:true,reason:"NO_CURRENT_QUEUE_PRESSURE"
  });
});
test("busy lane refuses optional work without submitting anything",()=>{
  const res=planOptionalDiagnosticAdmission({...good,
    reason:"SINGLE_FLIGHT_OR_BACKPRESSURE_ACTIVE",
    advisory_admit_nonessential_diagnostics:false});
  assert.deepEqual(res,{admitted:false,reason:"SINGLE_FLIGHT_OR_BACKPRESSURE_ACTIVE"});
});
test("missing, malformed and incomplete telemetry fails closed",()=>{
  for (const v of [null,undefined,{},[],{...good,ok:false},
    {...good,active_queue_complete:false},
    {...good,mutated_state:true},
    {...good,reason:"NO_CURRENT_QUEUE_PRESSURE",advisory_admit_nonessential_diagnostics:"true"}]) {
    assert.equal(planOptionalDiagnosticAdmission(v).admitted,false);
  }
});
test("contradictory admission signal refuses optional work",()=>{
  assert.equal(planOptionalDiagnosticAdmission({...good,
    reason:"NO_CURRENT_QUEUE_PRESSURE",advisory_admit_nonessential_diagnostics:false}).admitted,false);
  assert.equal(planOptionalDiagnosticAdmission({...good,
    reason:"AGENT_HEARTBEAT_STALE_OR_UNAVAILABLE",advisory_admit_nonessential_diagnostics:true}).admitted,false);
});
test("the original owner-authorized submit and poll code remains intact",()=>{
  const source=readFileSync(new URL("../server.mjs",import.meta.url),"utf8");
  assert.ok(source.includes('if (oauthProbePath && (tool==="submit_windows_operation" || tool==="poll_windows_operation"))'));
  assert.ok(source.includes('if (oauthProbePath && tool==="submit_optional_diagnostic")'));
  assert.ok(source.includes('const pressure=await callQueuePressureEdge(bearer);'));
  assert.ok(source.includes('const plan=planOptionalDiagnosticAdmission(pressure.value);'));
  assert.ok(source.includes('const request=prepareOptionalDiagnostic(args);'));
  assert.ok(source.includes('callWindowsOperation(bearer,"submit_windows_operation",request)'));
  assert.ok(source.includes('deferred:true,queued:false'));
  assert.ok(source.includes('if(pressure.unauthorized)return respond(res,200,ok(id,ownerChallenge()))'));
});
test("no clock, timer, network, file access or task side effects in policy module",()=>{
  const src=readFileSync(new URL("../optional-diagnostic-admission.mjs",import.meta.url),"utf8");
  for(const banned of ["fetch(", "Deno.", "process.env", "readFileSync(", "writeFileSync(", "Date.now(", "setTimeout("]) {
    assert.equal(src.includes(banned),false,banned);
  }
});
