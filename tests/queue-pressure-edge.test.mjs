import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {classifyQueuePressure,parseExactContentRange,activeQueueComplete} from "../supabase/functions/ocn-owner-health-dispatch/queue-pressure.mjs";
const now="2026-10-25T00:00:00Z",ms=Date.parse(now);
const at=(seconds)=>new Date(ms+seconds*1000).toISOString();
const base=(state={phase:"claim",claims_enabled:true},extra={})=>({
  observedAt:now,agents:[{last_seen_at:at(-2),state}],commands:[],complete:true,...extra
});
test("healthy and complete queue permits only advisory optional work",()=>{
  const x=classifyQueuePressure(base());
  assert.equal(x.ok,true);
  assert.equal(x.reason,"NO_CURRENT_QUEUE_PRESSURE");
  assert.equal(x.advisory_admit_nonessential_diagnostics,true);
  assert.equal(x.mutated_state,false);
});
test("busy execution lane blocks optional diagnostics even without backlog",()=>{
  const x=classifyQueuePressure(base({phase:"execution_lane_busy",claims_enabled:false}));
  assert.equal(x.reason,"SINGLE_FLIGHT_OR_BACKPRESSURE_ACTIVE");
  assert.equal(x.advisory_admit_nonessential_diagnostics,false);
});
test("incomplete queue sample fails closed",()=>{
  assert.equal(classifyQueuePressure(base(undefined,{complete:false})).reason,
    "ACTIVE_QUEUE_SAMPLE_INCOMPLETE");
});
test("heartbeat stale and future clock skew fail closed",()=>{
  const a=base();a.agents[0].last_seen_at=at(-70);
  assert.equal(classifyQueuePressure(a).reason,"AGENT_HEARTBEAT_STALE_OR_UNAVAILABLE");
  a.agents[0].last_seen_at=at(40);
  assert.equal(classifyQueuePressure(a).reason,"AGENT_HEARTBEAT_STALE_OR_UNAVAILABLE");
});
test("unknown claim readiness fails closed",()=>{
  assert.equal(classifyQueuePressure(base({phase:"complete_gzip"})).reason,
    "CLAIM_READINESS_UNVERIFIED");
});
test("long queue and imminent expiry warn",()=>{
  const q=base(undefined,{commands:[{status:"queued",created_at:at(-150),expires_at:at(15)}]});
  const x=classifyQueuePressure(q);
  assert.equal(x.reason,"QUEUE_AGE_HIGH");
  assert.equal(x.oldest_queued_age_s,150);
  assert.equal(x.near_expiry_queued,1);
  const young=base(undefined,{commands:[{status:"queued",created_at:at(-1),expires_at:at(15)}]});
  assert.equal(classifyQueuePressure(young).reason,"NEAR_EXPIRY");
});
test("claimed queue tracks age and counts, not command content",()=>{
  const x=classifyQueuePressure(base(undefined,{commands:[
    {status:"claimed",claimed_at:at(-55),request:{token:"NEVER_EXPOSE"},stdout:"NEVER_EXPOSE"}
  ]}));
  assert.equal(x.oldest_claimed_age_s,55);
  assert.equal(x.counts.claimed,1);
  assert.ok(!JSON.stringify(x).includes("NEVER_EXPOSE"));
});
test("invalid input is not silently accepted",()=>{
  assert.equal(classifyQueuePressure({observedAt:"invalid",agents:[],commands:[],complete:true}).ok,false);
});
test("Edge handler is read-only and owner protected",()=>{
  const index=readFileSync(new URL("../supabase/functions/ocn-owner-health-dispatch/index.ts",import.meta.url),"utf8");
  const s=index.slice(index.indexOf("async function queuePressureStatus()"),index.indexOf("async function dispatchHealth()"));
  assert.ok(s.includes('method:"GET"'));
  assert.ok(!s.includes('method:"POST"'));
  assert.ok(!s.includes('method:"PATCH"'));
  assert.ok(!s.includes('method:"DELETE"'));
  assert.ok(index.indexOf("if (!(await authenticated(")<index.indexOf('if(action==="queue_pressure_status")'));
  assert.ok(index.includes('action === "queue_pressure_status" && keys === "action"'));
});
test("Render MCP only exposes queue telemetry with owner OAuth",()=>{
  const s=readFileSync(new URL("../canary/mcp/server.mjs",import.meta.url),"utf8");
  assert.ok(s.includes('name:"queue_pressure_status"'));
  assert.ok(s.includes('securitySchemes:[{type:"oauth2",scopes:["openid","email"]}]'));
  assert.ok(s.includes('body:JSON.stringify({action:"queue_pressure_status"})'));
  assert.ok(s.includes('r.status===401'));
  assert.ok(s.includes('active_queue_complete'));
  assert.ok(!s.includes("QUEUE_PRESSURE_ENFORCE_SUBMIT"));
});

test("exact PostgREST Content-Range total handles zero and normal counts",()=>{
  assert.equal(parseExactContentRange("*/0"),0);
  assert.equal(parseExactContentRange("0-1/2"),2);
  assert.equal(parseExactContentRange("0-999/1500"),1500);
  assert.equal(parseExactContentRange("0-999/*"),null);
  assert.equal(parseExactContentRange(null),null);
  assert.equal(parseExactContentRange("malformed/20"),null);
  assert.equal(parseExactContentRange("0-9/999999999999999999999999"),null);
});
test("API max_rows truncation is never considered complete",()=>{
  assert.equal(activeQueueComplete(Array(1000).fill({}),1500),false);
  assert.equal(activeQueueComplete(Array(77).fill({}),92),false);
  assert.equal(activeQueueComplete(Array(1000).fill({}),3000),false);
  assert.equal(activeQueueComplete(Array(25).fill({}),25),true);
  assert.equal(activeQueueComplete([],0),true);
});
test("invalid or over-limit queue samples do not pass",()=>{
  assert.equal(activeQueueComplete(Array(2).fill({}),1),null);
  assert.equal(activeQueueComplete(Array(2001).fill({}),2001),null);
  assert.equal(activeQueueComplete([],null),null);
  assert.equal(activeQueueComplete({},0),null);
});
test("Edge pressure selector requests exact count and owner-device scoping",()=>{
  const index=readFileSync(new URL("../supabase/functions/ocn-owner-health-dispatch/index.ts",import.meta.url),"utf8");
  const start=index.indexOf("async function queuePressureStatus()");
  const stop=index.indexOf("async function dispatchHealth()",start);
  assert.ok(start>0 && stop>start);
  const section=index.slice(start,stop);
  assert.ok(section.includes('headers:serverHeaders("count=exact")'));
  assert.ok(section.includes('"request->>bound_owner":"eq."+OWNER'));
  assert.ok(section.includes('"request->>bound_agent_id":"eq."+DEVICE'));
  assert.ok(section.includes('cmdRes.headers.get("content-range")'));
  assert.ok(section.includes('activeQueueComplete(active,count,2000)'));
  assert.ok(section.includes('method:"GET"'));
  for (const method of ["POST","PATCH","DELETE"])assert.ok(!section.includes('method:"'+method+'"'));
  assert.ok(!section.includes('select:"request'));
});

test("expired claimed command is a bounded needs_review receipt, never a false 404",()=>{
  const index=readFileSync(new URL("../supabase/functions/ocn-owner-health-dispatch/index.ts",
    import.meta.url),"utf8");
  const start=index.indexOf("async function pollWindows(");
  const end=index.indexOf("\nDeno.serve(",start);
  assert.ok(start>=0 && end>start);
  const poll=index.slice(start,end);
  assert.match(index,/const STATE = new Set\([^\n]*"needs_review"/);
  assert.ok(poll.includes('if(row.status==="needs_review")'));
  assert.ok(poll.includes('review_required:true,retry_safe:false'));
  assert.ok(poll.includes('execution_outcome:"UNKNOWN"'));
  assert.ok(poll.includes('command_id:id'));
  assert.ok(!poll.includes('error:row.error'));
  assert.ok(!poll.includes('request:req'));
  // The SQL row is never mutated by checking a task's state.
  for(const verb of ["POST","PATCH","DELETE"])
    assert.ok(!poll.includes('method:"'+verb+'"'));
});

test("owner Edge only admits bounded non-cursor session output reads",()=>{
  const index=readFileSync(new URL("../supabase/functions/ocn-owner-health-dispatch/index.ts",
    import.meta.url),"utf8");
  const start=index.indexOf("function validWindowsPayload(");
  const end=index.indexOf("\nasync function submitWindows(",start);
  assert.ok(start>0 && end>start);
  const validator=index.slice(start,end);
  assert.ok(index.includes('"process_sessions","process_read"'));
  assert.ok(index.includes('"terminal_sessions","terminal_read"'));
  assert.ok(validator.includes('operation==="process_read"||operation==="terminal_read"'));
  assert.ok(validator.includes('payload.offset>=0 && payload.offset<=1000000000'));
  assert.ok(validator.includes('payload.max_bytes>=1 && payload.max_bytes<=65536'));
  assert.ok(validator.includes('payload.wait_ms===0'));
  assert.ok(validator.includes('NONCE.test(payload[idField])'));
  assert.ok(validator.includes('keys.length===4'));
  assert.ok(validator.includes('keys.every(k=>allowed.has(k))'));
  assert.ok(!validator.includes('payload.run_as'));
  assert.ok(index.indexOf('if (!(await authenticated(')<index.indexOf('if(action==="submit_windows_operation")'));
});

test("C5 owner-only queued cancellation performs exactly one CAS PATCH",()=>{
  const index=readFileSync(new URL("../supabase/functions/ocn-owner-health-dispatch/index.ts",
    import.meta.url),"utf8");
  const start=index.indexOf("async function cancelQueuedWindows(");
  const end=index.indexOf("\nasync function pollWindows(",start);
  assert.ok(start>0 && end>start);
  const cancel=index.slice(start,end);
  assert.ok(cancel.includes("validCancelReference(input)"));
  assert.ok(cancel.includes("queuedCancelFilter(input,OWNER,DEVICE)"));
  assert.equal((cancel.match(/method:"PATCH"/g)||[]).length,1);
  assert.ok(cancel.includes('headers:serverHeaders("return=representation")'));
  assert.ok(cancel.includes('status:"cancelled"'));
  assert.ok(cancel.includes('error:"QUEUED_OWNER_CANCELLED"'));
  assert.ok(cancel.includes('classifyCancelAfterRace(rows[0],input,OWNER,DEVICE)'));
  assert.ok(cancel.includes('response(classified.ok?200:409,classified)'));
  assert.ok(!cancel.includes('status:"claimed"'));
  assert.ok(!cancel.includes('run_as'));
  assert.ok(!cancel.includes('method:"DELETE"'));
  assert.ok(!cancel.includes("payload:row"));
});
test("C5 cancellation requires the same signed owner OAuth and exact reference",()=>{
  const index=readFileSync(new URL("../supabase/functions/ocn-owner-health-dispatch/index.ts",
    import.meta.url),"utf8");
  const auth=index.indexOf('if (!(await authenticated(');
  const action=index.indexOf('if(action==="cancel_queued_windows_operation")');
  assert.ok(auth>0 && action>auth);
  assert.ok(index.includes('action === "cancel_queued_windows_operation" && keys === "action,command_id,nonce"'));
  assert.ok(index.includes('if(row.status==="cancelled" && row.error==="QUEUED_OWNER_CANCELLED")'));
  assert.ok(index.includes('execution_state:"CANCELLED_BEFORE_CLAIM"'));
  assert.ok(index.includes('cancelled_before_claim:true'));
  assert.ok(index.includes('"claimed","uploading"'));
  const server=readFileSync(new URL("../canary/mcp/server.mjs",import.meta.url),"utf8");
  assert.ok(server.includes('"cancel_queued_windows_operation"].includes(tool)'));
  assert.ok(server.includes('result.conflict||result.uncertain'));
  assert.ok(server.includes('structuredContent:receipt,isError:true'));
});
