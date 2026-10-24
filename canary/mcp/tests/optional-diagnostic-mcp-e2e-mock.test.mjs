import {test,after} from "node:test";
import assert from "node:assert/strict";
import {request as httpRequest} from "node:http";

// In-process MCP server with a synthetic Edge transport. NO live OAuth token,
// database, Windows task, real external fetch or network dependency is used.
const ORIGIN="https://ocn-mcp-canary.onrender.com";
process.env.OCN_PUBLIC_ORIGIN=ORIGIN;
const {start}=await import("../server.mjs");
const server=start(0);
await new Promise(resolve=>server.once("listening",resolve));
after(()=>server.close());
const local="http://127.0.0.1:"+server.address().port;

function httpPost(payload,authorized=true){
  return new Promise((resolve,reject)=>{
    const body=JSON.stringify({jsonrpc:"2.0",id:100,method:"tools/call",params:payload});
    const headers={
      "host":new URL(ORIGIN).host,
      "accept":"application/json, text/event-stream",
      "content-type":"application/json",
      "mcp-protocol-version":"2025-06-18",
    };
    if(authorized) headers.authorization="Bearer SYNTHETIC_FIXTURE_NOT_A_REAL_TOKEN";
    const req=httpRequest(local+"/mcp-oauth",{method:"POST",headers},res=>{
      const chunks=[];
      res.on("data",x=>chunks.push(x));
      res.on("end",()=>{
        const raw=Buffer.concat(chunks).toString("utf8");
        try {resolve({status:res.statusCode,result:JSON.parse(raw).result});}
        catch(e){reject(e);}
      });
    });
    req.on("error",reject);
    req.end(body);
  });
}
function healthy(){
  return {
    ok:true,mutated_state:false,reason:"NO_CURRENT_QUEUE_PRESSURE",
    advisory_admit_nonessential_diagnostics:true,
    active_queue_complete:true,heartbeat_age_s:2,
    agent_phase:"claim",claims_enabled:true,
    counts:{queued:0,claimed:0,running:0},
    oldest_queued_age_s:null,oldest_claimed_age_s:null,near_expiry_queued:0
  };
}

test("MCP optional path never enqueues on busy, error, missing OAuth or invalid operation",async()=>{
  const original=globalThis.fetch;
  let mode="busy";
  const remote=[];
  globalThis.fetch=async(url,options)=>{
    const parsed=JSON.parse(options.body);
    remote.push({url:String(url),action:parsed.action,operation:parsed.operation});
    assert.equal(String(url),"https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-owner-health-dispatch");
    assert.equal(options.headers.authorization,"Bearer SYNTHETIC_FIXTURE_NOT_A_REAL_TOKEN");
    if(parsed.action==="queue_pressure_status"){
      if(mode==="unavailable")return new Response(JSON.stringify({ok:false}),{status:503});
      const data=healthy();
      if(mode==="busy"){
        data.reason="SINGLE_FLIGHT_OR_BACKPRESSURE_ACTIVE";
        data.advisory_admit_nonessential_diagnostics=false;
        data.agent_phase="execution_lane_busy";data.claims_enabled=false;
      }
      if(mode==="incomplete"){
        data.active_queue_complete=false;
        data.advisory_admit_nonessential_diagnostics=false;
        data.reason="ACTIVE_QUEUE_SAMPLE_INCOMPLETE";
      }
      return new Response(JSON.stringify(data),{status:200});
    }
    if(parsed.action==="submit_windows_operation"){
      return new Response(JSON.stringify({
        ok:true,command_id:1234,nonce:"a".repeat(32),status:"queued",operation:parsed.operation
      }),{status:202});
    }
    throw new Error("Unexpected synthetic Edge action");
  };
  try{
    const invalid=await httpPost({name:"submit_optional_diagnostic",arguments:{operation:"powershell"}});
    assert.equal(invalid.status,200);assert.equal(invalid.result.isError,true);
    assert.equal(remote.length,0);

    const missing=await httpPost({name:"submit_optional_diagnostic",arguments:{operation:"desktop_health"}},false);
    assert.equal(missing.status,200);assert.equal(missing.result.isError,true);
    assert.match(missing.result._meta["mcp/www_authenticate"][0],/invalid_token/);
    assert.equal(remote.length,0);

    mode="busy";
    const busy=await httpPost({name:"submit_optional_diagnostic",arguments:{operation:"desktop_health"}});
    assert.equal(busy.status,200);
    assert.equal(busy.result.structuredContent.deferred,true);
    assert.equal(busy.result.structuredContent.queued,false);
    assert.deepEqual(remote.map(x=>x.action),["queue_pressure_status"]);

    // Concurrent optional producers may query telemetry, but none may reach
    // Windows dispatch when Edge pressure reports busy.
    remote.length=0;
    const batch=await Promise.all(Array.from({length:12},()=>httpPost({
      name:"submit_optional_diagnostic",arguments:{operation:"desktop_lease_status"}
    })));
    assert.equal(batch.length,12);
    assert.ok(batch.every(r=>r.result.structuredContent.deferred===true));
    assert.equal(remote.filter(x=>x.action==="submit_windows_operation").length,0);
    assert.equal(remote.filter(x=>x.action==="queue_pressure_status").length,12);

    for(const state of ["unavailable","incomplete"]){
      remote.length=0;mode=state;
      const outcome=await httpPost({name:"submit_optional_diagnostic",arguments:{operation:"process_sessions"}});
      assert.equal(outcome.result.structuredContent.deferred,true);
      assert.equal(remote.filter(x=>x.action==="submit_windows_operation").length,0);
    }

    remote.length=0;mode="healthy";
    const allowed=await httpPost({name:"submit_optional_diagnostic",arguments:{operation:"terminal_sessions"}});
    assert.equal(allowed.result.structuredContent.status,"queued");
    assert.equal(allowed.result.structuredContent.command_id,1234);
    assert.equal(allowed.result.structuredContent.admission_mode,"optional_preflight");
    assert.deepEqual(remote.map(x=>x.action),["queue_pressure_status","submit_windows_operation"]);
    assert.equal(remote[1].operation,"terminal_sessions");

    // Legacy owner-authorized essential route is intentionally NOT affected
    // by optional admission checks. This verifies compatibility, not privilege.
    remote.length=0;mode="busy";
    const legacy=await httpPost({name:"submit_windows_operation",
      arguments:{operation:"desktop_health",payload:{}}});
    assert.equal(legacy.result.structuredContent.status,"queued");
    assert.deepEqual(remote.map(x=>x.action),["submit_windows_operation"]);
  } finally {globalThis.fetch=original;}
});
