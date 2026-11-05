import test from "node:test";
import assert from "node:assert/strict";
import {validCancelReference,queuedCancelFilter,classifyCancelAfterRace,resolveQueuedCancel}
  from "../supabase/functions/ocn-owner-health-dispatch/cancel-queued.mjs";

const nonce="a".repeat(32);
const ref={command_id:18000,nonce};
const owner="fixed-owner",device="DESKTOP-TEST-agent";
const row=(status,extra={})=>({id:ref.command_id,nonce,kind:"local_commander",
  request:{bound_owner:owner,bound_agent_id:device,operation:"file_write",
    payload:{secret:"NEVER_EXPOSE"}},status,error:null,...extra});

test("queue cancel reference accepts only original task id and nonce",()=>{
  assert.equal(validCancelReference(ref),true);
  for(const bad of [null,{},[],{command_id:0,nonce},
    {command_id:2.4,nonce},{command_id:ref.command_id,nonce:"wrong"},
    {command_id:ref.command_id,nonce:nonce.toUpperCase()},
    {command_id:ref.command_id,nonce,run_as:"system"},
    {command_id:ref.command_id,nonce,device:"elsewhere"}])
    assert.equal(Boolean(validCancelReference(bad)),false,JSON.stringify(bad));
});
test("CAS filter must atomically match original task, owner, device and queued",()=>{
  const q=queuedCancelFilter(ref,owner,device);
  assert.deepEqual([...q.entries()],[["select","id,status"],
    ["id","eq."+ref.command_id],["nonce","eq."+nonce],
    ["kind","eq.local_commander"],["status","eq.queued"],
    ["request->>bound_owner","eq."+owner],
    ["request->>bound_agent_id","eq."+device]]);
  assert.match(q.toString(),/status=eq.queued/);
  assert.throws(()=>queuedCancelFilter({command_id:3,nonce:"bad"},owner,device),TypeError);
  assert.throws(()=>queuedCancelFilter(ref,"",device),TypeError);
});
test("after lost response same queued cancellation is idempotent",()=>{
  const actual=classifyCancelAfterRace(row("cancelled",
    {error:"QUEUED_OWNER_CANCELLED"}),ref,owner,device);
  assert.deepEqual(actual,{ok:true,command_id:ref.command_id,status:"cancelled",
    cancelled:true,already_cancelled:true,cancellation_scope:"queued_only",
    execution_outcome:"NOT_STARTED"});
  assert.ok(!JSON.stringify(actual).includes("NEVER_EXPOSE"));
});
test("claimed/uploading and unknown outcomes are never reported as cancelled",()=>{
  for(const status of ["claimed","uploading","completed","failed","expired","needs_review"]){
    const x=classifyCancelAfterRace(row(status),ref,owner,device);
    assert.equal(x.cancelled,false);
    assert.equal(x.ok,false);
    assert.equal(x.status,status);
    assert.equal(x.error,"CANCEL_TOO_LATE");
    if(["claimed","uploading","needs_review"].includes(status))
      assert.equal(x.execution_outcome,"UNKNOWN");
  }
});
test("non-queued race is unknown when another actor cancelled without our marker",()=>{
  const x=classifyCancelAfterRace(row("cancelled",
    {error:"UNKNOWN_REASON"}),ref,owner,device);
  assert.equal(x.cancelled,false);
  assert.equal(x.error,"CANCEL_TOO_LATE");
  assert.notEqual(x.execution_outcome,"NOT_STARTED");
});
test("mismatched owner, device, nonce, kind, id and malformed states fail closed",()=>{
  for(const changed of [
    {id:18001},{nonce:"b".repeat(32)},{kind:"other"},
    {request:{bound_owner:"another",bound_agent_id:device}},
    {request:{bound_owner:owner,bound_agent_id:"other"}},
    {status:"running"},{status:null}
  ]){
    const x=classifyCancelAfterRace(row("cancelled",
      {error:"QUEUED_OWNER_CANCELLED",...changed}),ref,owner,device);
    assert.equal(x,null,JSON.stringify(changed));
  }
});
test("claim and queued cancellation compare-and-swap cannot both commit",()=>{
  for(const first of ["claim","cancel"]){
    const state={status:"queued"};
    const claim=()=>{if(state.status!=="queued")return false;state.status="claimed";return true;};
    const cancel=()=>{if(state.status!=="queued")return false;state.status="cancelled";return true;};
    const firstWins=first==="claim"?claim():cancel();
    const secondWins=first==="claim"?cancel():claim();
    assert.equal(firstWins,true);
    assert.equal(secondWins,false);
    assert.equal(state.status,first==="claim"?"claimed":"cancelled");
  }
});
test("queued-but-not-updated is unresolved, so the original reference may be retried",()=>{
  const x=classifyCancelAfterRace(row("queued"),ref,owner,device);
  assert.equal(x.cancelled,false);
  assert.equal(x.retry_same_reference,true);
  assert.equal(x.error,"CANCEL_RACE_UNRESOLVED");
});


test("real state-machine adapter cancels before claim with one atomic request",async()=>{
  const events=[];
  let current=row("queued");
  const patch=async filter=>{
    events.push({kind:"PATCH",filter:[...filter.entries()]});
    if(current.status!=="queued" || filter.get("nonce")!=="eq."+nonce)
      return [];
    current=row("cancelled",{error:"QUEUED_OWNER_CANCELLED"});
    return [{id:ref.command_id,status:"cancelled"}];
  };
  const lookup=async()=>{events.push({kind:"GET"});return [current];};
  const first=await resolveQueuedCancel(ref,owner,device,{patch,lookup});
  assert.equal(first.http_status,200);
  assert.equal(first.body.cancelled,true);
  assert.equal(first.body.already_cancelled,false);
  assert.equal(first.body.execution_outcome,"NOT_STARTED");
  assert.equal(events.filter(x=>x.kind==="PATCH").length,1);
  assert.equal(events.filter(x=>x.kind==="GET").length,0);
  const duplicate=await resolveQueuedCancel(ref,owner,device,{patch,lookup});
  assert.equal(duplicate.http_status,200);
  assert.equal(duplicate.body.already_cancelled,true);
  assert.equal(duplicate.body.cancelled,true);
  assert.equal(events.filter(x=>x.kind==="PATCH").length,2);
  assert.equal(events.filter(x=>x.kind==="GET").length,1);
  assert.ok(!JSON.stringify([first,duplicate]).includes("NEVER_EXPOSE"));
});
test("concurrent agent claim wins: cancellation returns conflict, not false success",async()=>{
  let state=row("queued"),patchCount=0,lookupCount=0;
  const claim=()=>{if(state.status!=="queued")return false;
    state=row("claimed");return true;};
  assert.equal(claim(),true);
  const v=await resolveQueuedCancel(ref,owner,device,{
    patch:async q=>{
      patchCount++;
      assert.equal(q.get("status"),"eq.queued");
      return state.status==="queued"?[{id:ref.command_id,status:"cancelled"}]:[];
    },
    lookup:async()=>{lookupCount++;return [state];}
  });
  assert.equal(patchCount,1);
  assert.equal(lookupCount,1);
  assert.equal(v.http_status,409);
  assert.equal(v.body.cancelled,false);
  assert.equal(v.body.execution_outcome,"UNKNOWN");
  assert.equal(state.status,"claimed");
});
test("cancelled wins the queued race: later claim cannot start",async()=>{
  let state="queued";
  const outcome=await resolveQueuedCancel(ref,owner,device,{
    patch:async filter=>{
      assert.equal(filter.get("status"),"eq.queued");
      if(state!=="queued")return [];
      state="cancelled";
      return [{id:ref.command_id,status:state}];
    },
    lookup:async()=>{throw new Error("should not read after one successful CAS");}
  });
  const claimSucceeded=state==="queued";
  assert.equal(outcome.http_status,200);
  assert.equal(claimSucceeded,false);
  assert.equal(state,"cancelled");
});
test("lost cancellation response is reconciled by ONE read without replaying PATCH",async()=>{
  let state=row("queued"),writes=0,reads=0;
  const patch=async()=>{
    writes++;
    state=row("cancelled",{error:"QUEUED_OWNER_CANCELLED"});
    throw new Error("network dropped after commit");
  };
  const lookup=async()=>{
    reads++;
    return [state];
  };
  const reconciled=await resolveQueuedCancel(ref,owner,device,{patch,lookup});
  assert.equal(reconciled.http_status,200);
  assert.equal(reconciled.body.cancelled,true);
  assert.equal(reconciled.body.already_cancelled,true);
  assert.equal(reconciled.body.execution_outcome,"NOT_STARTED");
  assert.equal(writes,1);
  assert.equal(reads,1);
});
test("lost cancellation response with unavailable reconciliation remains UNKNOWN",async()=>{
  let writes=0,reads=0;
  const unverified=await resolveQueuedCancel(ref,owner,device,{
    patch:async()=>{writes++;throw new Error("timeout");},
    lookup:async()=>{reads++;throw new Error("database unavailable");}
  });
  assert.equal(unverified.http_status,503);
  assert.equal(unverified.body.cancelled,false);
  assert.equal(unverified.body.execution_outcome,"UNKNOWN");
  assert.equal(unverified.body.command_id,ref.command_id);
  assert.equal(unverified.body.retry_same_reference,true);
  assert.equal(writes,1);
  assert.equal(reads,1);
});
test("lost cancellation response with missing row does not claim success",async()=>{
  const r=await resolveQueuedCancel(ref,owner,device,{
    patch:async()=>{throw new Error("network timeout");},
    lookup:async()=>[]
  });
  assert.equal(r.http_status,503);
  assert.equal(r.body.cancelled,false);
  assert.equal(r.body.execution_outcome,"UNKNOWN");
});
test("lost cancellation response after claim returns an explicit non-cancelled receipt",async()=>{
  const r=await resolveQueuedCancel(ref,owner,device,{
    patch:async()=>{throw new Error("response lost");},
    lookup:async()=>[row("claimed")]
  });
  assert.equal(r.http_status,409);
  assert.equal(r.body.cancelled,false);
  assert.equal(r.body.execution_outcome,"UNKNOWN");
});
test("mismatched owner/device and nonce resolve to generic not found with no leaks",async()=>{
  const mismatch=[
    row("claimed",{request:{bound_owner:"different",bound_agent_id:device}}),
    row("cancelled",{nonce:"b".repeat(32),error:"QUEUED_OWNER_CANCELLED"}),
    row("cancelled",{request:{bound_owner:owner,bound_agent_id:"different"},
      error:"QUEUED_OWNER_CANCELLED"})
  ];
  for(const fake of mismatch){
    let count=0;
    const output=await resolveQueuedCancel(ref,owner,device,{
      patch:async()=>{count++;return [];},
      lookup:async()=>{count++;return [fake];}
    });
    assert.equal(count,2);
    assert.equal(output.http_status,404);
    assert.deepEqual(output.body,{ok:false,error:"Command not found"});
    assert.ok(!JSON.stringify(output).includes("NEVER_EXPOSE"));
  }
});
test("ambiguous/malformed PATCH, result read failure and oversized lookup fail closed",async()=>{
  for(const patch of [
    async()=>null,async()=>({}),async()=>[{id:1},{id:2}],
    async()=>[{id:ref.command_id,status:"claimed"}],
    async()=>[{id:ref.command_id+1,status:"cancelled"}]
  ]){
    let reads=0;
    const got=await resolveQueuedCancel(ref,owner,device,{
      patch,lookup:async()=>{reads++;return [row("queued")];}
    });
    assert.equal(got.http_status,503);
    assert.equal(got.body.execution_outcome,"UNKNOWN");
    assert.equal(reads,0);
  }
  const lost=await resolveQueuedCancel(ref,owner,device,{
    patch:async()=>[],lookup:async()=>{throw Error("read failed");}
  });
  assert.equal(lost.http_status,503);
  const ambiguous=await resolveQueuedCancel(ref,owner,device,{
    patch:async()=>[],lookup:async()=>[row("cancelled"),row("claimed")]
  });
  assert.equal(ambiguous.http_status,503);
});
test("invalid original reference causes no database call",async()=>{
  let called=0;
  const outcome=await resolveQueuedCancel({command_id:0,nonce},owner,device,{
    patch:async()=>{called++;return [];},
    lookup:async()=>{called++;return [];}
  });
  assert.equal(called,0);
  assert.equal(outcome.http_status,400);
  assert.equal(outcome.body.ok,false);
});

test("invalid binding rejects before any database access",async()=>{
  let calls=0;
  const adapters={
    patch:async()=>{calls++;return [];},
    lookup:async()=>{calls++;return [];}
  };
  for(const [badOwner,badDevice] of [
    ["",device],[owner,""],[null,device],[owner,null]
  ]){
    const r=await resolveQueuedCancel(ref,badOwner,badDevice,adapters);
    assert.equal(r.http_status,400);
    assert.equal(r.body.ok,false);
  }
  assert.equal(calls,0);
});

test("deterministic 500-case cancellation and claim matrix preserves safety invariants",async()=>{
  const states=["queued","claimed","uploading","completed","failed","needs_review"];
  let successes=0,conflicts=0,uncertain=0;
  for(let i=0;i<500;i++){
    let current=row(states[i%states.length]),writes=0,reads=0;
    const result=await resolveQueuedCancel(ref,owner,device,{
      patch:async filter=>{
        writes++;
        assert.equal(filter.get("status"),"eq.queued");
        assert.equal(filter.get("nonce"),"eq."+nonce);
        if(current.status==="queued"){
          current=row("cancelled",{error:"QUEUED_OWNER_CANCELLED"});
          if(i%7===0)throw new Error("reply lost after commit");
          return [{id:ref.command_id,status:"cancelled"}];
        }
        if(i%13===0)throw new Error("reply lost before commit");
        return [];
      },
      lookup:async()=>{
        reads++;
        if(i%37===0)throw new Error("lookup unavailable");
        return [current];
      }
    });
    assert.equal(writes,1);
    assert.ok(reads<=1);
    assert.ok(!JSON.stringify(result).includes("NEVER_EXPOSE"));
    if(result.body.cancelled){
      successes++;
      assert.equal(current.status,"cancelled");
      assert.equal(result.body.execution_outcome,"NOT_STARTED");
    }else if(result.http_status===409)conflicts++;
    else if(result.http_status===503)uncertain++;
    else assert.fail("Unexpected cancellation state "+result.http_status);
  }
  assert.ok(successes>0 && conflicts>0 && uncertain>0);
});
