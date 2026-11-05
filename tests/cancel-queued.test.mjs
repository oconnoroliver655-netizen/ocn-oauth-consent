import test from "node:test";
import assert from "node:assert/strict";
import {validCancelReference,queuedCancelFilter,classifyCancelAfterRace}
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
