// Pure validators and state classification for owner-scoped queued cancellation.
// The Edge handler applies the returned filters in ONE conditional PATCH.
// Never requeue, revoke, or claim an already claimed/running operation.
const NONCE=/^[a-f0-9]{32}$/;
const FINAL_STATES=new Set(["claimed","uploading","completed","failed",
  "cancelled","expired","needs_review"]);
export function validCancelReference(input){
  return input && typeof input==="object" && !Array.isArray(input) &&
    Object.keys(input).length===2 && Object.hasOwn(input,"command_id") &&
    Object.hasOwn(input,"nonce") &&
    Number.isSafeInteger(input.command_id) && input.command_id>0 &&
    typeof input.nonce==="string" && NONCE.test(input.nonce);
}
export function queuedCancelFilter(input,owner,device){
  if(!validCancelReference(input)||typeof owner!=="string"||!owner||
    typeof device!=="string"||!device)
    throw new TypeError("Invalid cancel reference or binding");
  // All conditions participate in a single compare-and-swap UPDATE.
  return new URLSearchParams({
    select:"id,status",
    id:"eq."+input.command_id,nonce:"eq."+input.nonce,
    kind:"eq.local_commander",status:"eq.queued",
    "request->>bound_owner":"eq."+owner,
    "request->>bound_agent_id":"eq."+device
  });
}
export function classifyCancelAfterRace(row,input,owner,device){
  if(!validCancelReference(input)||!row ||typeof row!=="object"||
     row.id!==input.command_id||row.nonce!==input.nonce||
     row.kind!=="local_commander"||
     row.request?.bound_owner!==owner||
     row.request?.bound_agent_id!==device||
     typeof row.status!=="string")return null;
  if(row.status==="cancelled"&&row.error==="QUEUED_OWNER_CANCELLED")
    return {ok:true,command_id:input.command_id,status:"cancelled",
      cancelled:true,already_cancelled:true,
      cancellation_scope:"queued_only",execution_outcome:"NOT_STARTED"};
  if(row.status==="queued"||FINAL_STATES.has(row.status))
    return {ok:false,command_id:input.command_id,status:row.status,
      cancelled:false,error:row.status==="queued"?"CANCEL_RACE_UNRESOLVED":"CANCEL_TOO_LATE",
      execution_outcome:row.status==="claimed"||row.status==="uploading"||
        row.status==="needs_review"?"UNKNOWN":"NOT_CANCELLED",
      review_required:row.status==="needs_review",
      retry_same_reference:row.status==="queued"};
  return null;
}


// Explicit, testable cancellation protocol. Network adapters are injected by
// the Edge handler; neither the decision function nor its tests access SQL.
// A returned UNKNOWN is not proof the cancellation did or did not commit.
export async function resolveQueuedCancel(input,owner,device,{patch,lookup}={}){
  if(!validCancelReference(input))
    return {http_status:400,body:{ok:false,error:"Invalid command reference"}};
  if(typeof patch!=="function"||typeof lookup!=="function")
    throw new TypeError("Cancellation adapters must be provided");
  const uncertain=(reason)=>({http_status:503,body:{
    ok:false,command_id:input.command_id,cancelled:false,
    error:reason,execution_outcome:"UNKNOWN",retry_same_reference:true
  }});
  let updated,patchUncertain=false;
  try{
    updated=await patch(queuedCancelFilter(input,owner,device));
  }catch{
    // The CAS may have committed before the HTTP response was lost.
    // Resolve its actual state with one *read*, never a blind second write.
    patchUncertain=true;
  }
  if(!patchUncertain && (!Array.isArray(updated)||updated.length>1))
    return uncertain("Cancellation receipt unavailable");
  if(!patchUncertain && updated.length===1){
    if(updated[0].id!==input.command_id||updated[0].status!=="cancelled")
      return uncertain("Invalid cancellation receipt");
    return {http_status:200,body:{
      ok:true,command_id:input.command_id,status:"cancelled",
      cancelled:true,already_cancelled:false,cancellation_scope:"queued_only",
      execution_outcome:"NOT_STARTED"
    }};
  }
  // Lost atomic race, duplicate request, or missing PATCH response: read the
  // exact original row once. NEVER repeat the underlying Windows task or CAS.
  let rows;
  try{rows=await lookup(input);}catch{
    return uncertain("Cancellation reconciliation unavailable");
  }
  if(!Array.isArray(rows)||rows.length>1)
    return uncertain("Cancellation reconciliation unavailable");
  if(rows.length===0){
    // Following a transport failure, absence cannot prove what happened.
    return patchUncertain ? uncertain("Cancellation reference unverified") :
      {http_status:404,body:{ok:false,error:"Command not found"}};
  }
  const classified=classifyCancelAfterRace(rows[0],input,owner,device);
  if(!classified)return {http_status:404,body:{
    ok:false,error:"Command not found"}};
  return {http_status:classified.ok?200:409,body:classified};
}
