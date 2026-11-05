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
