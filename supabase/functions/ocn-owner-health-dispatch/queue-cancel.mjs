// Atomic owner/device-bound cancellation guard for the existing OCN command queue.
// A queued command is cancellable only before the Agent's conditional claim PATCH.
// These helpers are pure; caller MUST validate signed owner OAuth first.
const NONCE=/^[0-9a-f]{32}$/;
const OPERATION=/^[a-z][a-z0-9_]{0,79}$/;
const STATES=new Set(["queued","claimed","uploading","completed","failed",
                      "cancelled","expired","needs_review"]);

export function validCancelReference(commandId,nonce) {
  return Number.isSafeInteger(commandId) && commandId>0 &&
    typeof nonce==="string" && NONCE.test(nonce);
}

export function cancelDecision(row,{commandId,nonce,owner,device}) {
  if(!validCancelReference(commandId,nonce) || !row ||
     row.id!==commandId || row.nonce!==nonce || row.kind!=="local_commander")
    return {kind:"not_found"};
  const request=row.request;
  if(!request || typeof request!=="object" || Array.isArray(request) ||
     request.bound_owner!==owner || request.bound_agent_id!==device ||
     typeof request.operation!=="string" || !OPERATION.test(request.operation))
    return {kind:"not_found"};
  if(row.status==="cancelled") {
    const result=row.result;
    if(row.claimed_by==null && row.claim_request_id==null &&
       result?.state==="CANCELLED" && result?.operation===request.operation &&
       result?.detail?.cancelled_before_claim===true &&
       result?.detail?.dispatch_prevented===true)
      return {kind:"already_cancelled",operation:request.operation,status:"cancelled"};
    return {kind:"unverified_cancelled",status:"cancelled"};
  }
  if(row.status==="queued" && row.claimed_by==null && row.claim_request_id==null)
    return {kind:"eligible",operation:request.operation,status:"queued"};
  return {kind:"too_late",status:STATES.has(row.status)?row.status:"unknown"};
}

export function queuedCancelPredicate({commandId,nonce,owner,device,operation}) {
  if(!validCancelReference(commandId,nonce) ||
     typeof owner!=="string" || !owner ||
     typeof device!=="string" || !device ||
     typeof operation!=="string" || !OPERATION.test(operation))
    throw new TypeError("Invalid bounded cancellation identity");
  // The status predicate races atomically against Agent's own status=queued
  // conditional PATCH; both cannot commit on the same row.
  return new URLSearchParams({
    select:"id,nonce,kind,status,request,result,claimed_by,claim_request_id",
    id:"eq."+commandId,nonce:"eq."+nonce,status:"eq.queued",
    claimed_by:"is.null",claim_request_id:"is.null",
    "request->>bound_owner":"eq."+owner,
    "request->>bound_agent_id":"eq."+device,
    "request->>operation":"eq."+operation,
  });
}
