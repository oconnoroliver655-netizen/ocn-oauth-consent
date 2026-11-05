import {createHmac, randomBytes} from "node:crypto";

// Process-local secret: prevents raw ChatGPT session/subject identifiers
// from being exposed in MCP results, traces or persistent storage.
const EPHEMERAL_KEY=randomBytes(32);
const own=(obj,key)=>Object.prototype.hasOwnProperty.call(obj,key);
function opaqueId(obj,key){
  if(!obj || typeof obj!=="object" || Array.isArray(obj) || !own(obj,key)) return null;
  const v=obj[key];
  return typeof v==="string" && v.length>=1 && v.length<=512 &&
    v.trim()===v && !/[\u0000-\u001f\u007f]/.test(v) ? v : null;
}

// This is a DIAGNOSTIC, not proof of ChatGPT-host provenance:
// request _meta is client-supplied data and can be imitated by a bearer holder.
// The caller must enforce signed owner OAuth BEFORE using this helper.
export function summarizeSessionContext(meta) {
  const session=opaqueId(meta,"openai/session");
  const subject=opaqueId(meta,"openai/subject");
  const sessionTag=session
    ? createHmac("sha256",EPHEMERAL_KEY)
        .update("ocn-session-context-probe-v1\0")
        .update(subject??"").update("\0").update(session)
        .digest("hex").slice(0,24)
    : null;
  return {
    schema:1,
    session_metadata_present:session!==null,
    subject_metadata_present:subject!==null,
    session_correlation_tag:sessionTag,
    tag_lifetime:"single_server_process",
    client_metadata_is_identity_proof:false,
    conversation_message_source_verified:false,
    model_context_delivery_verified:false,
    mutated_state:false
  };
}
