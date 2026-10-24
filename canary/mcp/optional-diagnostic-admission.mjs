// Optional-only diagnostic admission. This is NOT a replacement for the
// owner-authorized Windows submit/poll tools or emergency recovery.
const OPTIONAL_OPERATIONS = Object.freeze([
  "desktop_health","process_sessions","terminal_sessions","desktop_lease_status"
]);
const OPERATIONS = new Set(OPTIONAL_OPERATIONS);
export const OPTIONAL_DIAGNOSTIC_TOOL = Object.freeze({
  name:"submit_optional_diagnostic",
  description:"Queue one optional, read-only Windows status diagnostic only if the signed owner/device-specific cloud queue has spare capacity. Busy/unknown pressure returns a deferred receipt WITHOUT adding a Windows command. Does not block the existing owner-authorized Windows tools or emergency recovery.",
  inputSchema:{
    type:"object",
    properties:{operation:{type:"string",enum:OPTIONAL_OPERATIONS}},
    required:["operation"],additionalProperties:false
  },
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false}
});
export function validOptionalDiagnosticCall(args) {
  return !!args && typeof args==="object" && !Array.isArray(args) &&
    Object.keys(args).length===1 && typeof args.operation==="string" &&
    OPERATIONS.has(args.operation);
}
export function prepareOptionalDiagnostic(args) {
  if(!validOptionalDiagnosticCall(args))
    throw new TypeError("INVALID_OPTIONAL_DIAGNOSTIC");
  return {operation:args.operation,payload:{}};
}
// A non-atomic admission hint: only **this separate optional path** observes it.
// An unrelated producer may enqueue after this preflight; no exactly-once or
// latency improvement may be inferred from admission being granted.
export function planOptionalDiagnosticAdmission(telemetry) {
  if(!telemetry || telemetry.ok!==true || telemetry.mutated_state!==false ||
     telemetry.active_queue_complete!==true ||
     typeof telemetry.reason!=="string" || telemetry.reason.length>80 ||
     typeof telemetry.advisory_admit_nonessential_diagnostics!=="boolean") {
    return {admitted:false,reason:"TELEMETRY_UNAVAILABLE_OR_INCOMPLETE"};
  }
  if(telemetry.reason!=="NO_CURRENT_QUEUE_PRESSURE" ||
     telemetry.advisory_admit_nonessential_diagnostics!==true) {
    return {admitted:false,reason:telemetry.reason};
  }
  return {admitted:true,reason:"NO_CURRENT_QUEUE_PRESSURE"};
}
