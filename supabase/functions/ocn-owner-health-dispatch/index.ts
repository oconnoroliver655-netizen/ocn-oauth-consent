// Owner OAuth dispatch; do not truncate application message content.
// The public caller never receives a service_role credential and cannot select
// an arbitrary Windows operation, host, device, owner, path or credential.
// Authentication is delegated to the already-live strict ES256 OAuth validator,
// which checks signed issuer/client/resource + active consent/session per call.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import {BROWSER_OPERATIONS, validBrowserPayload} from "./browser-operation-policy.mjs";
import {classifyQueuePressure} from "./queue-pressure.mjs";

const SUPABASE = "https://ouxniljtjxnrkwakkvbv.supabase.co";
const VALIDATOR = SUPABASE + "/functions/v1/ocn-oauth-validator";
const OWNER = "12509085-8869-4258-83f6-3afd6c53cec3";
const DEVICE = "DESKTOP-3I4OTFT-local-control";
const KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
const NONCE = /^[0-9a-f]{32}$/;
const STATE = new Set(["queued","claimed","completed","failed","cancelled","expired"]);

function response(status: number, body: object): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type":"application/json; charset=utf-8",
      "cache-control":"no-store",
      "x-content-type-options":"nosniff",
      "content-security-policy":"default-src 'none'",
    },
  });
}

async function authenticated(header: string): Promise<boolean> {
  if (!header.startsWith("Bearer ") || header.length > 8200 ||
      header.slice(7).includes(" ")) return false;
  try {
    const r = await fetch(VALIDATOR, {
      method:"POST",
      headers:{"authorization":header,"content-type":"application/json"},
      body:JSON.stringify({action:"owner_auth_probe"}),
      signal:AbortSignal.timeout(7000),
    });
    if (r.status !== 200) return false;
    const obj = await r.json();
    return obj && obj.ok === true && obj.owner_verified === true &&
      obj.machine_control === false;
  } catch {
    return false;
  }
}

function serverHeaders(prefer?: string): Record<string,string> {
  const h:Record<string,string> = {
    "apikey":KEY, "authorization":"Bearer " + KEY,
    "content-type":"application/json", "accept":"application/json",
  };
  if (prefer) h.prefer = prefer;
  return h;
}

async function getRows(query: URLSearchParams): Promise<any[]|null> {
  const url = SUPABASE + "/rest/v1/local_control_commands?" + query.toString();
  const r = await fetch(url,{
    method:"GET",headers:serverHeaders(),signal:AbortSignal.timeout(6000),
  });
  if (!r.ok) return null;
  const body = await r.json();
  return Array.isArray(body) ? body : null;
}

async function queuePressureStatus(): Promise<Response> {
  // Authenticated upstream; bounded, device-scoped, metadata-only queries.
  // This action does NOT insert, claim, expire, or complete any queue item.
  const filters = new URLSearchParams({
    select:"status,created_at,claimed_at,expires_at",
    status:"in.(queued,claimed,running)", order:"created_at.asc", limit:"2001"
  });
  const agentQuery = new URLSearchParams({
    select:"last_seen_at,state", agent_id:"eq."+DEVICE,
    order:"last_seen_at.desc", limit:"1"
  });
  const agentUrl = SUPABASE + "/rest/v1/local_control_agents?" + agentQuery.toString();
  const [active, agentRes] = await Promise.all([
    getRows(filters),
    fetch(agentUrl, {method:"GET",headers:serverHeaders(),
      signal:AbortSignal.timeout(6000)})
  ]);
  if (active === null || !agentRes.ok)
    return response(503,{ok:false,error:"Queue telemetry unavailable"});
  const agents = await agentRes.json().catch(()=>null);
  if (!Array.isArray(agents))
    return response(503,{ok:false,error:"Queue telemetry unavailable"});
  const result = classifyQueuePressure({
    observedAt:new Date().toISOString(), agents,
    commands:active.slice(0,2000),
    complete:active.length <= 2000
  });
  if (!result.ok) return response(503,{ok:false,error:"Queue telemetry invalid"});
  return response(200,result);
}

async function dispatchHealth(): Promise<Response> {
  // Bound list check suppresses accidental rapid duplicate probes. This is
  // a throttling hint, not a security/identity decision (both are server-side).
  const recent = new Date(Date.now()-15000).toISOString();
  const filter = new URLSearchParams({
    select:"id", created_at:"gte."+recent,
    "request->>bound_owner":"eq."+OWNER,
    "request->>bound_agent_id":"eq."+DEVICE,
    "request->>operation":"eq.health", limit:"1",
  });
  const existing = await getRows(filter);
  if (existing === null) return response(503,{ok:false,error:"Queue not available"});
  if (existing.length > 0) return response(429,{ok:false,error:"Health probe throttled"});

  const nonce = crypto.randomUUID().replace(/-/g,"");
  const expires = new Date(Date.now()+90000).toISOString();
  const request = {operation:"health",payload:{},bound_owner:OWNER,bound_agent_id:DEVICE};
  const r = await fetch(SUPABASE + "/rest/v1/local_control_commands?select=id",{
    method:"POST",headers:serverHeaders("return=representation"),
    body:JSON.stringify({nonce,kind:"local_commander",request,expires_at:expires}),
    signal:AbortSignal.timeout(6000),
  });
  if (!r.ok) return response(503,{ok:false,error:"Queue insert unavailable"});
  const rows = await r.json().catch(()=>null);
  const id = Array.isArray(rows) && rows.length===1 ? rows[0]?.id : null;
  if (!Number.isSafeInteger(id) || id<1) return response(503,{ok:false,error:"Queue receipt invalid"});
  return response(202,{ok:true,command_id:id,nonce,status:"queued"});
}

async function pollHealth(input:any): Promise<Response> {
  const id = input.command_id, nonce = input.nonce;
  if (!Number.isSafeInteger(id) || id<1 ||
      typeof nonce !== "string" || !NONCE.test(nonce)) {
    return response(400,{ok:false,error:"Invalid job reference"});
  }
  const filter = new URLSearchParams({
    select:"id,nonce,kind,request,status,expires_at,result",
    id:"eq."+id,nonce:"eq."+nonce,limit:"1",
  });
  const rows = await getRows(filter);
  if (!rows) return response(503,{ok:false,error:"Queue status unavailable"});
  if (rows.length !== 1) return response(404,{ok:false,error:"Job not found"});
  const row = rows[0];
  const q = row.request;
  const t = Date.parse(row.expires_at);
  if (row.id !== id || row.nonce !== nonce || row.kind !== "local_commander" ||
      !q || typeof q !== "object" || q.operation !== "health" ||
      !q.payload || Object.keys(q.payload).length !== 0 ||
      q.bound_owner !== OWNER || q.bound_agent_id !== DEVICE ||
      !Number.isFinite(t) || t <= Date.now() ||
      !STATE.has(row.status)) {
    return response(404,{ok:false,error:"Job not found"});
  }
  const status = row.status;
  const result = status === "completed" ? row.result : null;
  const ready = status === "completed" && result?.state === "SUCCEEDED" &&
    result?.operation === "health" && typeof result?.detail === "object" &&
    result.detail !== null && result.detail.health !== null &&
    typeof result.detail.health === "object";
  return response(200,{ok:true,command_id:id,status,ready});
}


/* Owner-authorized Windows operations use the EXISTING bound agent and queue.
   Each request is independently verified by the same signed OAuth validator
   used for health probes. No secret ever enters client responses. */
const WINDOWS_OPS = new Set([
  "file_read","file_read_lines","file_write","file_append",
  "powershell","exec","desktop_health","window_list","screenshot",
  "uia_tree","code_search","audit_recent","process_sessions",
  "terminal_sessions","desktop_lease_status",
  ...BROWSER_OPERATIONS
]);
const TERMINAL = new Set(["completed","failed","cancelled","expired"]);
function validWindowsPayload(operation:string, payload:any):boolean {
  if (!WINDOWS_OPS.has(operation) || !payload || typeof payload!=="object" ||
      Array.isArray(payload)) return false;
  const keys=Object.keys(payload);
  if(operation.startsWith("browser_"))return validBrowserPayload(operation,payload);
  if(operation.startsWith("file_") &&
    (typeof payload.path!=="string" || payload.path.length<3 ||
      !/^[a-zA-Z]:/.test(payload.path) ||
      ![92,47].includes(payload.path.charCodeAt(2)))) return false;
  if(operation==="powershell" &&
    (typeof payload.script!=="string" || payload.script.length<1))
    return false;
  if(operation==="exec" &&
    (!Array.isArray(payload.argv) || payload.argv.length<1 ||
      payload.argv.some((a:any)=>typeof a!=="string")))return false;
  if(["desktop_health","desktop_lease_status","process_sessions","terminal_sessions"].includes(operation)
    && keys.length>0)return false;
  return true;
}
async function submitWindows(input:any):Promise<Response> {
  const op=input.operation, payload=input.payload;
  if(!validWindowsPayload(op,payload))return response(400,{ok:false,error:"Unsupported operation or invalid payload"});
  const nonce=crypto.randomUUID().replace(/-/g,"");
  const expires=new Date(Date.now()+600000).toISOString();
  const request={operation:op,payload,bound_owner:OWNER,bound_agent_id:DEVICE};
  const r=await fetch(SUPABASE+"/rest/v1/local_control_commands?select=id",{
    method:"POST",headers:serverHeaders("return=representation"),
    body:JSON.stringify({nonce,kind:"local_commander",request,expires_at:expires}),
    signal:AbortSignal.timeout(7000)
  });
  if(!r.ok)return response(503,{ok:false,error:"Windows operation queue unavailable"});
  const rows=await r.json().catch(()=>null);
  const id=Array.isArray(rows)&&rows.length===1?rows[0]?.id:null;
  if(!Number.isSafeInteger(id)||id<1)return response(503,{ok:false,error:"Invalid queue receipt"});
  return response(202,{ok:true,command_id:id,nonce,status:"queued",operation:op});
}
async function pollWindows(input:any):Promise<Response>{
  const id=input.command_id,nonce=input.nonce;
  if(!Number.isSafeInteger(id)||id<1||typeof nonce!=="string"||!NONCE.test(nonce))
    return response(400,{ok:false,error:"Invalid command reference"});
  const q=new URLSearchParams({select:"id,nonce,kind,request,status,expires_at,result,error",
    id:"eq."+id,nonce:"eq."+nonce,limit:"1"});
  const rows=await getRows(q);
  if(!rows)return response(503,{ok:false,error:"Queue status unavailable"});
  if(rows.length!==1)return response(404,{ok:false,error:"Command not found"});
  const row=rows[0],req=row.request,exp=Date.parse(row.expires_at);
  if(row.id!==id||row.nonce!==nonce||row.kind!=="local_commander" ||
     !req||typeof req!=="object"||!validWindowsPayload(req.operation,req.payload) ||
     req.bound_owner!==OWNER||req.bound_agent_id!==DEVICE||
     !Number.isFinite(exp)||exp<Date.now()-86400000||!STATE.has(row.status))
    return response(404,{ok:false,error:"Command not found"});
  const data:any={ok:true,command_id:id,operation:req.operation,status:row.status};
  if(TERMINAL.has(row.status)){
    const result=row.result;
    if(result?.operation!==req.operation||typeof result?.state!=="string")
      return response(200,{...data,result_available:false});
    data.execution_state=result.state;
    // Complete result: platform or client may impose separate transport ceilings.
    const detail=result.detail && typeof result.detail==="object" ? result.detail:{};
    data.detail=detail;
    if(row.status==="failed")data.error="Windows operation failed";
  }
  return response(200,data);
}

Deno.serve(async (req:Request):Promise<Response> => {
  if (req.method === "GET" && new URL(req.url).pathname.endsWith("/healthz")) {
    return response(200,{online:true,owner_authenticated:false,files_enabled:false,
      shell_enabled:false,desktop_enabled:false});
  }
  if (req.method !== "POST") return response(405,{ok:false,error:"POST only"});
  if (req.headers.get("content-type")?.split(";")[0].trim() !== "application/json")
    return response(415,{ok:false,error:"JSON required"});
  if (!KEY || KEY.length < 32) return response(503,{ok:false,error:"Private queue unavailable"});
  // Authenticate before parsing the body, especially for large requests.
  if (!(await authenticated(req.headers.get("authorization") || "")))
    return response(401,{ok:false,error:"Owner OAuth authentication required"});
  let input:any;
  try {
    const raw = await req.text();
    input = JSON.parse(raw);
  } catch {
    return response(400,{ok:false,error:"Invalid JSON"});
  }
  if (!input || typeof input !== "object" || Array.isArray(input))
    return response(400,{ok:false,error:"Invalid request"});
  const action = input.action, keys = Object.keys(input).sort().join(",");
  if (!(action === "submit_machine_health" && keys === "action" ||
        action === "poll_machine_health" && keys === "action,command_id,nonce" ||
        action === "submit_windows_operation" && keys === "action,operation,payload" ||
        action === "poll_windows_operation" && keys === "action,command_id,nonce" ||
        action === "queue_pressure_status" && keys === "action"))
    return response(400,{ok:false,error:"Unsupported operation"});

  try {
    if(action==="queue_pressure_status")return await queuePressureStatus();
    if(action==="submit_windows_operation")return await submitWindows(input);
    if(action==="poll_windows_operation")return await pollWindows(input);
    return action === "submit_machine_health" ?
      await dispatchHealth() : await pollHealth(input);
  } catch {
    // Never relay SQL diagnostics or raw database/agent results to the client.
    return response(503,{ok:false,error:"Diagnostic unavailable"});
  }
});
