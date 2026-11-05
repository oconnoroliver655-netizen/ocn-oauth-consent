import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {once} from "node:events";
import {summarizeSessionContext} from "../canary/mcp/session-context-probe.mjs";

const session="opaque-session-test-01";
const subject="opaque-subject-test-01";

test("missing metadata fails closed without identity tag",()=>{
  for(const value of [undefined,null,[],42,{}]){
    const x=summarizeSessionContext(value);
    assert.equal(x.session_metadata_present,false);
    assert.equal(x.session_correlation_tag,null);
    assert.equal(x.client_metadata_is_identity_proof,false);
    assert.equal(x.model_context_delivery_verified,false);
    assert.equal(x.mutated_state,false);
  }
});

test("valid metadata yields stable process-scoped nonreversible tag",()=>{
  const meta={"openai/session":session,"openai/subject":subject};
  const a=summarizeSessionContext(meta);
  const b=summarizeSessionContext(meta);
  assert.equal(a.session_correlation_tag,b.session_correlation_tag);
  assert.match(a.session_correlation_tag,/^[a-f0-9]{24}$/);
  assert.equal(a.session_metadata_present,true);
  assert.equal(a.subject_metadata_present,true);
  assert.equal(a.client_metadata_is_identity_proof,false);
  assert.equal(a.conversation_message_source_verified,false);
  assert.ok(!JSON.stringify(a).includes(session));
  assert.ok(!JSON.stringify(a).includes(subject));
});

test("different sessions or subject tags never collapse",()=>{
  const a=summarizeSessionContext({"openai/session":session,"openai/subject":subject});
  const b=summarizeSessionContext({"openai/session":session+"-other","openai/subject":subject});
  const c=summarizeSessionContext({"openai/session":session,"openai/subject":subject+"-other"});
  assert.notEqual(a.session_correlation_tag,b.session_correlation_tag);
  assert.notEqual(a.session_correlation_tag,c.session_correlation_tag);
});

test("only own bounded printable string metadata is accepted",()=>{
  for(const v of [""," spaced ","bad\nline", "a".repeat(513),{},true,0]){
    const p=summarizeSessionContext({"openai/session":v});
    assert.equal(p.session_metadata_present,false);
    assert.equal(p.session_correlation_tag,null);
  }
  const inherited=Object.create({"openai/session":session});
  assert.equal(summarizeSessionContext(inherited).session_metadata_present,false);
});

// Isolated HTTP integration. Supabase owner validator is explicitly stubbed:
// passing here DOES NOT prove live provider-origin metadata or live OAuth.
test("owner OAuth gates the diagnostic and tool args cannot spoof metadata",async()=>{
  const oldOrigin=process.env.OCN_PUBLIC_ORIGIN;
  process.env.OCN_PUBLIC_ORIGIN="https://ocn-mcp-ping-canary.onrender.com";
  const oldFetch=globalThis.fetch;
  let count=0;
  globalThis.fetch=async(url)=>{
    if(String(url).endsWith("/ocn-oauth-validator")){
      count++;
      return {status:200,json:async()=>({ok:true,owner_verified:true,machine_control:false})};
    }
    throw new Error("Unexpected external network call in isolated test");
  };
  const {start}=await import("../canary/mcp/server.mjs");
  const srv=start(0);
  try{
    await once(srv,"listening");
    const port=srv.address().port;
    async function call(name,meta,bearer,path="/mcp-oauth",args={}){
      const body=JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",
        params:{name,arguments:args,_meta:meta}});
      return new Promise((resolve,reject)=>{
        const req=http.request({hostname:"127.0.0.1",port,path,method:"POST",
          headers:{host:"ocn-mcp-ping-canary.onrender.com",
            "content-type":"application/json",
            accept:"application/json, text/event-stream",
            ...(bearer?{authorization:bearer}:{})}},res=>{
            let raw="";res.setEncoding("utf8");res.on("data",x=>raw+=x);
            res.on("end",()=>resolve({status:res.statusCode,data:JSON.parse(raw)}));
          });
        req.on("error",reject);req.end(body);
      });
    }
    const metadata={"openai/session":session,"openai/subject":subject};
    const denied=await call("session_context_probe",metadata,null);
    assert.equal(denied.data.result.isError,true);
    assert.ok(!JSON.stringify(denied).includes(session));
    assert.equal(count,0);
    const accepted=await call("session_context_probe",metadata,"Bearer isolated-fixture");
    assert.equal(accepted.data.result.isError,false);
    assert.equal(accepted.data.result.structuredContent.owner_oauth_verified,true);
    assert.equal(accepted.data.result.structuredContent.session_metadata_present,true);
    assert.equal(accepted.data.result.structuredContent.client_metadata_is_identity_proof,false);
    assert.ok(!JSON.stringify(accepted).includes(session));
    assert.ok(!JSON.stringify(accepted).includes(subject));
    const again=await call("session_context_probe",metadata,"Bearer isolated-fixture");
    assert.equal(accepted.data.result.structuredContent.session_correlation_tag,
      again.data.result.structuredContent.session_correlation_tag);
    const spoof=await call("session_context_probe",undefined,"Bearer isolated-fixture",
      "/mcp-oauth",{"openai/session":session});
    assert.equal(spoof.data.result.isError,true);
    const publicRoute=await call("session_context_probe",metadata,"Bearer isolated-fixture","/mcp");
    assert.equal(publicRoute.data.result.isError,true);
    assert.equal(count,2);
  }finally{
    await new Promise(resolve=>srv.close(resolve));
    globalThis.fetch=oldFetch;
    if(oldOrigin===undefined)delete process.env.OCN_PUBLIC_ORIGIN;
    else process.env.OCN_PUBLIC_ORIGIN=oldOrigin;
  }
});
