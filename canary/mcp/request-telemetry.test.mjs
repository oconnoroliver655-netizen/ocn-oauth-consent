import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {createRequestTelemetry} from "./request-telemetry.mjs";

function fakeResponse(statusCode=200) {
  const res = new EventEmitter();
  res.statusCode = statusCode;
  res.writableFinished = false;
  return res;
}

test("records method, status, duration and safe route but no secrets",() => {
  const lines=[];
  let now=1000;
  const observe=createRequestTelemetry({clock:()=>now,write:x=>lines.push(x)});
  const res=fakeResponse(403);
  observe({method:"POST",url:"/mcp-oauth?access_token=hidden",headers:{
    authorization:"Bearer private-token",cookie:"sid=hidden","rndr-id":"a1b2c3d4-1111-2222-3333-444455556666"
  }},res);
  now=1023;
  res.writableFinished=true;
  res.emit("finish");
  res.emit("close");
  assert.equal(lines.length,1);
  const event=JSON.parse(lines[0]);
  assert.equal(event.event,"ocn_http_request");
  assert.equal(event.route,"mcp-oauth");
  assert.equal(event.method,"POST");
  assert.equal(event.status_code,403);
  assert.equal(event.duration_ms,23);
  assert.equal(event.completion,"finished");
  assert.equal(event.render_request_id,"a1b2c3d4-1111-2222-3333-444455556666");
  assert.match(event.trace_id,/^[a-f0-9-]{36}$/);
  assert.doesNotMatch(lines[0],/access_token|private-token|hidden|authorization|cookie/i);
});

test("unrecognized paths, methods and request IDs cannot enter logs",() => {
  const lines=[];
  const observe=createRequestTelemetry({write:x=>lines.push(x)});
  const res=fakeResponse(404);
  observe({method:"EVIL\nTOKEN",url:"/private/secret?x=y",headers:{"rndr-id":"evil\nlog"}},res);
  res.emit("finish");
  const entry=JSON.parse(lines[0]);
  assert.equal(entry.route,"other");
  assert.equal(entry.method,"OTHER");
  assert.equal(entry.render_request_id,null);
  assert.doesNotMatch(lines[0],/private|secret|EVIL|TOKEN/);
});

test("aborted requests log once, without misreporting completion",() => {
  const lines=[];
  const observe=createRequestTelemetry({write:x=>lines.push(x)});
  const res=fakeResponse(200);
  observe({method:"GET",url:"/healthz",headers:{}},res);
  res.emit("close");
  res.emit("finish");
  assert.equal(lines.length,1);
  assert.equal(JSON.parse(lines[0]).completion,"aborted");
});

test("rate cap provides aggregate suppression count in next minute",() => {
  const lines=[];
  let now=0;
  const observe=createRequestTelemetry({clock:()=>now,write:x=>lines.push(JSON.parse(x)),limitPerMinute:1});
  for (let i=0;i<3;i++) {
    const res=fakeResponse(200);
    observe({method:"GET",url:"/healthz",headers:{}},res);
    res.emit("finish");
  }
  now=61_000;
  const res=fakeResponse(500);
  observe({method:"GET",url:"/healthz",headers:{}},res);
  res.emit("finish");
  assert.deepEqual(lines.map(x=>x.event),["ocn_http_request","ocn_http_log_suppressed","ocn_http_request"]);
  assert.equal(lines[1].count,2);
  assert.equal(lines[2].status_code,500);
});

test("telemetry writer exceptions never affect HTTP completion",() => {
  const observe=createRequestTelemetry({write:()=>{throw new Error("log backend failed")}});
  const res=fakeResponse(200);
  observe({method:"GET",url:"/healthz",headers:{}},res);
  assert.doesNotThrow(()=>res.emit("finish"));
});
