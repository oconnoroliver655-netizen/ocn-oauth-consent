import {test} from "node:test";
import assert from "node:assert/strict";
import {THREADS_TOOLS,validThreadsCall,parseThreadsUrl,createThreadsClient,callThreadsTool} from "./threads-tools.mjs";

const ids=()=>({media_id:"1234567890"});
test("18 distinct owner-OAuth tools with safely disabled writes",()=>{
  assert.equal(THREADS_TOOLS.length,18);
  assert.equal(new Set(THREADS_TOOLS.map(t=>t.name)).size,18);
  for(const t of THREADS_TOOLS)assert.deepEqual(t.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(THREADS_TOOLS.find(t=>t.name==="threads_delete_post").annotations.destructiveHint,true);
});
test("strict validation forbids arbitrary URLs, commands and unconfirmed mutations",()=>{
  assert.equal(validThreadsCall("threads_read_post",ids()),true);
  assert.equal(validThreadsCall("threads_read_post",{media_id:"../secrets"}),false);
  assert.equal(validThreadsCall("threads_read_post",{...ids(),file:"/etc/passwd"}),false);
  assert.equal(validThreadsCall("threads_publish_text",{text:"Hello",confirm:true}),true);
  assert.equal(validThreadsCall("threads_publish_text",{text:"Hello"}),false);
  assert.equal(validThreadsCall("threads_publish_text",{text:"Hello",confirm:false}),false);
  assert.equal(validThreadsCall("threads_delete_post",{...ids(),confirm:false}),false);
  assert.equal(validThreadsCall("threads_publish_image",{image_url:"http://localhost/1.jpg",confirm:true}),false);
  assert.equal(validThreadsCall("threads_publish_image",{image_url:"https://127.0.0.1/1.jpg",confirm:true}),false);
  assert.equal(validThreadsCall("threads_publish_image",{image_url:"https://public.example/image.jpg",confirm:true}),true);
});
test("allowlisted share links only",()=>{
  assert.deepEqual(parseThreadsUrl("https://www.threads.com/share/BAV1ll6uqR/"),
    {kind:"share",url:"https://www.threads.com/share/BAV1ll6uqR/"});
  assert.equal(parseThreadsUrl("https://evil.example/share/BAV1ll6uqR/"),null);
  assert.equal(parseThreadsUrl("https://www.threads.com.evil.example/share/xXxX"),null);
  assert.equal(parseThreadsUrl("http://threads.com/share/xXxX"),null);
  assert.equal(parseThreadsUrl("https://threads.com@evil.example/share/xXxX"),null);
});
test("unconfigured read and write fail closed",async()=>{
  const env={};
  assert.deepEqual(await callThreadsTool("threads_connection_status",{}, {env}),
    {module:"threads",owner_oauth_verified:true,meta_connected:false,writes_enabled:false,provider:"Meta official Threads Graph API"});
  await assert.rejects(callThreadsTool("threads_my_posts",{}, {env}),/THREADS_NOT_CONFIGURED/);
  await assert.rejects(callThreadsTool("threads_publish_text",{text:"ok",confirm:true}, {env}),/THREADS_WRITES_DISABLED/);
});
test("Meta bearer never appears in URL or tool result",async()=>{
  let request;
  const fetcher=async(u,opts)=>{request={u,opts};return {ok:true,headers:{get:()=>null},text:async()=>JSON.stringify({data:[{id:"1"}]})};};
  const out=await callThreadsTool("threads_search_posts",{query:"hello",recent:true,limit:5},
    {env:{OCN_THREADS_ACCESS_TOKEN:"super-sensitive-token"},fetcher});
  assert.equal(out.data[0].id,"1");
  assert.equal(request.opts.headers.authorization,"Bearer super-sensitive-token");
  assert.equal(request.u.includes("super-sensitive-token"),false);
  assert.match(request.u,/\/keyword_search\?/);
});
test("official Graph failures do not echo upstream token-containing messages",async()=>{
  const fetcher=async()=>({ok:false,status:403,headers:{get:()=>null},
    text:async()=>JSON.stringify({error:{message:"token secret-token",code:190}})});
  const c=createThreadsClient({token:"secret-token",fetcher});
  await assert.rejects(c.graph("GET","/me",{}),e=>e.message==="THREADS_API_ERROR 403 code=190");
});
test("publish waits for container finished, publishes once and never retries ambiguous requests",async()=>{
  const calls=[],states=["IN_PROGRESS","FINISHED"];
  const fetcher=async(u,opts)=>{
    const url=new URL(u),path=url.pathname;
    calls.push({path,method:opts.method});
    const data=path.endsWith("/me/threads")?{id:"731"}:
      path.endsWith("/731")?{status:states.shift()}:{id:"998"};
    return {ok:true,headers:{get:()=>null},text:async()=>JSON.stringify(data)};
  };
  let slept=0;
  const out=await callThreadsTool("threads_publish_text",{text:"confirmed",confirm:true},
    {env:{OCN_THREADS_ACCESS_TOKEN:"token",OCN_THREADS_WRITES_ENABLED:"true"},fetcher,sleep:async()=>{slept++;}});
  assert.deepEqual(out,{container_id:"731",post:{id:"998"}});
  assert.equal(slept,1);
  assert.equal(calls.filter(c=>c.path.endsWith("/me/threads_publish")).length,1);
});
test("redirect resolution rejects non-Threads locations",async()=>{
  let calls=0;
  const fetcher=async()=>{calls++;return {status:302,headers:{get:()=>"https://127.0.0.1/private"}};};
  const value=await callThreadsTool("threads_read_shared_url",{url:"https://www.threads.com/share/BAV1ll6uqR/"},
    {env:{OCN_THREADS_ACCESS_TOKEN:"token"},fetcher});
  assert.equal(value.found,false);
  assert.equal(calls,1);
});
