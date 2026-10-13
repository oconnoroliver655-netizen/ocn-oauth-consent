import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request as nodeRequest} from 'node:http';
import {allowedRun,createBackend,makeHandler} from '../pr529-ci-guard.mjs';
const repo='oconnoroliver655-netizen/chatgpt-local-bridge',base=`https://api.github.com/repos/${repo}`;
const branch='feature/ocn-owner-bound-mcp-files-20261013',old='b'.repeat(40),head='a'.repeat(40);
const run=(id,overrides={})=>({id,name:'Cloud Admin Agent validation',event:'pull_request',
  head_branch:branch,head_sha:old,status:'queued',pull_requests:[{number:529,head:{ref:branch}}],...overrides});
function backendMock({rows=[run(1)],headSha=head,token='x'.repeat(50),switchHeadOnSecondGet=false,writesEnabled=true}={}){
  let state=headSha, posts=[],headLookups=0;
  const fetcher=async (url,params)=>{
    const u=new URL(url);
    if(u.origin!=='https://api.github.com')throw new Error('Wrong origin');
    if(params.method==='POST'){
      assert.match(u.pathname,/^\/repos\/oconnoroliver655-netizen\/chatgpt-local-bridge\/actions\/runs\/\d+\/cancel$/);
      posts.push(+u.pathname.split('/').at(-2));
      return {status:202};
    }
    let v;
    if(u.pathname===`/repos/${repo}/pulls/529`){
      headLookups++; if(switchHeadOnSecondGet && headLookups>=2) state=old;
      v={state:'open',head:{sha:state,ref:branch}};
    }
    else if(u.pathname.endsWith('/actions/runs'))v={workflow_runs:rows.filter(r=>r.status===u.searchParams.get('status'))};
    else if(/\/actions\/runs\/\d+$/.test(u.pathname))v=rows.find(r=>r.id===+u.pathname.split('/').at(-1));
    else throw new Error('Unexpected URL '+u.pathname);
    return {status:200,json:async()=>v};
  };
  const api=createBackend({githubToken:token,writesEnabled,fetcher,validator:async h=>h==='Bearer signed-owner'});
  return {api,posts,head:(newValue)=>state=newValue};
}
const ORIGIN='https://ocn-mcp-ping-canary.onrender.com';
const headers={'content-type':'application/json','accept':'application/json, text/event-stream',
  'mcp-protocol-version':'2025-11-25',host:new URL(ORIGIN).host};
async function withServer(backend,execute){
  const app=createServer((req,res)=>makeHandler({origin:ORIGIN,backend})(req,res).catch(err=>{res.statusCode=500;res.end(String(err))}));
  await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));
  const port=app.address().port;
  const rpc=async (method,params={},token='')=>{
    const body=JSON.stringify({jsonrpc:'2.0',id:7,method,params});
    return await new Promise((resolve,reject)=>{
      const req=nodeRequest(`http://127.0.0.1:${port}/mcp-ci-guard`,{
        method:'POST',headers:{...headers,...(token?{authorization:token}:{})}},res=>{
          const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{
            try{resolve({status:res.statusCode,data:JSON.parse(Buffer.concat(chunks).toString('utf8'))});}
            catch(e){reject(e);}
          });
        });
      req.on('error',reject);req.end(body);
    });
  };
  try{await execute(rpc);}finally{await new Promise(resolve=>app.close(resolve));}
}

test('eligible strictly restricts SHA, PR, branch, event and workflow',()=>{
  assert.equal(allowedRun(run(1),head),true);
  assert.equal(allowedRun(run(1,{head_sha:head}),head),false);
  assert.equal(allowedRun(run(1,{event:'push'}),head),false);
  assert.equal(allowedRun(run(1,{status:'completed'}),head),false);
  assert.equal(allowedRun(run(1,{head_branch:'main'}),head),false);
  assert.equal(allowedRun(run(1,{pull_requests:[{number:530,head:{ref:branch}}]}),head),false);
  assert.equal(allowedRun(run(1,{name:'Production deployment'}),head),false);
  assert.equal(allowedRun(run(1,{pull_requests:[]}),head),false);
});
test('scan is strictly read-only and filters latest and unrelated CI',async()=>{
  const mock=backendMock({rows:[run(1),run(2,{head_sha:head}),run(3,{event:'push'}),run(4,{name:'Other'})]});
  const p=await mock.api.scan();assert.deepEqual(p.stale.map(x=>x.id),[1]);assert.deepEqual(mock.posts,[]);
});
test('cancel only eligible runs, skips fresh SHA',async()=>{
  const m=backendMock({rows:[run(1),run(2,{head_sha:head}),run(3,{event:'push'})]});
  const p=await m.api.cancel();assert.equal(p.cancel_requests,1);assert.deepEqual(m.posts,[1]);
});
test('cancellation rechecks SHA immediately before write',async()=>{
  const m=backendMock({switchHeadOnSecondGet:true});
  const p=await m.api.cancel();assert.equal(p.cancel_requests,0);assert.deepEqual(m.posts,[]);
});
test('missing GitHub secret blocks API and no writes',async()=>{
  const m=backendMock({token:''});await assert.rejects(()=>m.api.scan(),/GITHUB_NOT_CONFIGURED/);assert.deepEqual(m.posts,[]);
});
test('authenticated MCP tools reject anonymous or forged bearer',async()=>{
  const m=backendMock();await withServer(m.api,async rpc=>{
    for(const auth of ['','Bearer forged']){
      const r=await rpc('tools/call',{name:'cancel_stale_pr529_ci',arguments:{}},auth);
      assert.equal(r.status,200);assert.equal(r.data.result.isError,true);
      assert.match(r.data.result._meta['mcp/www_authenticate'][0],/invalid_token/);
    }
  });assert.deepEqual(m.posts,[]);
});
test('MCP scan supports OAuth tool declaration',async()=>{
  const m=backendMock();await withServer(m.api,async rpc=>{
    const init=await rpc('initialize',{protocolVersion:'2025-11-25'});
    assert.equal(init.data.result.protocolVersion,'2025-11-25');
    const r=await rpc('tools/list');const names=r.data.result.tools.map(t=>t.name);
    assert.deepEqual(names,['inspect_pr529_ci','cancel_stale_pr529_ci']);
    assert.equal(r.data.result.tools[1].annotations.destructiveHint,true);
    assert.deepEqual(r.data.result.tools[1].securitySchemes,[{type:'oauth2',scopes:['openid','email']}]);
  });
});
test('authenticated MCP rejects unsupported tool, unexpected args and privilege escalation',async()=>{
  const m=backendMock();await withServer(m.api,async rpc=>{
    for(const [name,args] of [['run_shell',{}],['cancel_stale_pr529_ci',{force:true}],['cancel_stale_pr529_ci',{max_cancellations:999}],['inspect_pr529_ci',{repo:'other'}]]){
      const r=await rpc('tools/call',{name,arguments:args},'Bearer signed-owner');
      assert.equal(r.data.result.isError,true);
    }
  });assert.deepEqual(m.posts,[]);
});
test('authenticated MCP can cancel exactly one valid stale run',async()=>{
  const m=backendMock();await withServer(m.api,async rpc=>{
    const r=await rpc('tools/call',{name:'cancel_stale_pr529_ci',arguments:{max_cancellations:1}},'Bearer signed-owner');
    assert.equal(r.data.result.isError,false);assert.equal(r.data.result.structuredContent.cancel_requests,1);
  });assert.deepEqual(m.posts,[1]);
});

test('cancellation is off unless explicitly enabled on host',async()=>{
  const m=backendMock({writesEnabled:false});
  await assert.rejects(()=>m.api.cancel(),/WRITES_DISABLED/);
  assert.deepEqual(m.posts,[]);
});
