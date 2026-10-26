import test from 'node:test';
import assert from 'node:assert/strict';
import {request} from 'node:http';
process.env.OCN_PUBLIC_ORIGIN='https://fusion-gateway.test.invalid';
const {start}=await import('./server.mjs');
const server=start(0);
await new Promise(resolve=>server.once('listening',resolve));
const port=server.address().port;
async function rpc(path,method,params={},headers={}){
  const body=JSON.stringify({jsonrpc:'2.0',id:1,method,params});
  return new Promise((resolve,reject)=>{
    const req=request({hostname:'127.0.0.1',port,path,method:'POST',headers:{
      host:'fusion-gateway.test.invalid',
      'content-type':'application/json',accept:'application/json, text/event-stream',...headers
    }},res=>{
      const chunks=[];res.on('data',x=>chunks.push(x));
      res.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString()))}catch(e){reject(e)}});
    });
    req.on('error',reject);req.end(body);
  });
}
const args={action:'uia_invoke',lease_id:'a'.repeat(32),hwnd:700,browser_pid:900,
 profile_dir:'C:\\Users\\oliver\\AppData\\Local\\Temp\\ocn-v100-ui-profile-abcdef12',name:'Load unpacked'};
test.after(async()=>{await new Promise(resolve=>server.close(resolve));});
test('Fusion UI is owner-authenticated and hidden on open route',async()=>{
  const open=await rpc('/mcp','tools/list');
  const auth=await rpc('/mcp-oauth','tools/list');
  assert.equal(open.result.tools.some(t=>t.name==='fusion_test_ui'),false);
  assert.equal(auth.result.tools.filter(t=>t.name==='fusion_test_ui').length,1);
  const noBearer=await rpc('/mcp-oauth','tools/call',{name:'fusion_test_ui',arguments:args});
  assert.equal(noBearer.result.isError,true);
});
test('Unscoped or incorrect user profile is rejected before remote fetch',async()=>{
  const original=globalThis.fetch;
  globalThis.fetch=()=>{throw Error('REMOTE_FETCH_MUST_NOT_RUN')};
  try{
    const result=await rpc('/mcp-oauth','tools/call',{
      name:'fusion_test_ui',arguments:{...args,profile_dir:'C:\\Chrome\\Profile 6'}
    });
    assert.equal(result.result.isError,true);
    assert.match(JSON.stringify(result.result),/Invalid tool arguments/);
  }finally{globalThis.fetch=original}
});
test('Valid action queues one existing owner-bound Windows operation',async()=>{
  const original=globalThis.fetch;
  let seen;
  globalThis.fetch=async(url,options)=>{
    seen={url:String(url),authorization:options.headers.authorization,
      body:JSON.parse(options.body)};
    return new Response(JSON.stringify({ok:true,command_id:991,nonce:'b'.repeat(32),status:'queued'}),
      {status:202,headers:{'content-type':'application/json'}});
  };
  try{
    const result=await rpc('/mcp-oauth','tools/call',
       {name:'fusion_test_ui',arguments:args},{authorization:'Bearer mock-owner'});
    assert.equal(result.result.structuredContent.status,'queued');
    assert.equal(seen.authorization,'Bearer mock-owner');
    assert.equal(seen.body.action,'submit_windows_operation');
    assert.equal(seen.body.operation,'fusion_test_ui');
    assert.deepEqual(seen.body.payload,args);
    assert.equal(seen.body.payload.run_as,undefined);
    assert.match(seen.url,/ocn-owner-health-dispatch$/);
  }finally{globalThis.fetch=original}
});
