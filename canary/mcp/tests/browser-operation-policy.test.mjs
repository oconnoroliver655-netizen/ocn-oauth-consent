import {test} from 'node:test';
import assert from 'node:assert/strict';
import {BROWSER_OPERATIONS, validBrowserPayload} from './browser-operation-policy.mjs';
test('every declared browser tool has valid empty or typed args',()=>{
  for(const action of ['browser_connect','browser_status','browser_disconnect','browser_snapshot','browser_navigate_back','browser_tab_list'])
    assert.equal(validBrowserPayload(action,{}),true,action);
  assert.equal(BROWSER_OPERATIONS.length,10);
});
test('navigation requires public HTTP(S) URL',()=>{
  assert.equal(validBrowserPayload('browser_navigate',{url:'https://example.org'}),true);
  for(const url of ['file:///C:/Users','http://localhost:3000','http://127.0.0.1',
   'https://name:secret@example.com','javascript:alert(1)','http://192.168.0.1'])
    assert.equal(validBrowserPayload('browser_navigate',{url}),false,url);
});
test('click/type strictly validate selector and parameters',()=>{
 assert.equal(validBrowserPayload('browser_click',{target:'e1'}),true);
 assert.equal(validBrowserPayload('browser_type',{target:'e2',text:'hello',submit:false}),true);
 assert.equal(validBrowserPayload('browser_click',{target:'e1',button:'weird'}),false);
 assert.equal(validBrowserPayload('browser_type',{target:'e2',text:'hello',script:'whoami'}),false);
 assert.equal(validBrowserPayload('browser_type',{target:'e2'}),false);
});
test('tab selection is nonnegative int',()=>{
 assert.equal(validBrowserPayload('browser_tab_select',{index:2}),true);
 for(const i of [-1,1.2,'2',null]) assert.equal(validBrowserPayload('browser_tab_select',{index:i}),false);
});
test('OS and code execution tools never allowed',()=>{
 for(const op of ['powershell','browser_run_code','browser_evaluate','exec','file_write'])
  assert.equal(validBrowserPayload(op,{}),false);
});
