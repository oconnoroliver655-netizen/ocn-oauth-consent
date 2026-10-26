import test from 'node:test';
import assert from 'node:assert/strict';
import {validFusionUiPayload} from './fusion-ui-policy.mjs';
import {validWindowsCall} from './windows-tools.mjs';

const common={action:'uia_invoke',lease_id:'x'.repeat(32),hwnd:4321,
  browser_pid:9876,profile_dir:'C:\\Users\\oliver\\AppData\\Local\\Temp\\ocn-v100-ui-profile-abcdefgh',
  name:'Load unpacked'};

test('scoped UIA action accepted on both direct and generic routes',()=>{
  assert.equal(validFusionUiPayload(common),true);
  assert.equal(validWindowsCall('submit_windows_operation',
    {operation:'fusion_test_ui',payload:common}),true);
});
test('reject missing scope, forbidden operation, and system identity',()=>{
  for(const patch of [{hwnd:0},{browser_pid:-1},{profile_dir:'C:\\Users\\oliver\\Chrome\\Profile 6'},
    {run_as:'system'},{action:'window_close'},{action:'key_press',key:'delete'},
    {lease_id:'short'}]){
    assert.equal(validFusionUiPayload({...common,...patch}),false,JSON.stringify(patch));
  }
  assert.equal(validFusionUiPayload({...common,action:'key_press',key:3}),false);
  assert.equal(validFusionUiPayload({...common,action:'type_text',text:'hi',name:'extra'}),false);
});
test('leases are short and require exact keys',()=>{
  for(const t of [30,60,90])assert.equal(validFusionUiPayload({action:'lease_acquire',ttl_seconds:t}),true);
  for(const t of [1,15,300,true,'90'])assert.equal(validFusionUiPayload({action:'lease_acquire',ttl_seconds:t}),false);
  assert.equal(validFusionUiPayload({action:'lease_release',lease_id:'x'.repeat(32)}),true);
  assert.equal(validFusionUiPayload({action:'lease_release',lease_id:'x'.repeat(32),ttl_seconds:60}),false);
});
