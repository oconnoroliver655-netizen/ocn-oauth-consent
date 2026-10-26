import test from 'node:test';
import assert from 'node:assert/strict';
import {validFusionUiPayload as renderValid} from './fusion-ui-policy.mjs';
import {validFusionUiPayload as edgeValid} from '../../edge-stage/ocn-owner-health-dispatch/fusion-ui-policy.mjs';

test('Render and Supabase reject/accept identical disposable GUI payloads',()=>{
  const common={action:'uia_invoke',lease_id:'a'.repeat(32),hwnd:1234,
    browser_pid:5678,profile_dir:'C:\\Users\\oliver\\AppData\\Local\\Temp\\ocn-v100-ui-profile-abcdef12',
    name:'Load unpacked'};
  const samples=[{},null,[],common,{...common,run_as:'system'},
    {...common,profile_dir:'C:\\Users\\oliver\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 6'},
    {action:'lease_acquire',ttl_seconds:60},{action:'lease_acquire',ttl_seconds:300},
    {action:'lease_release',lease_id:'b'.repeat(32)},
    {...common,action:'key_press',key:'enter',name:undefined},
    {...common,action:'type_text',text:'hello',name:undefined}];
  for(const candidate of samples){
    assert.equal(renderValid(candidate),edgeValid(candidate),JSON.stringify(candidate));
  }
});
