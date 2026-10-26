// Owner-bound disposable-Chrome GUI actions only. Keep identical on Render
// and in the Supabase Edge function; Windows Desktop Agent validates again.
const isObj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const digits=x=>Number.isSafeInteger(x)&&x>0;
const lease=x=>typeof x==='string'&&x.length>=20&&x.length<=64;
const ttl=x=>Number.isInteger(x)&&x>=30&&x<=90;
const profile=x=>typeof x==='string'&&x.length>20&&x.length<=1024&&
  /[\\/]ocn-v100-ui-profile-[a-z0-9]{8,24}$/u.test(x);
const hasKeys=(o,required,optional=[])=>required.every(k=>Object.hasOwn(o,k))&&
  Object.keys(o).every(k=>required.includes(k)||optional.includes(k));

export function validFusionUiPayload(p){
  if(!isObj(p)||typeof p.action!=='string')return false;
  if(p.action==='lease_acquire')return hasKeys(p,['action','ttl_seconds'])&&ttl(p.ttl_seconds);
  if(p.action==='lease_renew')return hasKeys(p,['action','lease_id','ttl_seconds'])&&
    lease(p.lease_id)&&ttl(p.ttl_seconds);
  if(p.action==='lease_release')return hasKeys(p,['action','lease_id'])&&lease(p.lease_id);
  const common=['action','lease_id','hwnd','browser_pid','profile_dir'];
  if(!common.every(k=>Object.hasOwn(p,k))||!lease(p.lease_id)||
     !digits(p.hwnd)||!digits(p.browser_pid)||!profile(p.profile_dir)||
     p.run_as!==undefined)return false;
  if(p.action==='focus')return hasKeys(p,common);
  if(p.action==='uia_invoke'||p.action==='uia_set_value'){
    const required=p.action==='uia_set_value'?[...common,'value']:common;
    if(!hasKeys(p,required,['automation_id','name']))return false;
    if(!(p.name||p.automation_id))return false;
    if(['automation_id','name'].some(k=>p[k]!==undefined&&
      (typeof p[k]!=='string'||p[k].length>256)))return false;
    return p.action!=='uia_set_value'||(typeof p.value==='string'&&p.value.length<=2048);
  }
  if(p.action==='type_text')return hasKeys(p,[...common,'text'])&&
    typeof p.text==='string'&&p.text.length>0&&p.text.length<=2048;
  if(p.action==='key_press')return hasKeys(p,[...common,'key'])&&
    typeof p.key==='string'&&['enter','tab','esc','escape'].includes(p.key.toLowerCase());
  return false;
}

export const FUSION_UI_TOOL={
  name:'fusion_test_ui',
  description:'Owner-OAuth scoped GUI action for a disposable Chrome for Testing MV3 extension-install experiment. Requires one exact test HWND, browser PID, temporary ocn-v100-ui-profile directory, and live matching short desktop lease. No Chrome Profile 6, arbitrary desktop, UAC or privileged UI. Queues only; poll_windows_operation for outcome.',
  inputSchema:{type:'object',properties:{
    action:{type:'string',enum:['lease_acquire','lease_renew','lease_release',
      'focus','uia_invoke','uia_set_value','type_text','key_press']},
    lease_id:{type:'string',minLength:20,maxLength:64},
    ttl_seconds:{type:'integer',minimum:30,maximum:90},
    hwnd:{type:'integer',minimum:1},
    browser_pid:{type:'integer',minimum:1},
    profile_dir:{type:'string',maxLength:1024},
    automation_id:{type:'string',maxLength:256},
    name:{type:'string',maxLength:256},
    value:{type:'string',maxLength:2048},
    text:{type:'string',minLength:1,maxLength:2048},
    key:{type:'string',enum:['enter','tab','esc','escape']}
  },required:['action'],additionalProperties:false},
  securitySchemes:[{type:'oauth2',scopes:['openid','email']}],
  annotations:{readOnlyHint:false,destructiveHint:false,openWorldHint:false}
};
