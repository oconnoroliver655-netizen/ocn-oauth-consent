// Shared pure policy for typed browser operations exposed by OCN.
// Keep this identical in Render and Supabase Edge. The non-elevated Windows
// worker additionally validates requests before Playwright tool invocation.
export const BROWSER_OPERATIONS = Object.freeze([
  'browser_connect', 'browser_status', 'browser_disconnect',
  'browser_navigate', 'browser_snapshot', 'browser_click', 'browser_type',
  'browser_navigate_back', 'browser_tab_list', 'browser_tab_select',
  'browser_batch_persistent', 'browser_batch_unified'
]);
const optionalFields = Object.freeze({
  browser_connect: [], browser_status: [], browser_disconnect: [],
  browser_navigate: ['url'], browser_snapshot: [],
  browser_click: ['target','element','doubleClick','button'],
  browser_type: ['target','element','text','submit'],
  browser_navigate_back: [], browser_tab_list: [], browser_tab_select: ['index'],
  browser_batch_persistent: ['steps'],
  browser_batch_unified: ['steps','capabilities','unsafe_approved']
});

const PERSISTENT_TOOLS = new Set([
  'browser_navigate','browser_snapshot','browser_click','browser_type',
  'browser_navigate_back','browser_tab_list','browser_tab_select',
  'browser_tabs','browser_wait_for','browser_find'
]);

const UNIFIED_CAPS=new Set(['vision','pdf','devtools']);
const CAPABILITY_TOOLS=Object.freeze({"browser_mouse_click_xy":"vision","browser_mouse_down":"vision","browser_mouse_drag_xy":"vision","browser_mouse_move_xy":"vision","browser_mouse_up":"vision","browser_mouse_wheel":"vision","browser_pdf_save":"pdf","browser_annotate":"devtools","browser_hide_highlight":"devtools","browser_highlight":"devtools","browser_resume":"devtools","browser_start_recording":"devtools","browser_start_tracing":"devtools","browser_start_video":"devtools","browser_stop_recording":"devtools","browser_stop_tracing":"devtools","browser_stop_video":"devtools","browser_video_chapter":"devtools","browser_video_hide_actions":"devtools","browser_video_show_actions":"devtools"});
const UNIFIED_SENSITIVE=new Set(['browser_run_code_unsafe','browser_evaluate','browser_cdp_send','browser_route','browser_route_list','browser_storage_state','browser_configure','browser_network_set']);
function validUnifiedBatch(payload){
  const steps=payload.steps,caps=payload.capabilities??[];
  if(!Array.isArray(steps)||steps.length<1||steps.length>12||!Array.isArray(caps)||caps.length>3||caps.some(x=>!UNIFIED_CAPS.has(x))||new Set(caps).size!==caps.length||(payload.unsafe_approved!==undefined&&typeof payload.unsafe_approved!=='boolean')||new TextEncoder().encode(JSON.stringify(payload)).length>15500)return false;
  return steps.every(step=>{
    if(!step||typeof step!=='object'||Array.isArray(step)||Object.keys(step).length!==2||!('tool' in step)||!('arguments' in step)||typeof step.tool!=='string'||!/^browser_[a-z][a-z0-9_]{0,80}$/.test(step.tool)||!step.arguments||typeof step.arguments!=='object'||Array.isArray(step.arguments))return false;
    const tool=step.tool,a=step.arguments;
    if(UNIFIED_SENSITIVE.has(tool)&&payload.unsafe_approved!==true)return false;
    if(CAPABILITY_TOOLS[tool]&&!caps.includes(CAPABILITY_TOOLS[tool]))return false;
    if(tool==='browser_navigate'&&!validUrl(a.url))return false;
    if(tool==='browser_tabs'&&a.action==='new'&&'url' in a&&(!/^https?:\/\//.test(a.url)||!validUrl(a.url)))return false;
    if((tool==='browser_file_upload'||tool==='browser_drop')&&'paths' in a&&(!Array.isArray(a.paths)||a.paths.length>30||a.paths.some(p=>typeof p!=='string'||p.length>32767)))return false;
    return true;
  });
}

function validUrl(url) {
  if (typeof url !== 'string' || url.length < 8 || url.length > 8192) return false;
  try {
    const u = new URL(url);
    // Owner-scoped explicit Chrome diagnostic/extension pages, never blanket internal access.
    if (u.protocol === 'chrome:' || u.protocol === 'chrome-extension:') {
      const allowed = new Set([
        'chrome://version/',
        'chrome://extensions/',
        'chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/browser/js/options.html'
      ]);
      return !u.username && !u.password && !u.search && !u.hash &&
        allowed.has(u.href);
    }
    if (!['http:', 'https:'].includes(u.protocol) || !u.hostname ||
        u.username || u.password) return false;
    const host=u.hostname.toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost') ||
        host.endsWith('.local') || host.endsWith('.internal') ||
        host === '[::1]' || host === '127.0.0.1' ||
        /^(?:10\.|127\.|169\.254\.|192\.168\.)/.test(host)) return false;
    return true;
  } catch { return false; }
}

export function validBrowserPayload(operation, payload) {
  if (!Object.prototype.hasOwnProperty.call(optionalFields,operation) ||
      !payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
  const keys=Object.keys(payload), allowed=optionalFields[operation];
  if (keys.some(key=>!allowed.includes(key))) return false;
  if (operation==='browser_batch_unified') return validUnifiedBatch(payload);
  if (operation==='browser_batch_persistent') {
    if (keys.length!==1 || !Array.isArray(payload.steps) ||
        payload.steps.length<1 || payload.steps.length>8 ||
        JSON.stringify(payload).length>15500) return false;
    return payload.steps.every(step=>{
      if (!step || typeof step!=='object' || Array.isArray(step) ||
          Object.keys(step).length!==2 || !('tool' in step) ||
          !('arguments' in step) || !PERSISTENT_TOOLS.has(step.tool) ||
          !step.arguments || typeof step.arguments!=='object' ||
          Array.isArray(step.arguments)) return false;
      const a=step.arguments, k=Object.keys(a);
      if (step.tool==='browser_tabs') {
        if (a.action==='list') return k.length===1;
        if (a.action==='select') return k.length===2 &&
          validBrowserPayload('browser_tab_select',{index:a.index});
        if (a.action==='new') return k.length===1 ||
          (k.length===2 && typeof a.url==='string' &&
           (a.url.startsWith('https://') || a.url.startsWith('http://')) &&
           validBrowserPayload('browser_navigate',{url:a.url}));
        return false;
      }
      if (step.tool==='browser_wait_for') return k.length===1 &&
        ((typeof a.text==='string' && a.text.length>0 && a.text.length<=512) ||
         (typeof a.time==='number' && Number.isFinite(a.time) && a.time>0 && a.time<=20));
      if (step.tool==='browser_find') return k.length===1 &&
        typeof a.text==='string' && a.text.length>0 && a.text.length<=512;
      if (step.tool==='browser_navigate' &&
          (typeof a.url!=='string' ||
           !(a.url.startsWith('https://') || a.url.startsWith('http://')))) return false;
      return validBrowserPayload(step.tool,a);
    });
  }
  if (['browser_connect','browser_status','browser_disconnect','browser_snapshot',
       'browser_navigate_back','browser_tab_list'].includes(operation)) return keys.length===0;
  if (operation==='browser_navigate') return keys.length===1 && validUrl(payload.url);
  if (operation==='browser_tab_select') return keys.length===1 &&
      Number.isSafeInteger(payload.index) && payload.index>=0;
  if (typeof payload.target!=='string' || !payload.target || payload.target.length>4096)
    return false;
  if ('element' in payload && typeof payload.element!=='string') return false;
  if (operation==='browser_click') return (!('doubleClick' in payload) || typeof payload.doubleClick==='boolean') &&
    (!('button' in payload) || ['left','right','middle'].includes(payload.button));
  if (operation==='browser_type') return typeof payload.text==='string' &&
    (!('submit' in payload) || typeof payload.submit==='boolean');
  return false;
}
