// Shared pure policy for typed browser operations exposed by OCN.
// Keep this identical in Render and Supabase Edge. The non-elevated Windows
// worker additionally validates requests before Playwright tool invocation.
export const BROWSER_OPERATIONS = Object.freeze([
  'browser_connect', 'browser_status', 'browser_disconnect',
  'browser_navigate', 'browser_snapshot', 'browser_click', 'browser_type',
  'browser_navigate_back', 'browser_tab_list', 'browser_tab_select',
  'browser_batch_persistent'
]);
const optionalFields = Object.freeze({
  browser_connect: [], browser_status: [], browser_disconnect: [],
  browser_navigate: ['url'], browser_snapshot: [],
  browser_click: ['target','element','doubleClick','button'],
  browser_type: ['target','element','text','submit'],
  browser_navigate_back: [], browser_tab_list: [], browser_tab_select: ['index'],
  browser_batch_persistent: ['steps']
});

const PERSISTENT_TOOLS = new Set([
  'browser_navigate','browser_snapshot','browser_click','browser_type',
  'browser_navigate_back','browser_tab_list','browser_tab_select',
  'browser_tabs','browser_wait_for','browser_find'
]);

function validUrl(url) {
  if (typeof url !== 'string' || url.length < 8 || url.length > 8192) return false;
  try {
    const u = new URL(url);
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
