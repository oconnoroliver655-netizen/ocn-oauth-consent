// Remote, owner-authenticated CI Guard for one repository and one PR.
// Does not expose tokens, filesystem, command execution, deployment, force-cancel or rerun.
const REPO = 'oconnoroliver655-netizen/chatgpt-local-bridge';
const PR = 529;
const BRANCH = 'feature/ocn-owner-bound-mcp-files-20261013';
const API = `https://api.github.com/repos/${REPO}`;
const AUTH_URL = 'https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-oauth-validator';
const ALLOWED = new Set([
  'Local Commander validation and deployment',
  'Local Commander self-hosted validation',
  'Cloud Admin Agent validation',
  'OCN owner-bound remote read admission CI',
]);
const STATUSES = ['queued','pending','in_progress','waiting','requested'];
const VERSIONS = new Set(['2025-03-26','2025-06-18','2025-11-25','2026-07-28']);
const MAX_BODY = 4096;
let cancellationInProgress = false;

const ok = (id,result) => ({jsonrpc:'2.0',id,result});
const error = (id,code,message) => ({jsonrpc:'2.0',id,error:{code,message}});
function respond(res,status,payload,extra={}){
  res.writeHead(status,{'content-type':'application/json; charset=utf-8',
    'cache-control':'no-store','x-content-type-options':'nosniff',
    'content-security-policy':"default-src 'none'",...extra});
  res.end(payload === null ? '' : JSON.stringify(payload));
}
const textResponse=(text,isError=false,extra={})=>({content:[{type:'text',text}],isError,...extra});
const toolResult=(id,body)=>ok(id,{...body});
function authChallenge(origin){
  const challenge=`Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource", error="invalid_token", scope="openid email"`;
  return textResponse('Verified owner OAuth access required',true,{
    _meta:{'mcp/www_authenticate':[challenge]}});
}
function allowedRun(r,head){
  if(!r || typeof r!=='object' || !Number.isSafeInteger(r.id) || r.id<=0) return false;
  return r.event==='pull_request' && r.head_branch===BRANCH &&
    ALLOWED.has(r.name) && STATUSES.includes(r.status) &&
    typeof r.head_sha==='string' && /^[a-f0-9]{40}$/i.test(r.head_sha) &&
    r.head_sha.toLowerCase()!==head && Array.isArray(r.pull_requests) &&
    r.pull_requests.some(p=>p && p.number===PR && p.head?.ref===BRANCH);
}
export {allowedRun};

function createBackend({githubToken=process.env.PR529_GITHUB_ACTIONS_TOKEN||'',
  writesEnabled=process.env.PR529_CI_GUARD_WRITES_ENABLED==='true',fetcher=fetch,validator=null}={}){
  async function authenticated(authHeader){
    if(typeof authHeader!=='string'||!/^Bearer [A-Za-z0-9_\-\.]+$/.test(authHeader)||authHeader.length>8200) return false;
    if(validator) return await validator(authHeader);
    try{
      const r=await fetcher(AUTH_URL,{
        method:'POST', headers:{authorization:authHeader,'content-type':'application/json'},
        body:JSON.stringify({action:'owner_auth_probe'}),signal:AbortSignal.timeout(7000),
      });
      if(r.status!==200) return false;
      const d=await r.json();
      return d?.ok===true && d?.owner_verified===true && d?.machine_control===false;
    }catch{return false;}
  }
  async function github(method,path){
    if(!githubToken || githubToken.length<16) throw new Error('GITHUB_NOT_CONFIGURED');
    if(method!=='GET' && method!=='POST') throw new Error('METHOD_DENIED');
    if(!path.startsWith(`${API}/`) || path.includes('#')) throw new Error('URL_DENIED');
    if(method==='POST' && !new RegExp(`^${API.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}/actions/runs/[1-9][0-9]*/cancel$`).test(path))
      throw new Error('WRITE_DENIED');
    const r=await fetcher(path,{
      method,headers:{authorization:`Bearer ${githubToken}`,accept:'application/vnd.github+json',
        'x-github-api-version':'2022-11-28','user-agent':'pr529-ci-guard/1'},
      redirect:'error',signal:AbortSignal.timeout(9000),
    });
    if(method==='POST'){
      if(r.status!==202) throw new Error('CANCEL_REJECTED');
      return {};
    }
    if(r.status!==200) throw new Error('GITHUB_UNAVAILABLE');
    return await r.json();
  }
  async function head(){
    const p=await github('GET',`${API}/pulls/${PR}`);
    if(p.state!=='open'||p.head?.ref!==BRANCH||!/^[a-f0-9]{40}$/i.test(p.head?.sha||''))
      throw new Error('PR_NOT_MATCHED');
    return p.head.sha.toLowerCase();
  }
  async function scan(){
    const current=await head(),found=new Map();
    for(const status of STATUSES){
      for(let page=1;page<=4;page++){
        const query=new URLSearchParams({event:'pull_request',branch:BRANCH,status,
          per_page:'100',page:String(page)});
        const pageData=await github('GET',`${API}/actions/runs?${query}`);
        if(!Array.isArray(pageData.workflow_runs)) throw new Error('RUN_LIST_INVALID');
        for(const r of pageData.workflow_runs) if(allowedRun(r,current)) found.set(r.id,r);
        if(pageData.workflow_runs.length<100) break;
        if(page===4) throw new Error('SCAN_PAGINATION_CAP');
      }
    }
    const stale=[...found.values()].sort((a,b)=>a.id-b.id);
    return {repository:REPO,pr:PR,head_sha:current,stale_count:stale.length,
      stale:stale.map(r=>({id:r.id,name:r.name,status:r.status,sha:r.head_sha}))};
  }
  async function cancel(max=15){
    if(!writesEnabled) throw new Error('WRITES_DISABLED');
    if(!Number.isInteger(max)||max<1||max>25) throw new Error('LIMIT_INVALID');
    if(cancellationInProgress) throw new Error('CANCEL_IN_PROGRESS');
    cancellationInProgress=true;
    try{
      const plan=await scan(),report=[];
      for(const r of plan.stale.slice(0,max)){
        const current=await head();
        const live=await github('GET',`${API}/actions/runs/${r.id}`);
        if(!allowedRun(live,current)){
          report.push({id:r.id,state:'skipped_not_eligible'});continue;
        }
        await github('POST',`${API}/actions/runs/${r.id}/cancel`);
        report.push({id:r.id,state:'cancel_requested'});
      }
      return {repository:REPO,pr:PR,head_at_start:plan.head_sha,
        candidates:plan.stale_count,cancel_requests:report.filter(x=>x.state==='cancel_requested').length,
        results:report,note:'Requested cancellation is not evidence of terminal cancellation.'};
    }finally{cancellationInProgress=false;}
  }
  return {authenticated,scan,cancel,github};
}
export {createBackend};

const TOOLS=[
  {name:'inspect_pr529_ci',description:'Authenticated, read-only list of obsolete CI runs for the fixed PR #529.',
   inputSchema:{type:'object',properties:{},additionalProperties:false},
   securitySchemes:[{type:'oauth2',scopes:['openid','email']}],
   annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}},
  {name:'cancel_stale_pr529_ci',description:'Cancel only verified obsolete PR #529 validation runs; never latest commit, unrelated PR, deploy, or forced cancellation. Requires owner OAuth and GitHub Actions token.',
   inputSchema:{type:'object',properties:{max_cancellations:{type:'integer',minimum:1,maximum:25}},additionalProperties:false},
   securitySchemes:[{type:'oauth2',scopes:['openid','email']}],
   annotations:{readOnlyHint:false,destructiveHint:true,openWorldHint:false}},
];
export {TOOLS};

export function makeHandler({origin,backend=createBackend()}={}){
  if(!origin || !/^https:\/\/[^/]+$/.test(origin))throw new Error('Explicit HTTPS origin required');
  return async function handleCiGuard(req,res){
    if(req.headers.host!==new URL(origin).host)return respond(res,421,{error:'Unrecognized Host'});
    if(req.headers.origin!==undefined)return respond(res,403,{error:'Browser origins disabled'});
    if(req.method!=='POST')return respond(res,405,{error:'POST required'});
    if(req.headers['content-type']?.split(';')[0].trim()!=='application/json')
      return respond(res,415,{error:'JSON required'});
    const accept=String(req.headers.accept||'');
    if(!accept.includes('application/json')||!accept.includes('text/event-stream'))
      return respond(res,406,{error:'MCP Accept required'});
    if(req.headers['mcp-protocol-version']&&!VERSIONS.has(req.headers['mcp-protocol-version']))
      return respond(res,400,error(null,-32600,'Unsupported protocol version'));
    if(Number(req.headers['content-length']||0)>MAX_BODY)return respond(res,413,{error:'Oversized request'});
    const chunks=[];let size=0;
    for await(const c of req){size+=c.length;if(size>MAX_BODY)return respond(res,413,{error:'Oversized request'});chunks.push(c);}
    let m;try{m=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return respond(res,400,error(null,-32700,'Invalid JSON'));}
    if(!m||typeof m!=='object'||Array.isArray(m)||m.jsonrpc!=='2.0')return respond(res,400,error(null,-32600,'Invalid JSON-RPC'));
    const id=m.id; if(m.method==='notifications/initialized')return respond(res,202,null);
    if(!(typeof id==='string'&&id.length<=100||Number.isSafeInteger(id)))return respond(res,400,error(null,-32600,'Invalid id'));
    if(m.method==='initialize'){
      const v=m.params?.protocolVersion;
      if(!VERSIONS.has(v))return respond(res,200,error(id,-32602,'Unsupported protocol'));
      return respond(res,200,ok(id,{protocolVersion:v,capabilities:{tools:{listChanged:false}},serverInfo:{name:'pr529-ci-guard',version:'1.0.0'}}));
    }
    if(m.method==='ping')return respond(res,200,ok(id,{}));
    if(m.method==='tools/list')return respond(res,200,ok(id,{tools:TOOLS}));
    if(m.method!=='tools/call')return respond(res,200,error(id,-32601,'Unknown method'));
    const tool=m.params?.name,args=m.params?.arguments;
    if(!TOOLS.some(t=>t.name===tool)||!args||typeof args!=='object'||Array.isArray(args))
      return respond(res,200,toolResult(id,textResponse('Invalid call',true)));
    const keys=Object.keys(args);
    if(tool==='inspect_pr529_ci'&&keys.length!==0||tool==='cancel_stale_pr529_ci'&&
      (keys.some(k=>k!=='max_cancellations')||keys.length>1||
      (keys.includes('max_cancellations')&&(!Number.isInteger(args.max_cancellations)||args.max_cancellations<1||args.max_cancellations>25))))
      return respond(res,200,toolResult(id,textResponse('Invalid arguments',true)));
    if(!(await backend.authenticated(String(req.headers.authorization||''))))
      return respond(res,200,toolResult(id,authChallenge(origin)));
    try{
      const result=tool==='inspect_pr529_ci'?await backend.scan():await backend.cancel(args.max_cancellations??15);
      return respond(res,200,toolResult(id,{...textResponse(JSON.stringify(result)),structuredContent:result}));
    }catch(e){
      const msg=e?.message==='GITHUB_NOT_CONFIGURED'?'GitHub Actions server credential is not configured':
        e?.message==='WRITES_DISABLED'?'CI cancellation disabled until explicitly enabled':
        e?.message==='CANCEL_IN_PROGRESS'?'Cleanup already in progress':'CI Guard unavailable or rejected request';
      return respond(res,200,toolResult(id,textResponse(msg,true)));
    }
  };
}
