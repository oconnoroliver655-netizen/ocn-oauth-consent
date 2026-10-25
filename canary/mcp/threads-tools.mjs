// Independent OCN Threads social module. Official Meta Graph API only.
// All calls require verified OCN owner OAuth in server.mjs. Meta credentials
// are server-side environment variables and are never returned to clients.
const API = "https://graph.threads.net/v1.0";
const FIELDS = "id,username,text,media_type,media_url,permalink,timestamp,shortcode,children,is_reply,has_replies";
const OAUTH = [{type:"oauth2",scopes:["openid","email"]}];
const string = (max=500)=>({type:"string",minLength:1,maxLength:max});
const ident = {type:"string",pattern:"^[0-9]{1,30}$"};
const limit = {type:"integer",minimum:1,maximum:100};
const confirmed = {type:"boolean",const:true};
function entry(name,description,properties={},required=[],write=false,destructive=false){
  return {name,description,inputSchema:{type:"object",properties,required,additionalProperties:false},
    securitySchemes:OAUTH,annotations:{readOnlyHint:!write,destructiveHint:destructive,openWorldHint:true}};
}
export const THREADS_TOOLS = [
  entry("threads_connection_status","Read official Threads configuration status (never credentials)."),
  entry("threads_search_posts","Search discoverable public posts; Meta keyword-search permission required.",{query:string(256),recent:{type:"boolean"},limit},["query"]),
  entry("threads_read_post","Retrieve an eligible post using a numeric Threads media ID.",{media_id:ident},["media_id"]),
  entry("threads_read_shared_url","Resolve an official Threads share URL, then discover a matching post when supported.",{url:string(500)},["url"]),
  entry("threads_public_profile_posts","Discover an eligible public profile's posts.",{username:string(30),limit},["username"]),
  entry("threads_my_posts","List the authorized Threads account's posts.",{limit}),
  entry("threads_my_replies","List replies authored by the authorized Threads account.",{limit}),
  entry("threads_post_replies","Retrieve replies to an eligible post.",{media_id:ident,limit},["media_id"]),
  entry("threads_post_conversation","Retrieve the permitted post conversation.",{media_id:ident,limit},["media_id"]),
  entry("threads_post_insights","Retrieve own-post aggregate insights.",{media_id:ident},["media_id"]),
  entry("threads_publish_text","Publish a text post; requires owner confirmation and global write switch.",{text:string(500),confirm:confirmed},["text","confirm"],true),
  entry("threads_publish_image","Publish a publicly hosted HTTPS image; requires confirmation.",{image_url:string(1000),text:{type:"string",maxLength:500},confirm:confirmed},["image_url","confirm"],true),
  entry("threads_publish_video","Publish a publicly hosted HTTPS video; requires confirmation.",{video_url:string(1000),text:{type:"string",maxLength:500},confirm:confirmed},["video_url","confirm"],true),
  entry("threads_reply_to_post","Publish an exact text reply; requires confirmation.",{media_id:ident,text:string(500),confirm:confirmed},["media_id","text","confirm"],true),
  entry("threads_quote_post","Publish a text quote; requires confirmation.",{media_id:ident,text:string(500),confirm:confirmed},["media_id","text","confirm"],true),
  entry("threads_repost","Repost an eligible post; requires confirmation.",{media_id:ident,confirm:confirmed},["media_id","confirm"],true),
  entry("threads_manage_reply","Hide/unhide an eligible reply; requires confirmation.",{reply_id:ident,hide:{type:"boolean"},confirm:confirmed},["reply_id","hide","confirm"],true),
  entry("threads_delete_post","Permanently delete an owned post; requires exact ID and confirmation.",{media_id:ident,confirm:confirmed},["media_id","confirm"],true,true)
];
const specs = new Map(THREADS_TOOLS.map(x=>[x.name,x]));
const object = x=>x!==null && typeof x==="object" && !Array.isArray(x);
const digits = x=>typeof x==="string" && /^[0-9]{1,30}$/.test(x);
const username = x=>typeof x==="string" && /^@?[A-Za-z0-9._]{1,30}$/.test(x);
function mediaUrl(x){
  try {const u=new URL(x); return typeof x==="string" && x.length<=1000 && u.protocol==="https:" &&
    !!u.hostname && !u.username && !u.password && !u.port && !u.hash &&
    !/(^|\.)(localhost|local|internal)$/i.test(u.hostname) &&
    !/^(\d+\.){3}\d+$/.test(u.hostname) && !u.hostname.includes(":");} catch{return false;}
}
export function validThreadsCall(name,args){
  const spec=specs.get(name);
  if(!spec || !object(args))return false;
  const schema=spec.inputSchema;
  if(Object.keys(args).some(k=>!Object.hasOwn(schema.properties,k)) ||
    schema.required.some(k=>!Object.hasOwn(args,k)))return false;
  for(const [k,v] of Object.entries(args)){
    if(k==="media_id"||k==="reply_id"){if(!digits(v))return false;}
    else if(k==="username"){if(!username(v))return false;}
    else if(k==="query"){if(typeof v!=="string"||!v.trim()||v.length>256)return false;}
    else if(k==="url"){if(typeof v!=="string"||v.length>500||!parseThreadsUrl(v))return false;}
    else if(k==="limit"){if(!Number.isInteger(v)||v<1||v>100)return false;}
    else if(k==="recent"||k==="hide"){if(typeof v!=="boolean")return false;}
    else if(k==="confirm"){if(v!==true)return false;}
    else if(k==="image_url"||k==="video_url"){if(!mediaUrl(v))return false;}
    else if(k==="text"){if(typeof v!=="string"||v.length>500||
      (spec.name!=="threads_publish_image"&&spec.name!=="threads_publish_video"&&!v.trim()))return false;}
    else return false;
  }
  return Buffer.byteLength(JSON.stringify(args),"utf8")<=7500;
}
export function parseThreadsUrl(input){
  try{
    const u=new URL(input);
    if(u.protocol!=="https:" || !["threads.net","www.threads.net","threads.com","www.threads.com"].includes(u.hostname) ||
      u.username || u.password || u.port)return null;
    if(/^\/share\/[A-Za-z0-9_-]{3,80}\/?$/.test(u.pathname))return {kind:"share",url:u.origin+u.pathname};
    const m=u.pathname.match(/^\/@([A-Za-z0-9._]{1,30})\/post\/([A-Za-z0-9_-]{3,80})\/?$/);
    if(m)return {kind:"permalink",username:m[1],shortcode:m[2],url:u.origin+u.pathname};
    return null;
  }catch{return null;}
}
function fail(message){throw new Error(message);}
function headers(token){return {"authorization":"Bearer "+token,"accept":"application/json","user-agent":"OCN-Threads/0.2"};}
export function createThreadsClient({token,fetcher=fetch,sleep=ms=>new Promise(r=>setTimeout(r,ms))}){
  if(typeof token!=="string"||!token.trim())fail("THREADS_NOT_CONFIGURED");
  async function graph(method,path,params={}){
    if(!["GET","POST","DELETE"].includes(method) || !/^\/[A-Za-z0-9_\/]+$/.test(path))fail("INVALID_THREADS_PATH");
    const url=new URL(API+path);
    const data=new URLSearchParams(Object.entries(params).map(([k,v])=>[k,String(v)]));
    let body;
    if(method==="GET"||method==="DELETE")url.search=data.toString();else body=data;
    let response;
    try {response=await fetcher(url.toString(),{method,headers:{...headers(token),...(body?{"content-type":"application/x-www-form-urlencoded"}:{})},body,
      redirect:"error",signal:AbortSignal.timeout(14000)});}catch{fail("THREADS_API_NETWORK_ERROR");}
    const length=Number(response.headers?.get?.("content-length")||0);
    if(length>2_000_000)fail("THREADS_API_RESPONSE_TOO_LARGE");
    let raw;
    try{raw=await response.text();}catch{fail("THREADS_API_RESPONSE_READ_FAILED");}
    if(raw.length>2_000_000)fail("THREADS_API_RESPONSE_TOO_LARGE");
    let result;
    try{result=JSON.parse(raw);}catch{fail("THREADS_API_BAD_JSON");}
    if(!object(result))fail("THREADS_API_BAD_RESPONSE");
    if(!response.ok){const code=Number.isInteger(result.error?.code)?result.error.code:null;
      fail("THREADS_API_ERROR "+response.status+(code===null?"":" code="+code));}
    return result;
  }
  async function publish(payload){
    const created=await graph("POST","/me/threads",payload);
    if(!digits(String(created.id??"")))fail("THREADS_CONTAINER_INVALID");
    const id=String(created.id);
    for(let attempt=0;attempt<7;attempt++){
      const state=await graph("GET","/"+id,{fields:"status,error_message"});
      if(state.status==="FINISHED"){
        // Never auto-retry this irreversible call on an ambiguous network error.
        try{return {container_id:id,post:await graph("POST","/me/threads_publish",{creation_id:id})};}
        catch{fail("THREADS_PUBLISH_UNKNOWN_CHECK_CONTAINER_"+id);}
      }
      if(["ERROR","EXPIRED"].includes(state.status))fail("THREADS_CONTAINER_"+state.status+"_"+id);
      if(attempt<6)await sleep(5000);
    }
    fail("THREADS_CONTAINER_PENDING_"+id);
  }
  return {graph,publish};
}
async function resolveShare(parsed,fetcher){
  if(parsed.kind!=="share")return parsed;
  let current=parsed.url;
  for(let i=0;i<4;i++){
    let response;
    try{response=await fetcher(current,{method:"HEAD",redirect:"manual",signal:AbortSignal.timeout(8000)});}catch{return null;}
    if(![301,302,303,307,308].includes(response.status))return parseThreadsUrl(current);
    const location=response.headers.get("location");
    if(!location)return null;
    const next=new URL(location,current).toString();
    const safe=parseThreadsUrl(next);
    if(!safe)return null; // Never follow a redirect to another host.
    if(safe.kind==="permalink")return safe;
    current=safe.url;
  }
  return null;
}
export async function callThreadsTool(name,args,{env=process.env,fetcher=fetch,sleep}={}){
  if(!validThreadsCall(name,args))fail("INVALID_THREADS_ARGUMENTS");
  const write=specs.get(name).annotations.readOnlyHint===false;
  if(name==="threads_connection_status")return {module:"threads",owner_oauth_verified:true,
    meta_connected:!!env.OCN_THREADS_ACCESS_TOKEN,writes_enabled:env.OCN_THREADS_WRITES_ENABLED==="true",
    provider:"Meta official Threads Graph API"};
  if(write && env.OCN_THREADS_WRITES_ENABLED!=="true")fail("THREADS_WRITES_DISABLED");
  const c=createThreadsClient({token:env.OCN_THREADS_ACCESS_TOKEN||"",fetcher,sleep});
  const L=args.limit??20, ID=args.media_id;
  switch(name){
    case "threads_search_posts":return c.graph("GET","/keyword_search",{q:args.query,search_type:args.recent===false?"TOP":"RECENT",fields:FIELDS,limit:L});
    case "threads_read_post":return c.graph("GET","/"+ID,{fields:FIELDS});
    case "threads_public_profile_posts":return c.graph("GET","/profile_posts",{username:args.username.replace(/^@/,""),fields:FIELDS,limit:L});
    case "threads_my_posts":return c.graph("GET","/me/threads",{fields:FIELDS,limit:L});
    case "threads_my_replies":return c.graph("GET","/me/replies",{fields:FIELDS,limit:L});
    case "threads_post_replies":return c.graph("GET","/"+ID+"/replies",{fields:FIELDS,limit:L});
    case "threads_post_conversation":return c.graph("GET","/"+ID+"/conversation",{fields:FIELDS,limit:L});
    case "threads_post_insights":return c.graph("GET","/"+ID+"/insights",{metric:"views,likes,replies,reposts,quotes"});
    case "threads_read_shared_url":{
      const parsed=await resolveShare(parseThreadsUrl(args.url),fetcher);
      if(!parsed || parsed.kind!=="permalink")return {found:false,reason:"Share redirect unresolved; canonical post link or media ID required"};
      const posts=await c.graph("GET","/profile_posts",{username:parsed.username,fields:FIELDS,limit:100});
      const match=Array.isArray(posts.data)?posts.data.find(p=>p.shortcode===parsed.shortcode||p.permalink===parsed.url):null;
      return match?{found:true,post:match}:{found:false,canonical_url:parsed.url,reason:"Post not found in permitted first 100 profile results"};
    }
    case "threads_publish_text":return c.publish({media_type:"TEXT",text:args.text});
    case "threads_publish_image":return c.publish({media_type:"IMAGE",image_url:args.image_url,text:args.text||""});
    case "threads_publish_video":return c.publish({media_type:"VIDEO",video_url:args.video_url,text:args.text||""});
    case "threads_reply_to_post":return c.publish({media_type:"TEXT",text:args.text,reply_to_id:ID});
    case "threads_quote_post":return c.publish({media_type:"TEXT",text:args.text,quote_post_id:ID});
    case "threads_repost":return c.graph("POST","/"+ID+"/repost");
    case "threads_manage_reply":return c.graph("POST","/"+args.reply_id+"/manage_reply",{hide:String(args.hide)});
    case "threads_delete_post":return c.graph("DELETE","/"+ID);
    default:fail("UNKNOWN_THREADS_TOOL");
  }
}
