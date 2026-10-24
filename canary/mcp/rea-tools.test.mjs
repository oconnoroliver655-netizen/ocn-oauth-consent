import test from "node:test";
import assert from "node:assert/strict";
import {REA_TOOLS,validReaCall,buildReaWindowsRequest,callReaTool} from "./rea-tools.mjs";
const ID="0".repeat(32);
const examples=[
 ["rea_status",{}],["rea_list_tools",{filter:"inspect"}],
 ["rea_describe_tool",{tool:"inspect_binary_layout"}],
 ["rea_submit_tool",{tool:"analyze_javascript_application",arguments:{input_path:"D:\\sample",detail:"summary"},lane:"secondary"}],
 ["rea_poll",{request_id:ID}],
 ["rea_chunk",{request_id:ID,chunk_index:3}],
 ["rea_cancel",{request_id:ID}],["rea_list_prompts",{}],
 ["rea_get_prompt",{prompt_name:"investigate_feature",arguments:{feature:"example"},lane:"tertiary"}],
];
test("publish precisely nine owner-bound tools with correct schema",()=>{
 assert.equal(REA_TOOLS.length,9);
 assert.equal(new Set(REA_TOOLS.map(x=>x.name)).size,9);
 for(const tool of REA_TOOLS){
  assert.deepEqual(tool.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(tool.inputSchema.additionalProperties,false);
  assert.equal(tool.annotations.destructiveHint,["rea_submit_tool","rea_cancel"].includes(tool.name));
 }
});
test("all operations validate and dispatch to existing owner session",()=>{
 for(const [name,args] of examples){
  assert.equal(validReaCall(name,args),true,name);
  const request=buildReaWindowsRequest(name,args);
  assert.equal(request.operation,"powershell");
  assert.equal(request.payload.run_as,"oliver");
  assert.match(request.payload.script,/ConvertFrom-Json/);
  assert.match(request.payload.script,/rea-ocn\.ps1/);
  assert.equal(request.payload.timeout_seconds,25);
  assert.equal(request.payload.script.includes(args.tool||"VERY_UNLIKELY_INPUT"),false);
 }
});
test("PowerShell never contains user-supplied unescaped text",()=>{
 const injection="'; Remove-Item C:\\Users\\oliver\\* -Recurse #";
 const req=buildReaWindowsRequest("rea_submit_tool",{tool:"inspect_binary_layout",arguments:{path:injection,detail:"summary"}});
 assert.equal(req.payload.script.includes(injection),false);
 assert.equal(req.payload.script.includes("Remove-Item"),false);
 assert.equal(req.payload.script.includes("https://"),false);
 const enc=req.payload.script.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/)[1];
 const parsed=JSON.parse(Buffer.from(enc,"base64").toString("utf8"));
 assert.equal(parsed.Mode,"Submit");
 assert.deepEqual(JSON.parse(parsed.ArgumentsJson),{path:injection,detail:"summary"});
});
test("reject malformed IDs, invalid tools, lanes, extra and oversized data",()=>{
 const invalid=[
 ["rea_submit_tool",{tool:"a; Write-Host hacked",arguments:{}}],
 ["rea_submit_tool",{tool:"valid",arguments:[]}],
 ["rea_submit_tool",{tool:"valid",arguments:{},lane:"system"}],
 ["rea_poll",{request_id:"../../../secret"}],
 ["rea_chunk",{request_id:ID,chunk_index:-1}],
 ["rea_cancel",{request_id:"X".repeat(32)}],
 ["rea_status",{extra:"hidden"}],
 ["rea_submit_tool",{tool:"valid",arguments:{blob:"x".repeat(9800)}}],
 ["rea_get_prompt",{prompt_name:"investigate_feature",arguments:null}],
 ];
 for(const [name,args] of invalid)assert.equal(validReaCall(name,args),false,name);
});
test("preserve signed owner bearer and queued receipt, not completed status",async()=>{
 let observed;
 const bearer="Bearer signed-owner-token";
 const reply={value:{command_id:123,nonce:"a".repeat(32),status:"queued"}};
 const fake=async (...args)=>{observed=args;return reply};
 const result=await callReaTool(bearer,"rea_submit_tool",{tool:"inspect_binary_layout",arguments:{path:"D:\\fixture.exe"}},fake);
 assert.deepEqual(result,reply);
 assert.equal(observed[0],bearer);
 assert.equal(observed[1],"submit_windows_operation");
 assert.equal(observed[2].operation,"powershell");
 const bad=await callReaTool(bearer,"rea_submit_tool",{tool:"abc'",arguments:{}},fake);
 assert.match(bad.error,/Invalid REA/);
});
