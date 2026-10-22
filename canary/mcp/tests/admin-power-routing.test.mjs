import test from "node:test";
import assert from "node:assert/strict";
import {ADMIN_POWERSHELL_TOOL,validAdminPowerShellCall,adminPowerShellToWindowsCall,validWindowsCall} from "../windows-tools.mjs";

test("administrator operation is discoverable and owner OAuth-bound",()=>{
  assert.equal(ADMIN_POWERSHELL_TOOL.name,"submit_admin_powershell");
  assert.deepEqual(ADMIN_POWERSHELL_TOOL.securitySchemes,[{type:"oauth2",scopes:["openid","email"]}]);
  assert.equal(ADMIN_POWERSHELL_TOOL.annotations.destructiveHint,true);
  assert.match(ADMIN_POWERSHELL_TOOL.description,/Cloud Admin Agent/);
});
test("admin alias maps only to existing signed SYSTEM PowerShell route",()=>{
  const cmd=adminPowerShellToWindowsCall({script:"whoami /user",timeout_seconds:20});
  assert.deepEqual(cmd,{operation:"powershell",payload:{script:"whoami /user",run_as:"system",timeout_seconds:20}});
  assert.equal(validWindowsCall("submit_windows_operation",cmd),true);
});
test("reject arbitrary selector, malformed argument and oversized script",()=>{
  for(const bad of [{},{script:"  "},{script:"echo 1",run_as:"oliver"},
    {script:"echo 1",run_as:"system"},{script:"echo 1",extra:true},
    {script:"echo 1",timeout_seconds:0},{script:"echo 1",timeout_seconds:1801},
    {script:"echo 1",timeout_seconds:"30"},{script:"echo 1",cwd:42},
    {script:"x".repeat(131073)},null,[]]){
    assert.equal(validAdminPowerShellCall(bad),false);
    assert.throws(()=>adminPowerShellToWindowsCall(bad),TypeError);
  }
});
test("script is preserved verbatim and caller cannot choose execution identity",()=>{
  const payload=adminPowerShellToWindowsCall({script:"Write-Output 'ok'",cwd:"C:\\\\Windows"});
  assert.equal(payload.payload.run_as,"system");
  assert.equal(payload.payload.script,"Write-Output 'ok'");
  assert.equal(payload.payload.cwd,"C:\\\\Windows");
});
