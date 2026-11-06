import test from "node:test";
import assert from "node:assert/strict";
import {planWindowsRoute,toExistingWindowsCall} from "./route-policy.mjs";
const proof={
 global_nonce:"a".repeat(32),
 global_sha256:"b".repeat(64),
 scope:"machine"
};
test("valid full-read evidence survives the existing signed Windows route",()=>{
 const result=toExistingWindowsCall({
  operation:"powershell",intent:"user",
  payload:{script:"Write-Output ok",_policy_read_gate:proof}
 });
 assert.equal(result.status,"planned");
 assert.equal(result.arguments.payload.run_as,"oliver");
 assert.deepEqual(result.arguments.payload._policy_read_gate,proof);
});
test("malformed guide evidence is refused before dispatch",()=>{
 const result=planWindowsRoute({operation:"powershell",
  payload:{script:"Write-Output ok",
   _policy_read_gate:{...proof,global_nonce:"bad"}}});
 assert.equal(result.status,"refused");
 assert.equal(result.reason,"INVALID_READ_GATE_METADATA");
});
test("project scope requires a project guide read",()=>{
 const result=planWindowsRoute({operation:"powershell",
  payload:{script:"Write-Output ok",
   _policy_read_gate:{...proof,scope:"project",project_root:"D:\\Repo"}}});
 assert.equal(result.reason,"INVALID_READ_GATE_METADATA");
});
test("unsupported PowerShell parameters remain forbidden",()=>{
 const result=planWindowsRoute({operation:"powershell",
  payload:{script:"Write-Output ok",unexpected:"bad"}});
 assert.equal(result.reason,"INVALID_POWERSHELL_FIELD");
});
test("existing route remains compatible until Windows agent gate is activated",()=>{
 const result=planWindowsRoute({operation:"powershell",
  payload:{script:"Write-Output ok"}});
 assert.equal(result.status,"planned");
});
