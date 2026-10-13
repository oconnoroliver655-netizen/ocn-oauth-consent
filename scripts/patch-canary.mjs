// Stage-only patcher. Never starts Render, publishes code, or accesses credentials.
import fs from 'node:fs';
import path from 'node:path';
const input=process.argv[2],output=process.argv[3];
if(!input||!output||path.resolve(input)===path.resolve(output)){
  console.error('Usage: node patch-canary.mjs <existing-server.mjs> <staged-server.mjs>');
  process.exit(2);
}
let source=fs.readFileSync(input,'utf8');
const marker='  const oauthProbePath = req.url === "/mcp-oauth";';
if(!source.includes(marker) || !source.includes('if (!meta) return respond(res,503,') ||
  !source.includes('if (req.headers.origin!==undefined)') ||
  source.includes('/mcp-ci-guard') ||
  !source.includes('export function start(')){
  throw new Error('Current canary structure differs from reviewed source; refusing modification');
}
const imp='import {makeHandler} from "./pr529-ci-guard.mjs";\n';
if(source.includes(imp))throw new Error('Already imported');
source=imp+source;
source=source.replace(marker,`  // Independent owner-authenticated route: no changes to ping or health paths.\n  if (req.url === "/mcp-ci-guard")\n    return makeHandler({origin:ORIGIN})(req,res);\n${marker}`);
fs.mkdirSync(path.dirname(output),{recursive:true});
fs.writeFileSync(output,source,{flag:'wx'});
console.log('Staged patched canary, not deployed:',output);
