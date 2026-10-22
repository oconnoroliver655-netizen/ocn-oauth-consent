import test from "node:test";
import assert from "node:assert/strict";
import {validOcrCall,buildOcrRequest,OCR_IMAGE_TOOL} from "./ocr-mcp.mjs";

const image="D:\\OCN-Services\\OCR\\test_ocr.png";
test("tool is typed and owner-oauth protected",()=>{
  assert.equal(OCR_IMAGE_TOOL.name,"ocr_image");
  assert.deepEqual(OCR_IMAGE_TOOL.inputSchema.required,["image_path"]);
  assert.equal(OCR_IMAGE_TOOL.securitySchemes[0].type,"oauth2");
});
test("allowlisted image and optional crop",()=>{
  assert.equal(validOcrCall({image_path:image}),true);
  assert.equal(validOcrCall({image_path:image,rect:[0,0,100,40]}),true);
  const req=buildOcrRequest({image_path:image,rect:[0,0,100,40]});
  assert.equal(req.operation,"powershell");
  assert.equal(req.payload.run_as,"oliver");
  assert.match(req.payload.script,/FromBase64String/);
  assert.match(req.payload.script,/-Rect 0,0,100,40/);
  assert.ok(!req.payload.script.includes("test_ocr.png"));
});
test("reject traversal, UNC, executable, ADS, and injected fields",()=>{
  for(const path of [
    "D:\\OCN-Services\\OCR\\..\\secret.png",
    "D:\\OCN-Services\\OCR\\secret.png:stream",
    "\\\\server\\share\\pic.png",
    "C:\\Windows\\test.png",
    "D:\\Downloads\\tool.ps1",
    "D:\\Downloads\\a.png;Remove-Item",
    "D:\\Downloads\\a.png\\..\\b.png"
  ]) assert.equal(validOcrCall({image_path:path}),false,path);
  assert.equal(validOcrCall({image_path:image,script:"bad"}),false);
  assert.equal(validOcrCall({image_path:image,rect:[20,5,15,10]}),false);
});
