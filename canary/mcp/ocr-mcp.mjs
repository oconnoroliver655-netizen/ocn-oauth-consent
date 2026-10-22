import {Buffer} from "node:buffer";

// One typed, owner-OAuth-bound local OCR request. Never accepts script text.
const USER = "oliver";
const ADAPTER = "D:\\ChatGPT-Local-Bridge\\maintenance\\ocn-ocr.ps1";
const ROOTS = [
  "D:\\OCN-Services\\OCR\\",
  "D:\\ChatGPT-Local-Bridge\\state\\cloud-admin\\screenshots\\",
  "D:\\Downloads\\",
  "C:\\Users\\oliver\\Downloads\\",
  "C:\\Users\\oliver\\Pictures\\"
];
const EXT = /\.(?:png|jpe?g|webp|bmp)$/i;
const obj = x => x !== null && typeof x === "object" && !Array.isArray(x);

export const OCR_IMAGE_TOOL = {
  name:"ocr_image",
  description:"Run installed DDDD OCR locally on an existing, owner-authorized Windows image. No upload to a cloud OCR service. Supports optional crop rectangle [left,top,right,bottom]. Response is an asynchronous queued command_id/nonce; poll_windows_operation for actual result. OCR output is unverified and must not be trusted for high-stakes decisions. Only files under allowlisted user image/download/screenshot directories.",
  inputSchema:{type:"object",properties:{
    image_path:{type:"string",minLength:8,maxLength:500},
    rect:{type:"array",items:{type:"integer",minimum:0,maximum:100000},minItems:4,maxItems:4}
  },required:["image_path"],additionalProperties:false},
  securitySchemes:[{type:"oauth2",scopes:["openid","email"]}],
  annotations:{readOnlyHint:true,destructiveHint:false,openWorldHint:false}
};

export function validOcrCall(args) {
  if(!obj(args) || Object.keys(args).some(k=>!["image_path","rect"].includes(k))) return false;
  const path=args.image_path;
  if(typeof path!=="string"||path.length<8||path.length>500 ||
    /[\x00-\x1f"<>|*?]/.test(path) || path.includes("/") ||
    !/^[CD]:\\/i.test(path) || !EXT.test(path)) return false;
  // Reject traversal, ADS, and redundant path components.
  if(path.slice(2).includes(":") || path.split("\\").some(x=>!x||x==="."||x==="..")) return false;
  if(!ROOTS.some(root=>path.toLowerCase().startsWith(root.toLowerCase()))) return false;
  const r=args.rect;
  if(r!==undefined && (!Array.isArray(r)||r.length!==4||
    r.some(x=>!Number.isSafeInteger(x)||x<0||x>100000)||
    r[0]>=r[2]||r[1]>=r[3]))return false;
  return true;
}

export function buildOcrRequest(args) {
  if(!validOcrCall(args))throw new TypeError("INVALID_OCR_REQUEST");
  const encoded=Buffer.from(args.image_path,"utf8").toString("base64");
  const script=[
    "$ErrorActionPreference='Stop'",
    "$image=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+encoded+"'))",
    args.rect?
      "& '"+ADAPTER+"' -ImagePath $image -Rect "+args.rect.join(","):
      "& '"+ADAPTER+"' -ImagePath $image",
    "if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}"
  ].join(";\n");
  return {operation:"powershell",payload:{
    run_as:USER,script,timeout_seconds:90
  }};
}
