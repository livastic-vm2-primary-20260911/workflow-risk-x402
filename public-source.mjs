// GitHub-public-only source loader for a paid GET security-preflight.
// No user-controlled host, redirect, auth header, private repository, or source execution.
import {normalizeInput,MAX_YAML_BYTES} from "./core.mjs";
import {TextDecoder} from "node:util";

const SOURCE_ORIGIN="https://api.github.com";
const DEFAULT={owner:"livastic-vm2-primary-20260911",repo:"workflow-risk-x402",ref:"main",file:"verify.yml"};
const cache=new Map();
const CACHE_MS=8*60*1000;
const MAX_RESPONSE_BYTES=115000;

export function parsePublicSourceQuery(input={}){
 if(!input || typeof input!=="object" || Array.isArray(input))
  return {ok:false,status:400,error:"Expected optional public GitHub source query."};
 const keys=["owner","repo","ref","file"];
 if(Object.keys(input).some(x=>!keys.includes(x)))
  return {ok:false,status:400,error:"Only owner, repo, ref and file query parameters are supported."};
 const p={};
 for(const key of keys){
  if(input[key]!==undefined && typeof input[key]!=="string")
   return {ok:false,status:400,error:"Query parameters must be single strings."};
  p[key]=input[key]??DEFAULT[key];
 }
 if(!/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(p.owner) ||
    !/^[a-z\d][a-z\d_.-]{0,99}$/i.test(p.repo) || p.repo.includes("..") ||
    !/^(?:main|master|[a-f0-9]{40})$/.test(p.ref) ||
    !/^[a-z\d_-][a-z\d_.-]{0,76}\.ya?ml$/i.test(p.file) ||
    p.file.includes(".."))
  return {ok:false,status:400,error:"Use a public GitHub owner/repo, main/master or pinned 40-hex ref, and one simple .yml/.yaml filename."};
 const path="/repos/"+[p.owner,p.repo].map(encodeURIComponent).join("/")+
   "/contents/.github/workflows/"+encodeURIComponent(p.file);
 const canonical=new URL(path,SOURCE_ORIGIN);
 canonical.searchParams.set("ref",p.ref);
 return {ok:true,target:p,url:canonical.toString()};
}

function sourceOrigin(){
 // Only the local mock server under NODE_ENV=test can override the canonical GitHub API.
 const u=process.env.NODE_ENV==="test"?process.env.GITHUB_FIXTURE_BASE:"";
 if(!u)return SOURCE_ORIGIN;
 if(!/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(u))
  throw Error("Test GitHub fixture URL must be localhost only.");
 return u;
}

export async function readPublicWorkflow(query){
 const parsed=parsePublicSourceQuery(query);
 if(!parsed.ok)return parsed;
 const cacheKey=JSON.stringify(parsed.target);
 const cached=cache.get(cacheKey);
 if(cached && Date.now()-cached.at<CACHE_MS)return {ok:true,...cached.result};
 if(cache.size>64)cache.clear();
 let raw;
 try{
  // All caller input is in validated GitHub API path/query segments only.
  const sourceUrl=new URL(parsed.url);
  sourceUrl.protocol=new URL(sourceOrigin()).protocol;
  sourceUrl.host=new URL(sourceOrigin()).host;
  const r=await fetch(sourceUrl,{method:"GET",redirect:"error",headers:{
   Accept:"application/vnd.github+json",
   "User-Agent":"VM2-Workflow-Risk-x402-PublicSource/1",
   "X-GitHub-Api-Version":"2022-11-28"
  },signal:AbortSignal.timeout(10000)});
  if(!r.ok){
   const status=r.status===404?404:r.status===403||r.status===429?503:502;
   return {ok:false,status,error:r.status===404?
     "Requested public workflow not found; no payment required.":
     "Public GitHub source temporarily unavailable; no payment required."};
  }
  const n=Number(r.headers.get("content-length")||0);
  if(n>MAX_RESPONSE_BYTES)return {ok:false,status:413,error:"GitHub source metadata too large; no payment required."};
  if(!r.body)return {ok:false,status:503,error:"Public source unavailable; no payment required."};
  let size=0;const parts=[];const reader=r.body.getReader();
  try{
   while(true){
    const {done,value}=await reader.read();
    if(done)break;
    size+=value.byteLength;
    if(size>MAX_RESPONSE_BYTES){await reader.cancel();return {ok:false,status:413,error:"Source metadata exceeds the safety limit; no payment required."};}
    parts.push(Buffer.from(value));
   }
  }finally{reader.releaseLock();}
  raw=JSON.parse(Buffer.concat(parts).toString("utf8"));
 }catch{
  return {ok:false,status:503,error:"Public GitHub source lookup could not complete; no payment required."};
 }
 if(!raw || raw.type!=="file" || raw.encoding!=="base64" ||
    !/^[a-f0-9]{40}$/.test(String(raw.sha||"")) ||
    !Number.isInteger(raw.size) || raw.size<1 || raw.size>MAX_YAML_BYTES)
  return {ok:false,status:413,error:"Public workflow source is unavailable or too large; no payment required."};
 const encoded=String(raw.content||"").replace(/\s+/g,"");
 if(!encoded||!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))
  return {ok:false,status:422,error:"Unexpected public GitHub file encoding; no payment required."};
 const bytes=Buffer.from(encoded,"base64");
 if(bytes.byteLength!==raw.size || bytes.toString("base64")!==encoded)
  return {ok:false,status:422,error:"Public GitHub file failed byte-integrity check; no payment required."};
 let source;
 try{source=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}
 catch{return {ok:false,status:422,error:"Public workflow is not valid UTF-8; no payment required."};}
 const preflight=normalizeInput({workflowYaml:source,filename:parsed.target.file});
 if(!preflight.ok)
  return {ok:false,status:preflight.status,error:"Public workflow not eligible for scan: "+preflight.error};
 const result={preflight,source:{
  provider:"GitHub public Contents API; no private token used",
  owner:parsed.target.owner,repo:parsed.target.repo,
  ref:parsed.target.ref,path:".github/workflows/"+parsed.target.file,
  githubBlobSha:raw.sha,
  originalUrl:"https://github.com/"+encodeURIComponent(parsed.target.owner)+"/"+
   encodeURIComponent(parsed.target.repo)+"/blob/"+encodeURIComponent(parsed.target.ref)+
   "/.github/workflows/"+encodeURIComponent(parsed.target.file),
  sourceBytes:raw.size
 }};
 cache.set(cacheKey,{at:Date.now(),result});
 return {ok:true,...result};
}
