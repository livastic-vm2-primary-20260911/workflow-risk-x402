// Derived from original VM2 Workflow Risk Check (MIT); kept in sync with public source.
import {analyzeWorkflow} from "./analyzer.mjs";
export const MAX_YAML_BYTES=48000;
export const NETWORK="eip155:8453";
export const PRICE_USDC="0.02";
export const USDC_BASE="0x833589fCD6eDb6E08f4C7C32D4f71b54bdA02913";
export const RULESET="workflow-risk-check-v1.2.0";

export function normalizeInput(body){
 if(!body || typeof body!=="object" || Array.isArray(body))
   return {ok:false,status:400,error:"Expected one JSON object."};
 const keys=Object.keys(body);
 if(!keys.includes("workflowYaml") || keys.some(k=>!["workflowYaml","filename"].includes(k)))
   return {ok:false,status:400,error:"Only {workflowYaml:string, filename?:string} is supported."};
 if(typeof body.workflowYaml!=="string"||!body.workflowYaml.trim())
   return {ok:false,status:400,error:"workflowYaml must be a nonempty UTF-8 string."};
 const bytes=Buffer.byteLength(body.workflowYaml,"utf8");
 if(bytes>MAX_YAML_BYTES)
   return {ok:false,status:413,error:"Maximum source YAML size: "+MAX_YAML_BYTES+" UTF-8 bytes."};
 const filename=body.filename??"workflow.yml";
 if(typeof filename!=="string"||filename.length>120||!/^[a-zA-Z0-9_.-]+\.ya?ml$/i.test(filename))
   return {ok:false,status:400,error:"filename must be one simple .yaml or .yml basename (no path)."};
 const result=analyzeWorkflow(body.workflowYaml,filename);
 if(result.error)return {ok:false,status:400,error:result.error};
 const jobs=body.workflowYaml.match(/^[ \t]{0,2}jobs:/gm)||[];
 if(jobs.length>1)return {ok:false,status:400,error:"Expected one workflow YAML document."};
 return {ok:true,report:result,bytes,filename};
}
export function sampleResponse(text){
 const checked=normalizeInput({workflowYaml:text,filename:"pr-check.yml"});
 if(!checked.ok)throw Error("Synthetic sample must be valid for paid API.");
 const {report,bytes}=checked;
 if(report.counts.high!==1||report.counts.medium!==2||report.counts.note!==1)
  throw Error("Pinned sample changed. Revalidate upstream analyzer rules.");
 return {
  paid:false,
  kind:"synthetic_sample",
  ruleset:RULESET,
  input:{filename:"pr-check.yml",bytes,source:"https://github.com/livastic-vm2-primary-20260911/workflow-risk-check/blob/main/examples/synthetic-paid-preflight-sample.md"},
  report,
  disclaimer:"Static heuristic example only; not a real customer security finding or a paid engagement."
 };
}
export function paidResponse(report,bytes,filename){
 return {
  ok:true,
  paid_x402:{currency:"USDC",network:NETWORK,price:PRICE_USDC,claim:"Payment was processed by the external facilitator; confirm settlement independently on Base."},
  ruleset:RULESET,
  input:{filename,bytes},
  report,
  limitations:"Static YAML heuristics only; not a full security audit, penetration test, proof of vulnerability, or GitHub repository permission analysis. Clean scan is not a security guarantee."
 };
}
