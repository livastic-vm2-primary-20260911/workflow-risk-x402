/**
 * A small stateless Streamable-HTTP MCP surface around the ORIGINAL offline
 * YAML analyzer. The existing x402 REST routes and facilitator are unchanged.
 *
 * This server never reads wallet keys, performs payment, accesses GitHub,
 * persists input, or claims a valid quote was settled. A caller/marketplace
 * handles commercial terms outside this read-only origin tool.
 */
import {McpServer} from "@modelcontextprotocol/sdk/server/mcp.js";
import {StreamableHTTPServerTransport} from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import * as z from "zod/v4";
import {normalizeInput,RULESET,MAX_YAML_BYTES} from "./core.mjs";

// Keep original tool ID for existing clients while making the genuinely FREE
// origin response a coarse preview only. Detailed reports are paid x402 REST.
const TOOL="analyze_github_actions_yaml";
const PAID_ROUTES=Object.freeze({
 short:"GET https://vm2-workflow-x402.onrender.com/v1/quick-public-workflow — 0.005 native Base Circle USDC (public GitHub source) or POST /v1/quick-check (supplied public YAML)",
 full:"POST https://vm2-workflow-x402.onrender.com/v1/check or GET /v1/public-workflow — 0.02 native Base Circle USDC"
});
function coarseFreePreview(validated){
 const {report,bytes,filename}=validated;
 if(!report || !report.counts || !Array.isArray(report.findings))throw Error("Scanner did not produce expected free risk level");
 const high=report.counts.high||0, medium=report.counts.medium||0, note=report.counts.note||0;
 const level=high>0?"HIGH":medium>0?"MEDIUM":note>0?"NOTE":"NONE_OBSERVED";
 return {
  ok:true,product:"Free MCP coarse workflow preflight",
  ruleset:RULESET,checked:{filename,utf8Bytes:bytes},
  riskLevel:level,flagged:(high+medium+note)>0,
  // Never expose a report, counts, finding IDs, source lines, input source
  // or detailed fixes through the genuinely no-cost MCP origin.
  availablePaidRoutes:PAID_ROUTES,
  billing:"This MCP origin preview is free. Paid REST routes charge only when an independent buyer explicitly authorizes a real x402 v2 transfer; this MCP tool never signs, approves, or pays.",
  limits:"Coarse heuristics only. NONE_OBSERVED is never a clean-bill-of-health or audit. Never send private YAML, keys, secrets, or private repositories."
 };
}

const LIMIT=4;
let active=0;
const hits=new Map();
function rateAllowed(ip){
 const key=String(ip||"unknown").slice(0,120);
 const now=Date.now();
 const old=hits.get(key);
 const item=old&&now-old.start<60_000?old:{start:now,count:0};
 item.count++;
 hits.set(key,item);
 if(hits.size>120){
  for(const [k,v] of hits){if(now-v.start>60_000)hits.delete(k);}
  if(hits.size>120)hits.delete(hits.keys().next().value);
 }
 return item.count<=30;
}
export function createMcpServer(){
 const server=new McpServer({name:"onecursor-workflow-risk",version:"0.3.0"});
 server.registerTool(
  TOOL,{
   title:"Static GitHub Actions YAML Risk Preflight",
   description:"FREE origin MCP coarse risk-level alert only: HIGH/MEDIUM/NOTE/NONE_OBSERVED for nonsecret public GitHub Actions YAML. It does NOT return severity counts, actionable risk IDs/lines or a full report. To get a 3-signal report, an independent buyer may separately authorize 0.005 native Base Circle USDC on /v1/quick-public-workflow or /v1/quick-check; full report on /v1/public-workflow or /v1/check costs 0.02. Do not submit secrets or private workflows; no wallet, signature, or payment by this free tool. No audit guarantee.",
   inputSchema:{
    workflowYaml:z.string().min(1).max(MAX_YAML_BYTES).describe("One non-secret GitHub Actions YAML document; no tokens/credentials"),
    filename:z.string().max(120).optional().describe("One simple filename ending in .yml or .yaml")
   }
  },
  async({workflowYaml,filename})=>{
   const result=normalizeInput({workflowYaml,filename:filename||"workflow.yml"});
   if(!result.ok){
    return {isError:true,content:[{type:"text",text:JSON.stringify({ok:false,chargedByOrigin:false,error:result.error})}]};
   }
   const value=coarseFreePreview(result);
   return {content:[{type:"text",text:JSON.stringify(value)}],structuredContent:value};
  }
 );
 return server;
}
export function mcpHandler(){
 return async(req,res)=>{
  if(req.is("application/json")===false)return res.status(415).json({error:"MCP JSON-RPC requires application/json"});
  if(active>=LIMIT || !rateAllowed(req.ip))return res.status(429).json({error:"MCP is busy; no call accepted"});
  active++;
  const transport=new StreamableHTTPServerTransport({
    sessionIdGenerator:undefined,enableJsonResponse:true
  });
  let server;
  try{
   server=createMcpServer();
   res.on("close",()=>{void transport.close().catch(()=>{});});
   await server.connect(transport);
   await transport.handleRequest(req,res,req.body);
  }catch{
   if(!res.headersSent)res.status(500).json({error:"MCP could not process the request"});
   else if(!res.writableEnded)res.end();
  }finally{
   active=Math.max(0,active-1);
  }
 };
}
