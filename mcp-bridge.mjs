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

const TOOL="analyze_github_actions_yaml";
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
 const server=new McpServer({name:"onecursor-workflow-risk",version:"0.2.0"});
 server.registerTool(
  TOOL,{
   title:"Static GitHub Actions YAML Risk Preflight",
   description:"Read-only, offline AI-agent-friendly GitHub Actions YAML policy review. Finds broad token permissions, mutable action refs, pull_request_target boundaries and injected untrusted expressions. Input ONLY public/synthetic workflow YAML; maximum 48k UTF-8 bytes. Not a penetration test or security certification. Marketplace payment (if any) is handled by the caller; this tool never signs, pays, or claims a Base USDC transaction happened.",
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
   const value={
    ok:true,ruleset:RULESET,checked:{filename:result.filename,utf8Bytes:result.bytes},
    report:result.report,
    payment:"No payment or on-chain settlement is verified by this origin MCP tool. If a marketplace charges the caller, inspect its receipt independently.",
    limits:"Offline static heuristics only; not a security audit, proof of compromise, or guaranteed clean workflow."
   };
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
