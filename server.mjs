import express from "express";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {paymentMiddleware} from "@x402/express";
import {x402ResourceServer,HTTPFacilitatorClient} from "@x402/core/server";
import {ExactEvmScheme} from "@x402/evm/exact/server";
import {declareDiscoveryExtension} from "@x402/extensions/bazaar";
import {normalizeInput,sampleResponse,paidResponse,MAX_YAML_BYTES,RULESET,PRICE_USDC,USDC_BASE,NETWORK} from "./core.mjs";

const DIR=path.dirname(fileURLToPath(import.meta.url));
const PORT=Number(process.env.PORT||8737);
const HOST=process.env.HOST||"127.0.0.1";
const PRICE="$"+PRICE_USDC;
const PAY_TO=process.env.PAY_TO||"";
const FACILITATOR_URL=process.env.FACILITATOR_URL||"https://facilitator.openx402.ai";
const PUBLIC_ORIGIN=process.env.PUBLIC_ORIGIN||(process.env.NODE_ENV==="test"?"http://127.0.0.1:"+PORT:"");
if(!Number.isInteger(PORT)||PORT<1024||PORT>65535)throw Error("PORT must be an integer 1024–65535");
if(!["0.0.0.0","127.0.0.1"].includes(HOST))throw Error("HOST must be explicit loopback or all interfaces");
if(!/^0x[a-fA-F0-9]{40}$/.test(PAY_TO))throw Error("PAY_TO must be an authorized, configured EVM Base recipient address; no default wallet");
if(!/^https:\/\//.test(FACILITATOR_URL) && !(process.env.NODE_ENV==="test" && /^http:\/\/127\.0\.0\.1:\d+$/.test(FACILITATOR_URL)))
 throw Error("External facilitator must use HTTPS; localhost http only allowed for test fixture");
if(!PUBLIC_ORIGIN || !/^https:\/\/[a-z0-9.-]+$/.test(PUBLIC_ORIGIN) &&
 !(process.env.NODE_ENV==="test" && /^http:\/\/127\.0\.0\.1:\d+$/.test(PUBLIC_ORIGIN)))
 throw Error("PUBLIC_ORIGIN must be explicitly set to canonical HTTPS host in production");

const SAMPLE_YAML=fs.readFileSync(path.join(DIR,"examples/pr-check.yml"),"utf8");
const SAMPLE_REPORT=sampleResponse(SAMPLE_YAML);
const facilitator=new HTTPFacilitatorClient({url:FACILITATOR_URL});
const resourceServer=new x402ResourceServer(facilitator);
resourceServer.register("eip155:*",new ExactEvmScheme());
await resourceServer.initialize();
const payFields={
  protocol:"x402-v2",
  amountUSDC:PRICE_USDC,
  amountAtomicUSDC:"20000",
  network:NETWORK,
  asset:USDC_BASE,
  recipient:PAY_TO,
  facilitator:FACILITATOR_URL
};
const model={type:"object",properties:{
 workflowYaml:{type:"string",maxLength:MAX_YAML_BYTES,description:"One GitHub Actions YAML workflow, UTF-8. No private YAML, tokens or secrets."},
 filename:{type:"string",description:"Short .yml/.yaml basename, optional"}
},required:["workflowYaml"]};
const example={
  workflowYaml:SAMPLE_YAML,
  filename:"pr-check.yml"
};
const routes={
  "POST /v1/check":{
    accepts:{scheme:"exact",price:PRICE,network:NETWORK,payTo:PAY_TO},
    description:"Pay $0.02 USDC on Base to receive a source-line GitHub Actions static YAML preflight. Detects risky permission scope, mutable refs, pull_request_target trust boundaries and untrusted expressions. No private repos or execution.",
    mimeType:"application/json",
    extensions:declareDiscoveryExtension({
      method:"POST",bodyType:"json",input:example,
      inputSchema:model,output:{example:{ok:true,ruleset:RULESET,report:{counts:{high:1,medium:2,note:1},findings:[{id:"TARGET_UNTRUSTED_CODE",severity:"high",line:8}]}}}
    })
  }
};
const payment=paymentMiddleware(routes,resourceServer,undefined,undefined,false);

function makeDiscovery(){
 return {
  spec:{
   openapi:"3.1.0",
   info:{
    title:"Workflow Risk Check — x402 paid YAML preflight",
    version:"0.1.0",
    description:"AI-assisted transparent GitHub Actions static preflight, using original MIT heuristics. Valid YAML requests billed at 0.02 USDC; syntactically invalid requests rejected before payment. Actual paid transaction not yet live-settlement-tested.",
    contact:{name:"VM2 Workflow Guard",url:"https://github.com/livastic-vm2-primary-20260911/workflow-risk-x402"}
   },
   servers:[{url:PUBLIC_ORIGIN}],
   components:{
    securitySchemes:{x402Payment:{type:"apiKey",in:"header",name:"PAYMENT-SIGNATURE",description:"Buyer-signed x402 v2 EIP-3009 USDC payment; do not send wallet secrets."}},
    schemas:{
     CheckInput:model,
     CheckResult:{type:"object",properties:{ok:{type:"boolean"},ruleset:{type:"string"},report:{type:"object"},paid_x402:{type:"object"}}}
    }
   },
   paths:{
    "/health":{get:{summary:"Free readiness status",responses:{"200":{description:"Service alive"}}}},
    "/v1/docs":{get:{summary:"Free payment and privacy terms",responses:{"200":{description:"Documentation"}}}},
    "/v1/sample":{get:{summary:"Free reproducible synthetic findings",responses:{"200":{description:"Synthetic report"}}}},
    "/v1/check":{post:{
      summary:"GitHub Actions YAML static scan — x402 $0.02 USDC",
      operationId:"checkGithubActionsWorkflow",
      description:"One validated GitHub Actions workflow (up to 48k UTF-8 bytes). Fixed-price paid finding report, NOT a security audit. Buyer sends a signed x402 v2 Base USDC authorization.",
      "x-payment-info":{protocols:["x402"],price:{mode:"fixed",currency:"USDC",amount:PRICE_USDC},network:NETWORK,asset:USDC_BASE,payTo:PAY_TO},
      security:[{x402Payment:[]}],
      requestBody:{required:true,content:{"application/json":{schema:{$ref:"#/components/schemas/CheckInput"},example}}},
      responses:{
       "200":{description:"Payment-verified static finding report",content:{"application/json":{schema:{$ref:"#/components/schemas/CheckResult"}}}},
       "400":{description:"Invalid YAML/JSON input rejected before payment"},
       "402":{description:"x402 v2 Base USDC payment required",headers:{"PAYMENT-REQUIRED":{description:"Base64 x402 v2 payment requirements",schema:{type:"string"}}}},
       "413":{description:"Workflow too large (rejected before payment)"},
       "429":{description:"Rate limited"},
       "503":{description:"Service temporarily unavailable"}
      }
    }}
   },
   "x-discovery":{provider:"VM2 Workflow Guard",freeDemo:"https://livastic-vm2-primary-20260911.github.io/workflow-risk-check/",upstreamRuleSource:"https://github.com/livastic-vm2-primary-20260911/workflow-risk-check",realPaidSettlementVerified:false}
  },
  wellKnown:{
   version:1,
   resources:[PUBLIC_ORIGIN+"/v1/check"],
   description:"Fixed-price x402 Base USDC 0.02 for 1 source-line GitHub Actions YAML preflight. POST {workflowYaml:'...'} with x402 v2 authorization. First receive HTTP 402. Free example /v1/sample. Not a security certificate.",
   paymentExperience:"Quote tested, full onchain settlement not yet independently verified."
  }
 };
}
const {spec:openapi,wellKnown}=makeDiscovery();
const app=express();
app.disable("x-powered-by");
app.set("trust proxy",HOST==="0.0.0.0"?1:"loopback");
app.use((req,res,next)=>{
 res.setHeader("Access-Control-Allow-Origin","*");
 res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
 res.setHeader("Access-Control-Allow-Headers","Content-Type,PAYMENT-SIGNATURE,PAYMENT-RESPONSE");
 res.setHeader("Access-Control-Expose-Headers","PAYMENT-REQUIRED,PAYMENT-RESPONSE");
 res.setHeader("Cache-Control","no-store");
 res.setHeader("X-Content-Type-Options","nosniff");
 res.setHeader("Referrer-Policy","no-referrer");
 res.setHeader("X-Frame-Options","DENY");
 next();
});
const traffic=new Map();
let inFlight=0;
app.use((req,res,next)=>{
 const key=req.ip||"unknown";
 const now=Date.now();
 let item=traffic.get(key);
 if(!item||now-item.from>60000)item={from:now,count:0};
 item.count++;
 traffic.set(key,item);
 if(traffic.size>5000)for(const [k,v] of traffic)if(now-v.from>60000)traffic.delete(k);
 if(item.count>70){res.setHeader("Retry-After","60");return res.status(429).json({error:"Too many requests; try later."});}
 next();
});
app.get("/",(_req,res)=>res.redirect(302,"/v1/docs"));
app.get("/health",(_req,res)=>res.json({ok:true,name:"VM2 Workflow Risk Check x402",ruleset:RULESET,paidRoute:"POST /v1/check",network:NETWORK,feeUSDC:PRICE_USDC}));
app.get("/v1/docs",(_req,res)=>res.json({
 name:"VM2 Workflow Risk Check x402",
 status:"Beta — real on-chain payment settlement not yet exercised",
 payment:payFields,
 paid:{method:"POST",path:"/v1/check",contentType:"application/json",body:model},
 free:{"/health":"Service health","/v1/sample":"Original synthetic reproducible sample","/openapi.json":"OpenAPI 3.1 with payment info"},
 limits:{utf8WorkflowBytes:MAX_YAML_BYTES,requestsPerMinute:70,concurrentChecks:2},
 privacy:"Server-side processing of explicitly provided YAML only; no application-level persistence, analytics, IP/address or payment-header logging. Hosting platform and external x402 facilitator have separate logs. Do not submit secrets or private code.",
 caution:"Heuristic triage is NOT formal security advice, security certification, penetration testing, or evidence of a real security vulnerability. No verified paying customers or settlement yet.",
 freeLocalTool:"https://livastic-vm2-primary-20260911.github.io/workflow-risk-check/"
}));
app.get("/v1/sample",(_req,res)=>res.json(SAMPLE_REPORT));
app.get("/openapi.json",(_req,res)=>res.json(openapi));
app.get(["/.well-known/x402","/.well-known/x402.json"],(_req,res)=>res.json(wellKnown));
app.get("/robots.txt",(_req,res)=>res.type("text/plain").send("User-agent: *\nDisallow: /v1/check\nAllow: /v1/docs\nAllow: /v1/sample\n"));
app.options("/v1/check",(_req,res)=>res.status(204).end());
app.post("/v1/check",express.json({limit:"70kb"}),(req,res,next)=>{
 if(!req.is("application/json"))return res.status(415).json({charged:false,error:"Use application/json."});
 const preflight=normalizeInput(req.body);
 if(!preflight.ok)return res.status(preflight.status).json({charged:false,error:preflight.error});
 if(inFlight>=2)return res.status(503).json({charged:false,error:"Busy: no payment accepted. Retry later."});
 inFlight++;
 res.on("finish",()=>{inFlight=Math.max(0,inFlight-1);});
 res.on("close",()=>{if(!res.writableEnded)inFlight=Math.max(0,inFlight-1);});
 res.locals.preflight=preflight;
 next();
},payment,(req,res)=>{
 const {report,bytes,filename}=res.locals.preflight;
 res.status(200).json(paidResponse(report,bytes,filename));
});
app.use((err,_req,res,_next)=>{
 if(res.headersSent)return;
 const isHuge=err?.type==="entity.too.large";
 res.status(isHuge?413:400).json({ok:false,charged:false,error:isHuge?"JSON body exceeds 70 KiB.":"Malformed JSON request."});
});
const server=app.listen(PORT,HOST,()=>console.log("VM2 Workflow Risk x402 server ready on "+HOST+":"+PORT+"; settlement not yet live-verified"));
process.on("SIGTERM",()=>server.close(()=>process.exit(0)));
