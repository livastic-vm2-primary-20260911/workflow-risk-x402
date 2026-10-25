import express from "express";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {paymentMiddleware} from "@x402/express";
import {x402ResourceServer,HTTPFacilitatorClient} from "@x402/core/server";
import {ExactEvmScheme} from "@x402/evm/exact/server";
import {declareDiscoveryExtension} from "@x402/extensions/bazaar";
import {normalizeInput,sampleResponse,paidResponse,MAX_YAML_BYTES,RULESET,PRICE_USDC,USDC_BASE,NETWORK} from "./core.mjs";
import {readPublicWorkflow,readBundledPublicWorkflow} from "./public-source.mjs";
import {mcpHandler} from "./mcp-bridge.mjs";
import {quickResponse,QUICK_PRICE_USDC} from "./quick-check.mjs";

const DIR=path.dirname(fileURLToPath(import.meta.url));
const PORT=Number(process.env.PORT||8737);
const HOST=process.env.HOST||"127.0.0.1";
const PRICE="$"+PRICE_USDC;
const QUICK_PRICE="$"+QUICK_PRICE_USDC;
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
const PINNED_PUBLIC_SAMPLE=readBundledPublicWorkflow();
if(!PINNED_PUBLIC_SAMPLE.ok)throw Error("Pinned public GitHub source invalid; refuse to advertise paid discovery.");
const PUBLIC_OUTPUT_EXAMPLE={
 ...paidResponse(PINNED_PUBLIC_SAMPLE.preflight.report,
                 PINNED_PUBLIC_SAMPLE.preflight.bytes,
                 PINNED_PUBLIC_SAMPLE.preflight.filename),
 source:PINNED_PUBLIC_SAMPLE.source,
 disclosure:"This is an illustrative paid-response shape derived from an original pinned public YAML. It is NOT a paid customer order, an onchain receipt or a certification."
};
const QUICK_PUBLIC_OUTPUT_EXAMPLE={
 ...quickResponse(PINNED_PUBLIC_SAMPLE.preflight),
 source:PINNED_PUBLIC_SAMPLE.source,
 disclosure:"Illustrative 0.005 USDC short report shape from already-public pinned source; NOT a buyer order or on-chain receipt."
};
const PUBLIC_QUERY_SCHEMA={properties:{
 owner:{type:"string",description:"Optional existing public GitHub username or organization; defaults to our own publisher."},
 repo:{type:"string",description:"Optional public GitHub repository; defaults to workflow-risk-x402."},
 ref:{type:"string",description:"Optional main, master or exactly 40 lowercase hex Git commit; defaults to pinned deployed source."},
 file:{type:"string",description:"Optional simple .yml or .yaml filename under .github/workflows; defaults to verify.yml."}
},additionalProperties:false};
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
  "GET /v1/quick-public-workflow":{
    accepts:{scheme:"exact",price:QUICK_PRICE,network:NETWORK,payTo:PAY_TO},
    description:"Low-cost, GET-only $0.005 native Circle USDC Base source-line risk-count and top-three-signal brief on an anonymously readable public GitHub Actions YAML workflow. Default safely pins publisher's own versioned workflow. No buyer credentials, source uploads or arbitrary hosts.",
    mimeType:"application/json",
    extensions:declareDiscoveryExtension({
      method:"GET",input:{},inputSchema:PUBLIC_QUERY_SCHEMA,
      output:{example:QUICK_PUBLIC_OUTPUT_EXAMPLE,schema:{properties:{
        ok:{type:"boolean"},ruleset:{type:"string"},product:{type:"string"},
        counts:{type:"object"},topSignals:{type:"array",items:{type:"object"}},
        input:{type:"object"},source:{type:"object"},paid_x402:{type:"object"}
      }}}
    })
  },
  "POST /v1/quick-check":{
    accepts:{scheme:"exact",price:QUICK_PRICE,network:NETWORK,payTo:PAY_TO},
    description:"Pay $0.005 native Circle USDC on Base for a low-cost short GitHub Actions YAML static security-risk summary: source-line risk counts and up to three signal IDs/lines. Not a full review. Input is one public or nonsecret workflowYaml JSON document.",
    mimeType:"application/json",
    extensions:declareDiscoveryExtension({
      method:"POST",bodyType:"json",input:example,
      inputSchema:model,output:{example:{
        ok:true,product:"VM2 Quick Workflow Risk",ruleset:RULESET,
        counts:{high:1,medium:2,note:1},
        topSignals:[{id:"TARGET_UNTRUSTED_CODE",severity:"high",line:8}],
        limitations:"Example only; not a real paid customer order."
      }}
    })
  },
  "POST /v1/check":{
    accepts:{scheme:"exact",price:PRICE,network:NETWORK,payTo:PAY_TO},
    description:"Pay $0.02 USDC on Base to receive a source-line GitHub Actions static YAML preflight. Detects risky permission scope, mutable refs, pull_request_target trust boundaries and untrusted expressions. No private repos or execution.",
    mimeType:"application/json",
    extensions:declareDiscoveryExtension({
      method:"POST",bodyType:"json",input:example,
      inputSchema:model,output:{example:{ok:true,ruleset:RULESET,report:{counts:{high:1,medium:2,note:1},findings:[{id:"TARGET_UNTRUSTED_CODE",severity:"high",line:8}]}}}
    })
  },
  "GET /v1/public-workflow":{
    accepts:{scheme:"exact",price:PRICE,network:NETWORK,payTo:PAY_TO},
    description:"One public GitHub Actions source-file static preflight, read anonymously from GitHub Contents API. No buyer-supplied host, no code execution, no private repository or credentials.",
    mimeType:"application/json",
    extensions:declareDiscoveryExtension({
      method:"GET",input:{},inputSchema:PUBLIC_QUERY_SCHEMA,
      output:{example:PUBLIC_OUTPUT_EXAMPLE,schema:{properties:{
        ok:{type:"boolean"},ruleset:{type:"string"},input:{type:"object"},
        report:{type:"object"},source:{type:"object"},paid_x402:{type:"object"}
      }}}
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
    version:"0.2.0",
    description:"AI-assisted transparent GitHub Actions static preflight, using original MIT heuristics. Valid YAML requests billed at 0.02 USDC; syntactically invalid requests rejected before payment. Actual paid transaction not yet live-settlement-tested. New quick $0.005 summary is separate from the $0.02 full review.",
    "x-guidance":"Read free /v1/docs and /v1/sample first. POST /v1/quick-check delivers only three top signals at 0.005 USDC. GET /v1/quick-public-workflow offers an exactly priced 0.005 GET-only 3-signal report for agent marketplaces. GET /v1/public-workflow performs a paid static review of one publicly readable GitHub Actions YAML, defaulting to our own exact Git-blob-pinned published workflow (optional owner/repo/ref/file query). POST /v1/check requires a valid JSON workflowYaml and optional filename (up to 48k UTF-8 bytes). Paid endpoints return HTTP 402 until an external buyer independently authorizes exact 0.005 or 0.02 native Base Circle USDC x402 v2 payment. Never send credentials or private YAML. No service or customer should infer that a 402 quote or example response was a completed sale. Static heuristic triage, not a security audit or trading advice.",
    contact:{name:"VM2 Workflow Guard",url:"https://github.com/livastic-vm2-primary-20260911/workflow-risk-x402"}
   },
   servers:[{url:PUBLIC_ORIGIN}],
   components:{
    securitySchemes:{x402Payment:{type:"apiKey",in:"header",name:"PAYMENT-SIGNATURE",description:"Buyer-signed x402 v2 EIP-3009 USDC payment; do not send wallet secrets."}},
    schemas:{
     CheckInput:model,
     CheckResult:{type:"object",properties:{ok:{type:"boolean"},ruleset:{type:"string"},report:{type:"object"},paid_x402:{type:"object"}}},
     QuickCheckResult:{type:"object",properties:{ok:{type:"boolean"},product:{type:"string"},counts:{type:"object"},topSignals:{type:"array",items:{type:"object"}},paid_x402:{type:"object"}}},
     PublicWorkflowResult:{type:"object",properties:{ok:{type:"boolean"},ruleset:{type:"string"},report:{type:"object"},paid_x402:{type:"object"},input:{type:"object"},source:{type:"object",properties:{provider:{type:"string"},githubBlobSha:{type:"string"},originalUrl:{type:"string"},sourceBytes:{type:"integer"}},required:["provider","githubBlobSha","originalUrl","sourceBytes"]},disclosure:{type:"string"}},required:["ok","ruleset","report","paid_x402","input","source","disclosure"]}
    }
   },
   paths:{
    "/health":{get:{summary:"Free readiness status",security:[],responses:{"200":{description:"Service alive"}}}},
    "/v1/docs":{get:{summary:"Free payment and privacy terms",security:[],responses:{"200":{description:"Documentation"}}}},
    "/v1/sample":{get:{summary:"Free reproducible synthetic findings",security:[],responses:{"200":{description:"Synthetic report"}}}},
    "/v1/quick-public-workflow":{get:{
      summary:"GET-only $0.005 USDC native Base public GitHub Actions short security-risk brief",
      operationId:"quickPreflightPublicGithubWorkflow",
      description:"Paid short static YAML risk count and up to three source-line signal IDs; fetch only an anonymously readable public GitHub YAML from a fixed GitHub API host, defaulting to publisher's pinned source. No user-supplied host or private token, no execution, never a security certification. Compared with 0.02 full public report, deliberately fewer findings and no detailed fix advice.",
      parameters:[
       {in:"query",name:"owner",required:false,schema:{type:"string"}},
       {in:"query",name:"repo",required:false,schema:{type:"string"}},
       {in:"query",name:"ref",required:false,schema:{type:"string"}},
       {in:"query",name:"file",required:false,schema:{type:"string"}}
      ],
      "x-payment-info":{protocols:[{x402:{}}],price:{mode:"fixed",currency:"USD",amount:QUICK_PRICE_USDC},network:NETWORK,asset:USDC_BASE,payTo:PAY_TO},
      security:[{x402Payment:[]}],
      responses:{"200":{description:"Payment-verified short static source-line findings and GitHub SHA, not a complete audit",content:{"application/json":{schema:{$ref:"#/components/schemas/QuickCheckResult"},example:QUICK_PUBLIC_OUTPUT_EXAMPLE}}},
       "400":{description:"Invalid public repo source, not charged"},"402":{description:"5,000 micro native Base USDC x402 v2 payment quote"},
       "404":{description:"Public GitHub workflow unavailable before payment"},"413":{description:"YAML too large to review, not charged"},
       "503":{description:"GitHub or service unavailable, not charged"}}
    }},
    "/v1/public-workflow":{get:{
      summary:"Paid 0.02 USDC native Base GitHub Actions public workflow preflight",
      operationId:"preflightPublicGithubWorkflow",
      description:"Only anonymous GitHub public Contents API. Optional source owner, repo, ref=main/master/40hex and file=one .yml/.yaml basename. Invalid or unavailable sources fail before payment.",
      parameters:[
       {in:"query",name:"owner",required:false,schema:{type:"string"}},
       {in:"query",name:"repo",required:false,schema:{type:"string"}},
       {in:"query",name:"ref",required:false,schema:{type:"string"}},
       {in:"query",name:"file",required:false,schema:{type:"string"}}
      ],
      "x-payment-info":{protocols:[{x402:{}}],price:{mode:"fixed",currency:"USD",amount:PRICE_USDC},network:NETWORK,asset:USDC_BASE,payTo:PAY_TO},
      security:[{x402Payment:[]}],
      responses:{"200":{description:"Payment-verified static public GitHub workflow findings with original source SHA",content:{"application/json":{schema:{$ref:"#/components/schemas/PublicWorkflowResult"},example:PUBLIC_OUTPUT_EXAMPLE}}},
       "400":{description:"Invalid source, not charged"},"402":{description:"x402 Base USDC payment quote"},
       "404":{description:"Public workflow unavailable, not charged"},"413":{description:"Source too large, not charged"},
       "503":{description:"GitHub unavailable, not charged"}}
    }},
    "/v1/quick-check":{post:{
      summary:"Under-1-cent short GitHub Actions risk-signal preflight — x402 0.005 Base native Circle USDC",
      operationId:"quickCheckGithubActionsWorkflow",
      description:"One public/synthetic GitHub Actions workflow. Return at most three source-line risk IDs and counts. No execution, no private YAML, no security guarantee. The existing 0.02 complete result remains on /v1/check.",
      "x-payment-info":{protocols:[{x402:{}}],price:{mode:"fixed",currency:"USD",amount:QUICK_PRICE_USDC},network:NETWORK,asset:USDC_BASE,payTo:PAY_TO},
      security:[{x402Payment:[]}],
      requestBody:{required:true,content:{"application/json":{schema:{$ref:"#/components/schemas/CheckInput"},example}}},
      responses:{"200":{description:"Short heuristic report after separately validated payment",content:{"application/json":{schema:{$ref:"#/components/schemas/QuickCheckResult"}}}},
        "400":{description:"Invalid non-secret source; not charged"},"402":{description:"5,000 micro-USDC exact x402 v2 quote"},"413":{description:"Oversized source rejected before charging"}}
    }},
    "/v1/check":{post:{
      summary:"GitHub Actions YAML static scan — x402 $0.02 USDC",
      operationId:"checkGithubActionsWorkflow",
      description:"One validated GitHub Actions workflow (up to 48k UTF-8 bytes). Fixed-price paid finding report, NOT a security audit. Buyer sends a signed x402 v2 Base USDC authorization.",
      "x-payment-info":{protocols:[{x402:{}}],price:{mode:"fixed",currency:"USD",amount:PRICE_USDC},network:NETWORK,asset:USDC_BASE,payTo:PAY_TO},
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
   resources:[PUBLIC_ORIGIN+"/v1/check",PUBLIC_ORIGIN+"/v1/public-workflow",PUBLIC_ORIGIN+"/v1/quick-check",PUBLIC_ORIGIN+"/v1/quick-public-workflow"],
   description:"Exact 0.005 and 0.02 native Base Circle USDC x402 API. POST /v1/quick-check and GET /v1/quick-public-workflow deliver short 3-signal risk previews at 0.005; POST /v1/check analyzes supplied public YAML. GET /v1/public-workflow analyzes one anonymously readable public GitHub Actions workflow with optional safe owner/repo/ref/file query. Both require buyer-signed settlement. Free example /v1/sample. Not a security certification.",
   paymentExperience:"Quote tested, full onchain settlement not yet independently verified."
  }
 };
}
const {spec:openapi,wellKnown}=makeDiscovery();
// Public SHA-256 owner proof only. Never embed the private 402 Index domain-management token.
const DIRECTORY_DOMAIN_PROOF_HASH="60ee3185f8c4f940d09a60d73ebc467b8bd65649d479d6bf556a4fff530207e1";
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
 // Never change the real API's 70/minute guard. The isolated NODE_ENV=test
 // test harness exercises more than 70 local requests in one second.
 const perMinuteLimit=process.env.NODE_ENV==="test"?300:70;
 if(item.count>perMinuteLimit){res.setHeader("Retry-After","60");return res.status(429).json({error:"Too many requests; try later."});}
 next();
});
app.get("/",(_req,res)=>res.redirect(302,"/v1/docs"));
app.get("/health",(_req,res)=>res.json({ok:true,name:"VM2 Workflow Risk Check x402",ruleset:RULESET,paidRoute:"POST /v1/check",mcpRoute:"POST /mcp",quickRoute:"POST /v1/quick-check",quickPublicGET:"GET /v1/quick-public-workflow",quickFeeUSDC:QUICK_PRICE_USDC,network:NETWORK,feeUSDC:PRICE_USDC}));
app.get("/v1/docs",(_req,res)=>res.json({
 name:"VM2 Workflow Risk Check x402",
 status:"Beta — real on-chain payment settlement not yet exercised",
 payment:payFields,
 paid:{method:"POST",path:"/v1/check",contentType:"application/json",body:model},
 quick:{method:"POST",path:"/v1/quick-check",contentType:"application/json",body:model,feeUSDC:QUICK_PRICE_USDC,output:"Top three risk IDs/lines and counts; not a full report"},
 quickPublicGET:{method:"GET",path:"/v1/quick-public-workflow",feeUSDC:QUICK_PRICE_USDC,
   defaultPublicSource:"https://github.com/livastic-vm2-primary-20260911/workflow-risk-x402/blob/main/.github/workflows/verify.yml",
   query:["owner","repo","ref","file"],sourceValidatedBeforePayment:true,
   output:"Counts + at most three finding IDs/severity/line numbers and original public GitHub source SHA, NOT the full review"},
 mcp:{method:"POST",path:"/mcp",protocol:"Streamable HTTP",tool:"analyze_github_actions_yaml",resultScope:"FREE coarse risk level only; no report, severity counts, finding IDs or source lines; detailed results require separately authorized paid x402 REST",payment:"Free origin MCP; independent x402 REST prices 0.005/0.02 native Base Circle USDC. No wallet or payment actions from MCP."},
 paidPublicGET:{method:"GET",path:"/v1/public-workflow",defaultPublicSource:"https://github.com/livastic-vm2-primary-20260911/workflow-risk-x402/blob/main/.github/workflows/verify.yml",query:["owner","repo","ref","file"],sourceValidatedBeforePayment:true},
 free:{"/health":"Service health","/v1/sample":"Original synthetic reproducible sample","/openapi.json":"OpenAPI 3.1 with payment info"},
 limits:{utf8WorkflowBytes:MAX_YAML_BYTES,requestsPerMinute:70,concurrentChecks:2},
 privacy:"Server-side processing of explicitly provided YAML only; no application-level persistence, analytics, IP/address or payment-header logging. Hosting platform and external x402 facilitator have separate logs. Do not submit secrets or private code.",
 caution:"Heuristic triage is NOT formal security advice, security certification, penetration testing, or evidence of a real security vulnerability. No verified paying customers or settlement yet.",
 freeLocalTool:"https://livastic-vm2-primary-20260911.github.io/workflow-risk-check/"
}));
app.get("/v1/sample",(_req,res)=>res.json(SAMPLE_REPORT));
// Separate read-only Streamable HTTP MCP origin. FiatDock or a client decides
// whether its gateway charges; this route never uses the user wallet.
app.options("/mcp",(_req,res)=>res.status(204).end());
app.post("/mcp",express.json({limit:"70kb"}),mcpHandler());
app.get("/mcp",(_req,res)=>res.status(405).set("Allow","POST").json({error:"MCP stateless transport uses POST"}));
app.get("/.well-known/402index-verify.txt",(_req,res)=>res.type("text/plain").send(DIRECTORY_DOMAIN_PROOF_HASH));
app.get("/openapi.json",(_req,res)=>res.json(openapi));
app.get(["/.well-known/x402","/.well-known/x402.json"],(_req,res)=>res.json(wellKnown));
app.get("/robots.txt",(_req,res)=>res.type("text/plain").send("User-agent: *\nDisallow: /v1/check\nDisallow: /v1/public-workflow\nDisallow: /v1/quick-public-workflow\nAllow: /v1/docs\nAllow: /v1/sample\n"));
app.options("/v1/check",(_req,res)=>res.status(204).end());
// Compatibility for buyers that parse JSON in 402 instead of only the header.
// Mirror the canonical original middleware quote exactly; never create a
// payment requirement or change verification/settlement, wallet or price.
function mirrorCanonicalPublicGet402(req,res,next){
 const originalSend=res.send;
 res.send=function(body){
  const wire=res.getHeader("PAYMENT-REQUIRED");
  if(req.method==="GET" && res.statusCode===402 &&
     typeof wire==="string" && wire.length>0 && wire.length<20000){
   try{
    const q=JSON.parse(Buffer.from(wire,"base64").toString("utf8"));
    const resource=new URL(q?.resource?.url);
    const expected=new URL(req.originalUrl,PUBLIC_ORIGIN);
    const a=q?.accepts;
    if(q?.x402Version===2 && resource.href===expected.href &&
       resource.origin===PUBLIC_ORIGIN &&
       (resource.pathname==="/v1/public-workflow" ||
        resource.pathname==="/v1/quick-public-workflow") &&
       Array.isArray(a) && a.length===1 &&
       a[0]?.scheme==="exact" && a[0]?.network===NETWORK &&
       a[0]?.amount===(resource.pathname==="/v1/public-workflow"?"20000":"5000") &&
       a[0]?.asset?.toLowerCase()===USDC_BASE.toLowerCase() &&
       a[0]?.payTo?.toLowerCase()===PAY_TO.toLowerCase() &&
       a[0]?.extra?.name==="USD Coin"){
      res.setHeader("X-Payment-Required",wire);
      res.setHeader("Access-Control-Expose-Headers",
        "PAYMENT-REQUIRED,X-Payment-Required,PAYMENT-RESPONSE");
      res.type("json");
      return originalSend.call(res,JSON.stringify(q));
    }
   }catch{ /* Any mismatch leaves the original middleware response unchanged. */ }
  }
  return originalSend.call(res,body);
 };
 next();
}
app.get("/v1/quick-public-workflow",async(req,res,next)=>{
 const source=await readPublicWorkflow(req.query);
 if(!source.ok)return res.status(source.status).json({ok:false,charged:false,error:source.error});
 if(inFlight>=2)return res.status(503).json({ok:false,charged:false,error:"Busy; no payment accepted. Retry later."});
 inFlight++;
 res.on("finish",()=>{inFlight=Math.max(0,inFlight-1);});
 res.on("close",()=>{if(!res.writableEnded)inFlight=Math.max(0,inFlight-1);});
 res.locals.publicWorkflow=source;
 next();
},mirrorCanonicalPublicGet402,payment,(req,res)=>{
 const {preflight,source}=res.locals.publicWorkflow;
 res.status(200).json({...quickResponse(preflight),
  source,disclosure:"Only the top-three public YAML risk signals and counts, not a full report, security certification or independent proof of a buyer's Base USDC settlement."});
});
app.get("/v1/public-workflow",async(req,res,next)=>{
 const source=await readPublicWorkflow(req.query);
 if(!source.ok)return res.status(source.status).json({ok:false,charged:false,error:source.error});
 if(inFlight>=2)return res.status(503).json({ok:false,charged:false,error:"Busy; no payment accepted. Retry later."});
 inFlight++;
 res.on("finish",()=>{inFlight=Math.max(0,inFlight-1);});
 res.on("close",()=>{if(!res.writableEnded)inFlight=Math.max(0,inFlight-1);});
 res.locals.publicWorkflow=source;
 next();
},mirrorCanonicalPublicGet402,payment,(req,res)=>{
 const {preflight,source}=res.locals.publicWorkflow;
 res.status(200).json({...paidResponse(preflight.report,preflight.bytes,preflight.filename),
  source,disclosure:"Anonymous public GitHub YAML static preflight. Not a security audit, certification or exploit evidence."});
});
app.options("/v1/quick-check",(_req,res)=>res.status(204).end());
app.post("/v1/quick-check",express.json({limit:"70kb"}),(req,res,next)=>{
 if(!req.is("application/json"))return res.status(415).json({charged:false,error:"Use application/json."});
 const preflight=normalizeInput(req.body);
 if(!preflight.ok)return res.status(preflight.status).json({charged:false,error:preflight.error});
 if(inFlight>=2)return res.status(503).json({charged:false,error:"Busy; no payment accepted."});
 inFlight++;
 res.on("finish",()=>{inFlight=Math.max(0,inFlight-1);});
 res.on("close",()=>{if(!res.writableEnded)inFlight=Math.max(0,inFlight-1);});
 res.locals.preflight=preflight;
 next();
},payment,(req,res)=>res.status(200).json(quickResponse(res.locals.preflight)));
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
