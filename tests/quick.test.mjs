import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {QUICK_PRICE_USDC, QUICK_PRICE_ATOMIC,quickResponse} from "../quick-check.mjs";
import {normalizeInput} from "../core.mjs";

const base=process.env.TEST_URL;
const payto=process.env.TEST_PAYTO;
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base||"")||!/^0x[0-9a-fA-F]{40}$/.test(payto||""))throw Error("Quick tests MUST use local mock server");
const valid={workflowYaml:fs.readFileSync(new URL("../examples/pr-check.yml",import.meta.url),"utf8"),filename:"pr-check.yml"};
const endpoint=base+"/v1/quick-check";
function post(data,headers={}){
 return fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json",...headers},body:typeof data==="string"?data:JSON.stringify(data)});
}
function quote(response){
 const h=response.headers.get("payment-required");
 assert.ok(h,"A valid paid request MUST quote before returning findings");
 return JSON.parse(Buffer.from(h,"base64").toString("utf8"));
}
function fakePay(req,signature){
 return Buffer.from(JSON.stringify({x402Version:2,resource:req.resource,accepted:req.accepts[0],
 payload:{signature,authorization:{from:"0x"+"33".repeat(20),to:req.accepts[0].payTo,
 value:req.accepts[0].amount,validAfter:"0",validBefore:"9999999999",nonce:"0x"+"55".repeat(32)}},
 extensions:req.extensions||{}})).toString("base64");
}
test("New 0.005 USDC quote has original owner, official native Circle Base, exact scheme, no receipt",async()=>{
 const res=await post(valid);
 assert.equal(res.status,402);
 const q=quote(res),a=q.accepts[0];
 assert.equal(q.x402Version,2);
 assert.equal(a.network,"eip155:8453");
 assert.equal(a.scheme,"exact");
 assert.equal(a.amount,QUICK_PRICE_ATOMIC);
 assert.equal(QUICK_PRICE_USDC,"0.005");
 assert.equal(a.payTo.toLowerCase(),payto.toLowerCase());
 assert.equal(a.asset.toLowerCase(),"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
 assert.equal(res.headers.get("payment-response"),null);
 assert.equal((await res.text()).includes("TARGET_UNTRUSTED_CODE"),false,"Must not leak paid summary");
});
test("New 0.005 SKU is separately discoverable, originals remain 0.02",async()=>{
 const spec=await (await fetch(base+"/openapi.json")).json();
 for(const p of ["/v1/check","/v1/public-workflow"])assert.equal(spec.paths[p][p.endsWith("check")?"post":"get"]["x-payment-info"].price.amount,"0.02");
 const q=spec.paths["/v1/quick-check"].post;
 assert.equal(q["x-payment-info"].price.amount,"0.005");
 assert.equal(q["x-payment-info"].network,"eip155:8453");
 const docs=await(await fetch(base+"/v1/docs")).json();
 assert.equal(docs.quick.feeUSDC,"0.005");
 const health=await(await fetch(base+"/health")).json();
 assert.equal(health.quickRoute,"POST /v1/quick-check");
 assert.equal(health.feeUSDC,"0.02");
});
test("Negative: YAML syntax, nonworkflow, unexpected fields, oversized, traversal, content-type rejected before quote",async()=>{
 const cases=[
  [{workflowYaml:"jobs: [broken"},400],
  [{workflowYaml:"unrelated: plain"},400],
  [{...valid,extra:"private"},400],
  [{workflowYaml:"x".repeat(48001)},413],
  [{...valid,filename:"../../passwd.yml"},400],
  ["{bad JSON",400]
 ];
 for(const [body,status] of cases){
  const r=await post(body);assert.equal(r.status,status,JSON.stringify(body).slice(0,50));
  assert.equal(r.headers.get("payment-required"),null);
  assert.equal(r.headers.get("payment-response"),null);
 }
 const type=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"text/plain"},body:"hello"});
 assert.equal(type.status,415);
 assert.equal(type.headers.get("payment-required"),null);
});
test("Negative: invalid signed marker cannot unlock summary or fabricated receipt",async()=>{
 const r=await post(valid);const req=quote(r);
 const out=await post(valid,{"PAYMENT-SIGNATURE":fakePay(req,"0x"+"99".repeat(65))});
 assert.equal(out.status,402);
 assert.equal(out.headers.get("payment-response"),null);
 assert.equal((await out.text()).includes("TARGET_UNTRUSTED_CODE"),false);
});
test("Mock facilitator valid marker unlocks exact small summary, NEVER an onchain payment claim",async()=>{
 const r=await post(valid);const req=quote(r);
 const out=await post(valid,{"PAYMENT-SIGNATURE":fakePay(req,"0x"+"11".repeat(65))});
 assert.equal(out.status,200);
 const b=await out.json();
 assert.equal(b.product,"VM2 Quick Workflow Risk");
 assert.deepEqual(b.counts,{high:1,medium:2,note:1});
 assert.ok(Array.isArray(b.topSignals)&&b.topSignals.length<=3);
 assert.ok(b.topSignals.some(x=>x.severity==="high"));
 assert.equal(b.paid_x402.price,"0.005");
 assert.match(b.paid_x402.disclaimer,/NOT independent proof/);
 assert.equal(Object.hasOwn(b,"report"),false,"Do not sell full 0.02 report in quick SKU");
 const receipt=out.headers.get("payment-response");
 assert.ok(receipt,"MCP fake facilitator simulated only");
 const data=JSON.parse(Buffer.from(receipt,"base64").toString());
 assert.equal(data.transaction,"0x"+"22".repeat(32),"SIMULATED transaction; not real funds");
});
test("Pure quick response never includes unsafe full findings or client workflow YAML",()=>{
 const checked=normalizeInput(valid);assert.equal(checked.ok,true);
 const resp=quickResponse(checked);
 assert.equal(resp.input.filename,"pr-check.yml");
 assert.equal(resp.input.bytes,Buffer.byteLength(valid.workflowYaml));
 assert.ok(resp.topSignals.length<=3);
 assert.equal(Object.hasOwn(resp,"report"),false);
 assert.equal(JSON.stringify(resp).includes(valid.workflowYaml),false);
});
