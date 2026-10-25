import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
const base=process.env.TEST_URL;
const payto=process.env.TEST_PAYTO;
assert(base&&payto,"Tests require local mock fixture launched by scripts/run-tests.mjs");
const sample=fs.readFileSync(new URL("../examples/pr-check.yml",import.meta.url),"utf8");
const valid={workflowYaml:sample,filename:"pr-check.yml"};
function send(body,headers={}){
 return fetch(base+"/v1/check",{method:"POST",headers:{"Content-Type":"application/json",...headers},body:JSON.stringify(body)});
}
function decodeHeader(response,key){
 const encoded=response.headers.get(key);
 return encoded?JSON.parse(Buffer.from(encoded,"base64").toString("utf8")):null;
}
test("Readiness is a free public endpoint, does not claim a cash sale",async()=>{
 const r=await fetch(base+"/health");assert.equal(r.status,200);
 const json=await r.json();assert.equal(json.ok,true);
 assert.equal(json.feeUSDC,"0.02");
});
test("Docs are public and warn that real settlement has not been tested",async()=>{
 const r=await fetch(base+"/v1/docs");assert.equal(r.status,200);
 const j=await r.json();assert.match(j.status,/not yet/);
 assert.equal(j.payment.network,"eip155:8453");
 assert.equal(j.payment.recipient.toLowerCase(),payto.toLowerCase());
 assert.match(j.caution,/NOT formal security advice/);
});
test("Directory domain ownership proof exposes only a public 64-hex digest, never the management credential",async()=>{
 const r=await fetch(base+"/.well-known/402index-verify.txt");
 assert.equal(r.status,200);
 assert.match(r.headers.get("content-type")||"",/text\/plain/);
 assert.equal(r.headers.get("payment-required"),null);
 const payload=await r.text();
 assert.match(payload,/^[a-f0-9]{64}$/);
 assert.equal(payload.length,64);
});
test("Synthetic example is free with exact findings",async()=>{
 const r=await fetch(base+"/v1/sample");assert.equal(r.status,200);
 const j=await r.json();assert.equal(j.paid,false);
 assert.deepEqual(j.report.counts,{high:1,medium:2,note:1});
});
test("Valid JSON without payment gets real x402 v2 Base USDC quote only",async()=>{
 const r=await send(valid);
 assert.equal(r.status,402);
 const chall=decodeHeader(r,"payment-required");
 assert.equal(chall.x402Version,2);
 assert.equal(chall.accepts[0].network,"eip155:8453");
 assert.equal(chall.accepts[0].amount,"20000");
 assert.equal(chall.accepts[0].payTo.toLowerCase(),payto.toLowerCase());
 assert.equal(chall.accepts[0].asset.toLowerCase(),"0x833589fcD6eDb6e08f4c7c32d4f71b54bda02913".toLowerCase());
 assert.equal(r.headers.get("payment-response"),null);
});
test("Unknown body key fails before charging",async()=>{
 const r=await send({...valid,token:"do-not-log"});assert.equal(r.status,400);
 assert.equal(r.headers.get("payment-required"),null);
});
test("Invalid YAML document fails before paying",async()=>{
 const r=await send({workflowYaml:"jobs: [broken"});assert.equal(r.status,400);
 assert.equal(r.headers.get("payment-required"),null);
});
test("Nonworkflow YAML is not payable",async()=>{
 const r=await send({workflowYaml:"foo: bar"});assert.equal(r.status,400);
 assert.equal(r.headers.get("payment-required"),null);
});
test("Oversized source blocked before charging",async()=>{
 const r=await send({workflowYaml:"z".repeat(48001)});assert.equal(r.status,413);
 assert.equal(r.headers.get("payment-required"),null);
});
test("Input filename prevents traversal before paywall",async()=>{
 const r=await send({workflowYaml:sample,filename:"../../a.yaml"});assert.equal(r.status,400);
 assert.equal(r.headers.get("payment-required"),null);
});
test("Malformed JSON envelope refused without payment",async()=>{
 const r=await fetch(base+"/v1/check",{method:"POST",headers:{"Content-Type":"application/json"},body:"{invalid"});
 assert.equal(r.status,400);assert.equal(r.headers.get("payment-required"),null);
});
test("OpenAPI x402 discovery points to correct single paid endpoint",async()=>{
 const r=await fetch(base+"/openapi.json");assert.equal(r.status,200);
 const spec=await r.json();
 assert.equal(spec.openapi,"3.1.0");
 assert.equal(spec.paths["/v1/check"].post["x-payment-info"].price.amount,"0.02");
 assert.equal(spec.paths["/v1/check"].post.operationId,"checkGithubActionsWorkflow");
 assert.ok(spec.paths["/v1/check"].post.responses["402"]);
 assert.ok(spec.components.securitySchemes.x402Payment);
 assert.ok(!JSON.stringify(spec).includes("onecursor1@gmail.com"));
});
test("Machine-readable well-known resources refer to real paid path",async()=>{
 for(const endpoint of ["/.well-known/x402","/.well-known/x402.json"]){
  const r=await fetch(base+endpoint);assert.equal(r.status,200);
  const data=await r.json();
  assert.deepEqual(data.resources,[base+"/v1/check",base+"/v1/public-workflow",base+"/v1/quick-check"]);
 }
});
function fakePayment(requirements,signature){
 return Buffer.from(JSON.stringify({
  x402Version:2,resource:requirements.resource,accepted:requirements.accepts[0],
  payload:{signature,authorization:{
   from:"0x"+"33".repeat(20),to:requirements.accepts[0].payTo,
   value:requirements.accepts[0].amount,validAfter:"0",validBefore:"9999999999",
   nonce:"0x"+"55".repeat(32)
  }},extensions:requirements.extensions||{}
 })).toString("base64");
}
test("MOCK ONLY: local facilitator success returns actual detector report; NOT an onchain payment",async()=>{
 const init=await send(valid);
 assert.equal(init.status,402);
 const quote=decodeHeader(init,"payment-required");
 const authorized=await send(valid,{"PAYMENT-SIGNATURE":fakePayment(quote,"0x"+"11".repeat(65))});
 const raw=await authorized.text();
 assert.equal(authorized.status,200,"HTTP "+authorized.status+" "+raw.slice(0,350));
 const report=JSON.parse(raw);
 assert.equal(report.ok,true);
 assert.deepEqual(report.report.counts,{high:1,medium:2,note:1});
 assert.equal(report.input.filename,"pr-check.yml");
 assert.match(report.limitations,/NOT formal security advice|not a full security audit/);
 const receipt=decodeHeader(authorized,"payment-response");
 assert.equal(receipt.transaction,"0x"+"22".repeat(32));
 // TEST transaction hash is NOT on Base: never book revenue.
});
test("MOCK ONLY: invalid marker does not get a paid report or a mock-settlement receipt",async()=>{
 const initial=await send(valid);
 assert.equal(initial.status,402);
 const quote=decodeHeader(initial,"payment-required");
 const rejected=await send(valid,{"PAYMENT-SIGNATURE":fakePayment(quote,"0x"+"99".repeat(65))});
 assert.equal(rejected.status,402);
 assert.equal(rejected.headers.get("payment-response"),null);
});
test("Unpaid response is not marked successful (no data leak)",async()=>{
 const r=await send(valid);
 assert.equal(r.status,402);
 const body=await r.text();
 assert.ok(!body.includes("TARGET_UNTRUSTED_CODE"),"Do not expose full report before authorization");
});
