import test from "node:test";
import assert from "node:assert/strict";

const base=process.env.TEST_URL;
const payto=process.env.TEST_PAYTO;
assert.match(base||"",/^http:\/\/127\.0\.0\.1:\d+$/);
assert.match(payto||"",/^0x[0-9a-fA-F]{40}$/);
const quick=base+"/v1/quick-public-workflow";
const full=base+"/v1/public-workflow";
const decode=(r,k)=>{const b=r.headers.get(k);return b?JSON.parse(Buffer.from(b,"base64").toString()):null;};
function fakePayment(quote,sig){
 return Buffer.from(JSON.stringify({x402Version:2,resource:quote.resource,accepted:quote.accepts[0],
  payload:{signature:sig,authorization:{from:"0x"+"33".repeat(20),to:quote.accepts[0].payTo,
   value:quote.accepts[0].amount,validAfter:"0",validBefore:"9999999999",
   nonce:"0x"+"55".repeat(32)}},extensions:quote.extensions||{}})).toString("base64");
}
test("New GET no-body native Base 5000-microUSDC challenge, correct original recipient and preserved old 20000 route",async()=>{
 const [r,old]=await Promise.all([fetch(quick),fetch(full)]);
 assert.equal(r.status,402);
 assert.equal(old.status,402);
 assert.equal(decode(old,"payment-required").accepts[0].amount,"20000");
 const q=decode(r,"PAYMENT-REQUIRED");
 assert.equal(q.x402Version,2);
 assert.equal(q.accepts.length,1);
 assert.equal(q.accepts[0].amount,"5000");
 assert.equal(q.accepts[0].network,"eip155:8453");
 assert.equal(q.accepts[0].scheme,"exact");
 assert.equal(q.accepts[0].asset.toLowerCase(),"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
 assert.equal(q.accepts[0].payTo.toLowerCase(),payto.toLowerCase());
 assert.equal(r.headers.get("PAYMENT-RESPONSE"),null);
 assert.equal(r.headers.get("X-Payment-Required"),r.headers.get("PAYMENT-REQUIRED"),
   "Same canonical middleware quote mirrored to JSON; no custom payment forge");
 assert.deepEqual(await r.json(),q);
 assert.match(q.resource.url,/\/v1\/quick-public-workflow$/);
 assert.equal(q.extensions?.bazaar?.info?.input?.method,"GET");
 assert.equal(q.extensions?.bazaar?.info?.output?.type,"json");
 assert.equal(q.extensions.bazaar.info.output.example.source.githubBlobSha,
   "8892016df7376c6fd7d97fee13e87ab72cfd53ca");
});
test("Document real product separately in OpenAPI, original resource and 0.02 price unchanged",async()=>{
 const [spec,manifest,docs,health]=await Promise.all([
  fetch(base+"/openapi.json").then(r=>r.json()),
  fetch(base+"/.well-known/x402").then(r=>r.json()),
  fetch(base+"/v1/docs").then(r=>r.json()),
  fetch(base+"/health").then(r=>r.json())
 ]);
 assert.equal(spec.paths["/v1/quick-public-workflow"].get["x-payment-info"].price.amount,"0.005");
 assert.equal(spec.paths["/v1/public-workflow"].get["x-payment-info"].price.amount,"0.02");
 assert.equal(spec.paths["/v1/quick-check"].post["x-payment-info"].price.amount,"0.005");
 assert.equal(spec.paths["/v1/check"].post["x-payment-info"].price.amount,"0.02");
 assert.deepEqual(manifest.resources,[base+"/v1/check",base+"/v1/public-workflow",
  base+"/v1/quick-check",base+"/v1/quick-public-workflow"]);
 assert.equal(docs.quickPublicGET.path,"/v1/quick-public-workflow");
 assert.equal(docs.quickPublicGET.feeUSDC,"0.005");
 assert.equal(health.quickPublicGET,"GET /v1/quick-public-workflow");
 assert.equal(health.feeUSDC,"0.02");
});
test("Pre-billing public GitHub source validation and SSRF prevention also protect quick GET",async()=>{
 for(const qs of ["?owner=evil.com","?repo=../secret","?ref=%2e%2e%2fsecret",
                   "?file=../../secrets.yml","?url=http://169.254.169.254/private"]){
  const r=await fetch(quick+qs);
  assert.equal(r.status,400,qs);
  assert.equal(r.headers.get("PAYMENT-REQUIRED"),null);
  assert.equal((await r.json()).charged,false);
 }
 const missing=await fetch(quick+"?file=does-not-exist.yml");
 assert.equal(missing.status,404);
 assert.equal(missing.headers.get("PAYMENT-REQUIRED"),null);
});
test("Invalid signed marker cannot retrieve content or spoof a receipt",async()=>{
 const q=decode(await fetch(quick),"PAYMENT-REQUIRED");
 const r=await fetch(quick,{headers:{"PAYMENT-SIGNATURE":fakePayment(q,"0x"+"99".repeat(65))}});
 assert.equal(r.status,402);
 assert.equal(r.headers.get("PAYMENT-RESPONSE"),null);
 const body=await r.json();
 assert.equal(body.x402Version,2);
 assert.equal(body.accepts[0].amount,"5000");
 assert.equal(body.accepts[0].payTo.toLowerCase(),payto.toLowerCase());
 assert.equal(Object.hasOwn(body,"topSignals"),false,
   "Reject must not return paid result at top level; Bazaar discovery MAY include public synthetic examples");
 assert.equal(Object.hasOwn(body,"counts"),false);
 assert.equal(Object.hasOwn(body,"report"),false);
});
test("Valid TEST-ONLY mock facilitator provides bounded scope and pinned GitHub provenance, no full report",async()=>{
 const q=decode(await fetch(quick),"PAYMENT-REQUIRED");
 const r=await fetch(quick,{headers:{"PAYMENT-SIGNATURE":fakePayment(q,"0x"+"11".repeat(65))}});
 assert.equal(r.status,200);
 const data=await r.json();
 assert.equal(data.product,"VM2 Quick Workflow Risk");
 assert.deepEqual(data.counts,{high:1,medium:2,note:1});
 assert.ok(data.topSignals.length>0 && data.topSignals.length<=3);
 assert.equal(data.paid_x402.price,"0.005");
 assert.equal(data.source.provider,"GitHub public Contents API; no private token used");
 assert.equal(data.source.githubBlobSha,"0".repeat(40));
 assert.equal(Object.hasOwn(data,"report"),false);
 assert.equal(Object.hasOwn(data,"workflowYaml"),false);
 assert.match(data.disclosure,/not a full report/);
 assert.match(data.paid_x402.disclaimer,/NOT independent proof/);
 const receipt=decode(r,"PAYMENT-RESPONSE");
 assert.equal(receipt.transaction,"0x"+"22".repeat(32),"Mock tx is a fixture, NEVER actual paid owner cash");
});
