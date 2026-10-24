import test from "node:test";
import assert from "node:assert/strict";
import {parsePublicSourceQuery} from "../public-source.mjs";
const base=process.env.TEST_URL;
const payto=process.env.TEST_PAYTO;
assert(base && payto,"Local original mock-facilitator and GH fixture required");
const decodeHeader=(r,key)=>{
 const data=r.headers.get(key);
 return data?JSON.parse(Buffer.from(data,"base64").toString("utf8")):null;
};
const url=base+"/v1/public-workflow";
function fakePayment(terms,signature){
 return Buffer.from(JSON.stringify({x402Version:2,resource:terms.resource,accepted:terms.accepts[0],
  payload:{signature,authorization:{from:"0x"+"33".repeat(20),to:terms.accepts[0].payTo,
   value:terms.accepts[0].amount,validAfter:"0",validBefore:"9999999999",
   nonce:"0x"+"55".repeat(32)}},extensions:terms.extensions||{}})).toString("base64");
}
test("Only safe public GitHub ownership and workflow filename can create outbound URL",()=>{
 const a=parsePublicSourceQuery({});
 assert.equal(a.ok,true);
 assert.equal(new URL(a.url).hostname,"api.github.com");
 assert.equal(a.target.owner,"livastic-vm2-primary-20260911");
 assert(a.url.includes("/contents/.github/workflows/verify.yml?ref=main"));
 for(const bad of [{owner:"evil.com"},{owner:"bad/path"},{repo:"../private"},{repo:"x..y"},
   {file:"../../p.yml"},{file:"a.yaml/../b.yml"},{file:"another.js"},{ref:"refs/heads/main"},
   {ref:"../../main"},{url:"http://169.254.169.254"},{owner:["alice","bob"]}]){
  assert.equal(parsePublicSourceQuery(bad).ok,false,JSON.stringify(bad));
 }
});
test("Owned public repo GitHub fixture pays only after public source is downloaded and valid",async()=>{
 const r=await fetch(url);
 assert.equal(r.status,402);
 const data=decodeHeader(r,"payment-required");
 assert.equal(data?.x402Version,2);
 assert.equal(data.accepts.length,1);
 assert.equal(data.accepts[0].network,"eip155:8453");
 assert.equal(data.accepts[0].amount,"20000");
 assert.equal(data.accepts[0].payTo.toLowerCase(),payto.toLowerCase());
 assert.equal(r.headers.get("payment-response"),null);
});
test("MOCK ONLY: successful outside buyer signature unlocks public source report",async()=>{
 const first=await fetch(url);
 const quote=decodeHeader(first,"payment-required");
 const r=await fetch(url,{headers:{"PAYMENT-SIGNATURE":fakePayment(quote,"0x"+"11".repeat(65))}});
 const raw=await r.text();
 assert.equal(r.status,200,raw.slice(0,400));
 const value=JSON.parse(raw);
 assert.deepEqual(value.report.counts,{high:1,medium:2,note:1});
 assert.equal(value.source.provider,"GitHub public Contents API; no private token used");
 assert.equal(value.source.path,".github/workflows/verify.yml");
 assert.equal(value.source.githubBlobSha,"0".repeat(40));
 const receipt=decodeHeader(r,"payment-response");
 assert.equal(receipt.transaction,"0x"+"22".repeat(32));
 // Fake local signed marker/settlement is NOT REAL BASE USDC or a customer purchase.
});
test("Bad parameters and unresolvable public Github path are refused BEFORE payment",async()=>{
 for(const q of ["?owner=evil.com","?repo=../private","?ref=%2e%2e%2fsecret",
                "?file=../../p.yml","?url=https://127.0.0.1/private"]){
  const r=await fetch(url+q);
  assert.equal(r.status,400,q);
  assert.equal(r.headers.get("payment-required"),null);
 }
 const missing=await fetch(url+"?file=does-not-exist.yml");
 assert.equal(missing.status,404);
 assert.equal(missing.headers.get("payment-required"),null);
});
test("Original discovery reveals separate GET and POST paid routes",async()=>{
 const w=await (await fetch(base+"/.well-known/x402")).json();
 assert.deepEqual(w.resources,[base+"/v1/check",base+"/v1/public-workflow"]);
 const openapi=await (await fetch(base+"/openapi.json")).json();
 assert.equal(openapi.paths["/v1/public-workflow"].get["x-payment-info"].price.amount,"0.02");
 const docs=await (await fetch(base+"/v1/docs")).json();
 assert.equal(docs.paidPublicGET.path,"/v1/public-workflow");
 assert.equal(docs.payment.recipient.toLowerCase(),payto.toLowerCase());
});
