import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {normalizeInput,sampleResponse,paidResponse,MAX_YAML_BYTES,NETWORK,PRICE_USDC,RULESET} from "../core.mjs";
const sample=fs.readFileSync(new URL("../examples/pr-check.yml",import.meta.url),"utf8");
const valid={workflowYaml:sample,filename:"pr-check.yml"};
test("Known synthetic YAML is accepted",()=>assert.equal(normalizeInput(valid).ok,true));
test("Original rule set matches actual synthetic finding counts",()=>{
 const report=normalizeInput(valid).report;
 assert.deepEqual(report.counts,{high:1,medium:2,note:1});
 const hits=Object.fromEntries(report.findings.map(x=>[x.id,x.line]));
 assert.equal(hits.TARGET_UNTRUSTED_CODE,8);
 assert.equal(hits.ACTION_UNPINNED,8);
 assert.equal(hits.WORKFLOW_WRITE,3);
 assert.equal(hits.TARGET_CONTEXT,2);
});
test("False-empty input and invalid scalars fail before payment",()=>{
 for(const x of [null,[],{},false,1,{workflowYaml:""},{workflowYaml:123}])
  assert.equal(normalizeInput(x).ok,false);
});
test("Parsing errors are rejected before billing",()=>{
 assert.match(normalizeInput({workflowYaml:"jobs: [broken"}).error,/YAML parse error/);
});
test("Arbitrary nonworkflow YAML is rejected",()=>{
 assert.match(normalizeInput({workflowYaml:"a: 2\nb: 4"}).error,/missing top-level jobs/);
});
test("Reject unknown key, prevent extensions that hide extra data",()=>{
 assert.equal(normalizeInput({...valid,privateKey:"secret"}).ok,false);
});
test("Reject filename traversal, shell sequences, long filename",()=>{
 for(const n of ["../../foo.yml","foo.yml;echo hi","foo.js","x".repeat(125)+".yaml","\nfoo.yml"])
  assert.equal(normalizeInput({...valid,filename:n}).ok,false);
});
test("Enforce byte size on Unicode and plain ASCII input",()=>{
 assert.equal(normalizeInput({workflowYaml:"a".repeat(MAX_YAML_BYTES+1)}).status,413);
 assert.equal(normalizeInput({workflowYaml:"가".repeat(MAX_YAML_BYTES/3+1)}).status,413);
});
test("Check valid no-finding YAML without promising security",()=>{
 const safe=normalizeInput({workflowYaml:"on: pull_request\npermissions: {contents: read}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test"});
 assert.equal(safe.ok,true);
 assert.deepEqual(safe.report.counts,{high:0,medium:0,note:0});
 const delivered=paidResponse(safe.report,safe.bytes,safe.filename);
 assert.match(delivered.limitations,/not a security guarantee/i);
});
test("Free sample proves no buyer engagement",()=>{
 const report=sampleResponse(sample);
 assert.equal(report.paid,false);
 assert.equal(report.kind,"synthetic_sample");
 assert.match(report.disclaimer,/not a real customer security finding/);
});
test("Paid report explicitly qualifies settlement as external and unverified",()=>{
 const p=normalizeInput(valid);
 const out=paidResponse(p.report,p.bytes,p.filename);
 assert.equal(out.paid_x402.network,NETWORK);
 assert.equal(out.paid_x402.price,PRICE_USDC);
 assert.equal(out.ruleset,RULESET);
 assert.match(out.paid_x402.claim,/independently/);
});
test("Source report deterministic on repeated scans",()=>{
 assert.deepEqual(normalizeInput(valid).report,normalizeInput(valid).report);
});
