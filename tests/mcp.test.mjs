import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {Client} from "@modelcontextprotocol/sdk/client/index.js";
import {StreamableHTTPClientTransport} from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE=process.env.TEST_URL;
assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(BASE||""),"No external MCP test endpoint");
const valid=fs.readFileSync(new URL("../examples/pr-check.yml",import.meta.url),"utf8");

test("Original HTTP paid endpoints stay unchanged, MCP advertises no wallet side effects",async()=>{
 const health=await fetch(BASE+"/health");
 assert.equal(health.status,200);
 const h=await health.json();
 assert.equal(h.paidRoute,"POST /v1/check");
 assert.equal(h.network,"eip155:8453");
 const get=await fetch(BASE+"/mcp");
 assert.equal(get.status,405);
});

test("Official SDK Client can negotiate stateless MCP and list one original analyer",async()=>{
 const client=new Client({name:"vm2-read-only-e2e",version:"0.1.0"});
 const transport=new StreamableHTTPClientTransport(new URL(BASE+"/mcp"));
 try{
  await client.connect(transport);
  const tools=await client.listTools();
  assert.equal(tools.tools.length,1);
  assert.equal(tools.tools[0].name,"analyze_github_actions_yaml");
  assert.match(tools.tools[0].description,/FREE origin MCP coarse risk-level/);
  assert.ok(tools.tools[0].inputSchema,"Missing tool validation schema");
 }finally{await client.close().catch(()=>{});}
});

test("Official MCP client gets coarse genuinely FREE preview, not paid report data",async()=>{
 const client=new Client({name:"vm2-synthetic-fixture",version:"0.1.0"});
 const transport=new StreamableHTTPClientTransport(new URL(BASE+"/mcp"));
 try{
  await client.connect(transport);
  const result=await client.callTool({name:"analyze_github_actions_yaml",arguments:{workflowYaml:valid,filename:"pr-check.yml"}});
  assert.notEqual(result.isError,true);
  assert.equal(result.structuredContent?.product,"Free MCP coarse workflow preflight");
  assert.equal(result.structuredContent.checked.filename,"pr-check.yml");
  assert.equal(result.structuredContent.riskLevel,"HIGH");
  assert.equal(result.structuredContent.flagged,true);
  for(const field of ["report","counts","topSignals","findings","paid_x402","workflowYaml"]){
   assert.equal(Object.hasOwn(result.structuredContent,field),false,field+" must never be returned for free");
  }
  assert.match(result.structuredContent.availablePaidRoutes.short,/0[.]005 native Base Circle USDC/);
  assert.match(result.structuredContent.availablePaidRoutes.full,/0[.]02 native Base Circle USDC/);
  assert.match(result.structuredContent.billing,/This MCP origin preview is free/);
  assert.match(result.content[0].text,/"riskLevel":"HIGH"/);
  assert.equal(result.content[0].text.includes(valid),false,"Input YAML must not be echoed");
  assert.equal(result.content[0].text.includes('"line":'),false,"No line-level detail free");
 }finally{await client.close().catch(()=>{});}
});

test("Invalid YAML fails closed, no fictitious success or payment proof",async()=>{
 const client=new Client({name:"vm2-invalid-fixture",version:"0.1.0"});
 const transport=new StreamableHTTPClientTransport(new URL(BASE+"/mcp"));
 try{
  await client.connect(transport);
  const result=await client.callTool({name:"analyze_github_actions_yaml",arguments:{workflowYaml:"hello: world",filename:"bad.yml"}});
  assert.equal(result.isError,true);
  assert.match(result.content[0].text,/chargedByOrigin":false/);
 }finally{await client.close().catch(()=>{});}
});

test("Untrusted YAML is bounded before request, path traversal not accepted",async()=>{
 const client=new Client({name:"vm2-filename-check",version:"0.1.0"});
 const transport=new StreamableHTTPClientTransport(new URL(BASE+"/mcp"));
 try{
  await client.connect(transport);
  const result=await client.callTool({name:"analyze_github_actions_yaml",arguments:{workflowYaml:valid,filename:"../../evil.yml"}});
  assert.equal(result.isError,true);
  assert.match(result.content[0].text,/filename must be one simple/);
 }finally{await client.close().catch(()=>{});}
});

test("Bad method and content type fail closed without charging or exposing a stack trace",async()=>{
 const r=await fetch(BASE+"/mcp",{method:"POST",headers:{"content-type":"text/plain"},body:"secret"});
 assert.equal(r.status,415);
 const bad=await r.text();
 assert.equal(/privatekey|\n\s*at |PAY_TO/.test(bad),false);
});
