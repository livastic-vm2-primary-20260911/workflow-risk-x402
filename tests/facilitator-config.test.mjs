import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import YAML from "yaml";
import {PRICE_USDC,USDC_BASE,NETWORK} from "../core.mjs";
import {QUICK_PRICE_USDC} from "../quick-check.mjs";
const source=fs.readFileSync(new URL("../server.mjs",import.meta.url),"utf8");
const blueprint=YAML.parse(fs.readFileSync(new URL("../render.yaml",import.meta.url),"utf8"));
const env=Object.fromEntries(blueprint.services[0].envVars.map(e=>[e.key,e]));
test("Production default uses the reviewed credential-free facilitator",()=>{
 assert(source.includes('process.env.FACILITATOR_URL||"https://facilitator.payai.network"'));
});
test("Render blueprint agrees with the server default",()=>{
 assert.equal(env.FACILITATOR_URL.value,"https://facilitator.payai.network");
 assert.equal(env.NODE_ENV.value,"production");
 assert.equal(blueprint.services[0].plan,"free");
});
test("Payout destination is operator-configured, not replaced or committed",()=>{
 assert.equal(env.PAY_TO.sync,false);
 assert.equal(env.PAY_TO.value,undefined);
 assert(source.includes('process.env.PAY_TO||""'));
});
test("Both existing prices and Base native USDC remain unchanged",()=>{
 assert.equal(PRICE_USDC,"0.02");assert.equal(QUICK_PRICE_USDC,"0.005");
 assert.equal(NETWORK,"eip155:8453");
 assert.equal(USDC_BASE.toLowerCase(),"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
});
test("Deployment does not enable billing credentials or an alternate settlement route",()=>{
 assert(!Object.keys(env).some(k=>/PRIVATE_KEY|API_KEY|TOP.?UP|FALLBACK/.test(k)));
 assert.equal((source.match(/new HTTPFacilitatorClient\(/g)||[]).length,1);
 assert(source.includes('resourceServer.register("eip155:*",new ExactEvmScheme())'));
});
