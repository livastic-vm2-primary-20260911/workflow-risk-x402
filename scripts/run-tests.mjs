// Test-only local facilitator: verifies fake byte marker, never signs or settles Base USDC.
import http from "node:http";
import net from "node:net";
import {spawn} from "node:child_process";
import {once} from "node:events";
const TEST_PAYTO="0x"+"44".repeat(20);
async function getPort(){
 const s=net.createServer();s.listen(0,"127.0.0.1");await once(s,"listening");
 const p=s.address().port;await new Promise(ok=>s.close(ok));return p;
}
const facilitator=http.createServer((req,res)=>{
 res.setHeader("Content-Type","application/json");
 if(req.method==="GET" && req.url==="/supported"){
  res.end(JSON.stringify({kinds:[{x402Version:2,scheme:"exact",network:"eip155:8453",
   extra:{name:"USD Coin",version:"2",asset:"0x833589fCD6eDb6E08f4C7C32D4f71b54bdA02913",assetTransferMethod:"eip3009"}}],
   extensions:["discovery"],signers:{"eip155:*":["0x"+"00".repeat(20)]}}));
  return;
 }
 if(req.method==="POST" && ["/verify","/settle"].includes(req.url)){
  let b="";req.on("data",c=>b+=c);req.on("end",()=>{
   let data={};try{data=JSON.parse(b)}catch{}
   const requirements=data?.paymentRequirements;
   const valid=data?.x402Version===2 && requirements?.network==="eip155:8453" &&
    requirements?.amount==="20000" && requirements?.payTo?.toLowerCase()===TEST_PAYTO.toLowerCase() &&
    data?.paymentPayload?.payload?.signature==="0x"+"11".repeat(65);
   if(req.url==="/verify"){
    res.end(JSON.stringify({isValid:valid,payer:"0x"+"33".repeat(20),
     invalidReason:valid?undefined:"test_fixture_bad_marker"}));
   }else{
    res.end(JSON.stringify({success:valid,transaction:"0x"+"22".repeat(32),network:"eip155:8453",
     amount:valid?"20000":"0",payer:"0x"+"33".repeat(20),errorReason:valid?undefined:"test_fixture_bad_marker"}));
   }
  });return;
 }
 res.statusCode=503;res.end(JSON.stringify({error:"mock only supports supported, verify, settle"}));
});
facilitator.listen(0,"127.0.0.1");await once(facilitator,"listening");
const port=await getPort();
const env={...process.env,PORT:String(port),HOST:"127.0.0.1",NODE_ENV:"test",
 PAY_TO:TEST_PAYTO,TEST_PAYTO,TEST_URL:"http://127.0.0.1:"+port,
 FACILITATOR_URL:"http://127.0.0.1:"+facilitator.address().port};
const service=spawn(process.execPath,["server.mjs"],{cwd:new URL("../",import.meta.url),
 env,stdio:["ignore","pipe","pipe"]});
let log="";
service.stdout.on("data",chunk=>log+=String(chunk));
service.stderr.on("data",chunk=>log+=String(chunk));
async function ready(){
 for(let i=0;i<65;i++){
  if(service.exitCode!==null)throw Error("VM2 service process exit: "+log.slice(-1500));
  try{const r=await fetch(env.TEST_URL+"/health",{signal:AbortSignal.timeout(1500)});if(r.ok)return;}
  catch{}
  await new Promise(r=>setTimeout(r,225));
 }
 throw Error("Timed out waiting for local service: "+log.slice(-1500));
}
let result=1;
try{
 await ready();
 const tests=spawn(process.execPath,["--test","tests/core.test.mjs","tests/api.test.mjs","tests/security-guide.test.mjs"],
  {cwd:new URL("../",import.meta.url),env,stdio:"inherit"});
 const [code]=await once(tests,"close");
 result=code??1;
}catch(e){console.error("TEST_HARNESS_ERROR",e.stack||e);}
finally{service.kill("SIGTERM");facilitator.close();}
process.exitCode=result;
