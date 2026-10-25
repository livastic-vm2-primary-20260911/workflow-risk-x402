/**
 * Original VM2 lower-price SKU: exact same deterministic static YAML checks,
 * bounded short-form finding summary, no buyer secrets, no protocol bypass.
 * This file computes report formatting only; x402 middleware protects paid content.
 */
import {RULESET,NETWORK,USDC_BASE} from "./core.mjs";

export const QUICK_PRICE_USDC="0.005";
export const QUICK_PRICE_ATOMIC="5000";
const severityRank={high:0,medium:1,note:2,low:3};

export function quickResponse({report,bytes,filename}){
 if(!report || typeof report!=="object" || !report.counts || !Array.isArray(report.findings))throw Error("Unexpected original scanner report");
 const sorted=report.findings
  .filter(f=>f && typeof f==="object")
  .sort((a,b)=>(severityRank[a.severity]??9)-(severityRank[b.severity]??9))
  .slice(0,3)
  .map(f=>({
    id:typeof f.id==="string"?f.id.slice(0,110):"",
    severity:typeof f.severity==="string"?f.severity:"",
    line:Number.isSafeInteger(f.line)?f.line:null
  }));
 return {
  ok:true,product:"VM2 Quick Workflow Risk",
  ruleset:RULESET,
  input:{filename,bytes},
  counts:{high:report.counts.high??0,medium:report.counts.medium??0,note:report.counts.note??0},
  topSignals:sorted,
  moreSignalsAvailable:report.findings.length>sorted.length,
  paid_x402:{
   currency:"USDC",network:NETWORK,asset:USDC_BASE,price:QUICK_PRICE_USDC,
   disclaimer:"The x402 facilitator handled payment verification; this response is NOT independent proof a Base USDC transfer was finalized."
  },
  limitations:"Short heuristic preview only, not a formal security audit or a complete finding report. Never trust a zero-finding result as approval."
 };
}
