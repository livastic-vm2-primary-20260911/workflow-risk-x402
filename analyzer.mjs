import YAML from "yaml";

const DOCS = Object.freeze({
  permissions: "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
  targets: "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
  pin: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
  script: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
  runners: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-github-hosted-runners",
  reusable: "https://docs.github.com/en/actions/sharing-automations/reusing-workflows"
});
const level = {high: 0, medium: 1, note: 2};
const isObject = x => x !== null && typeof x === "object" && !Array.isArray(x);
const truthyKey = (obj,key) => isObject(obj) && Object.prototype.hasOwnProperty.call(obj,key);
const normalizeEvents = (on) => {
  if(typeof on === "string") return [on];
  if(Array.isArray(on)) return on.filter(x=>typeof x==="string");
  if(isObject(on)) return Object.keys(on);
  return [];
};
function normalizedUses(x) { return String(x || "").trim(); }
function isExternalAction(x) {
  return x && !x.startsWith("./") && !x.startsWith("docker://") && !x.startsWith(".\\");
}
function isHashPinned(x) { return /@[a-f0-9]{40}$/i.test(x); }
function containsUntrustedInterpolation(x) {
  const text = String(x || "");
  return /\$\{\{\s*(?:github\.head_ref\b|github\.event\.(?:issue|pull_request|comment|review|head_commit|commits|discussion)(?:\.|\[|\b))[^}]*\}\}/i.test(text);
}
function containsHeadRef(x) {
  return /\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.head_ref)\b/i.test(String(x||""));
}
function isSelfHosted(x) {
  if (typeof x === "string") return x.toLowerCase() === "self-hosted";
  if (Array.isArray(x)) return x.some(isSelfHosted);
  if (isObject(x)) return isSelfHosted(x.labels);
  return false;
}
function hasArtifactDownload(steps) {
  return steps.some(s => /^(actions\/download-artifact|dawidd6\/action-download-artifact)@/i.test(normalizedUses(s?.uses)));
}
function hasRunStep(steps) { return steps.some(s => typeof s?.run === "string" && s.run.trim()); }
function writeScopes(x) {
  if(typeof x === "string") return x === "write-all" ? ["all"] : [];
  if(!isObject(x)) return [];
  return Object.entries(x).filter(([,v]) => String(v).toLowerCase() === "write").map(([k])=>k);
}

/**
 * Conservative static rules. This is NOT a security certification, policy engine,
 * or a substitute for runtime context and code review.
 * @returns {{file: string, events:string[], findings:object[], counts:object, error?:string}}
 */
export function analyzeWorkflow(input, name = "workflow.yml") {
  const file = String(name).slice(0,160);
  const result = {file, events: [], findings: [], counts: {high:0, medium:0, note:0}};
  if(typeof input !== "string" || input.trim().length === 0) {
    return {...result,error:"Paste a GitHub Actions workflow YAML file to begin."};
  }
  if(input.length > 240_000) {
    return {...result,error:"File too large. Maximum 240,000 characters per workflow."};
  }
  let wf;
  let doc;
  const lineCounter = new YAML.LineCounter();
  try {
    doc = YAML.parseDocument(input, {uniqueKeys:true, version:"1.2", lineCounter});
    if(doc.errors.length) throw new Error(doc.errors[0].message);
    wf = doc.toJS({maxAliasCount:100});
  } catch (e) {
    return {...result,error:"YAML parse error: " + String(e?.message||e).slice(0,220)};
  }
  if(!isObject(wf) || !truthyKey(wf,"jobs")) {
    return {...result,error:"This does not appear to be a GitHub Actions workflow (missing top-level jobs: mapping)."};
  }
  if(!isObject(wf.jobs)) {
    return {...result,error:"The jobs: value must be a mapping."};
  }
  const events = normalizeEvents(wf.on);
  result.events = events;
  const findings = result.findings;
  const jobNames=Object.keys(wf.jobs).sort((a,b)=>b.length-a.length);
  const lineFor = where => {
    try {
      let keys;
      if(where.startsWith("workflow / "))keys=[where.slice("workflow / ".length)];
      else if(where.startsWith("jobs.")){
        const rest=where.slice("jobs.".length);
        const id=jobNames.find(k=>rest===k || rest.startsWith(k+"."));
        if(!id)return 1;
        keys=["jobs",id];
        const tail=rest.slice(id.length);
        for(const match of tail.matchAll(/\.([a-zA-Z0-9_-]+)|\[(\d+)\]/g)){
          keys.push(match[1] || Number(match[2])-1);
        }
      }else return 1;
      const n=doc.getIn(keys,true);
      return n?.range && n.range[0]>=0 ? lineCounter.linePos(n.range[0]).line : 1;
    }catch{return 1;}
  };
  const add = (severity, id, title, where, description, recommendation, source) => {
    findings.push({severity, id, title, where, description, recommendation, source, line:lineFor(where)});
  };
  const hasPullRequest = events.includes("pull_request");
  const hasPullRequestTarget = events.includes("pull_request_target");
  const hasWorkflowRun = events.includes("workflow_run");
  const untrustedEvent = hasPullRequest || hasPullRequestTarget || events.includes("issues") || events.includes("issue_comment") || events.includes("discussion_comment");
  const tokenWrite = writeScopes(wf.permissions);
  if(wf.permissions === "write-all") {
    add("high", "TOKEN_WRITE_ALL", "Workflow grants every available token write scope", "workflow / permissions",
      "permissions: write-all provides broad GITHUB_TOKEN privileges across jobs.",
      "Declare the minimum named permissions, preferably read-all or permissions: {} at the workflow level and opt individual jobs into writes.", DOCS.permissions);
  } else if (!truthyKey(wf,"permissions")) {
    add("note", "DEFAULT_TOKEN", "Workflow does not declare token permissions", "workflow / permissions",
      "Effective permissions depend on repository/org default settings and event type; this is not proof of an exploit.",
      "Consider explicit top-level permissions: contents: read (or {}) and grant writes only in jobs that require them.", DOCS.permissions);
  } else if (tokenWrite.length && untrustedEvent) {
    add("medium", "WORKFLOW_WRITE", "Workflow-level token has write permissions with externally triggered events",
      "workflow / permissions", "Write-capable scopes: " + tokenWrite.join(", ") + ". Exposure depends on the trigger and job trust boundaries.",
      "Move necessary writes to trusted jobs with tight conditions and use the smallest scopes possible.", DOCS.permissions);
  }
  if(hasPullRequestTarget) {
    add("note", "TARGET_CONTEXT", "pull_request_target requires a trusted-code boundary", "workflow / on",
      "The event may run in the base repository's privileged context. Merely enabling it is not necessarily vulnerable.",
      "Avoid running untrusted PR changes or content in this event; check out only trusted base code.", DOCS.targets);
  }
  for(const [jobId,job] of Object.entries(wf.jobs)) {
    if(!isObject(job)) continue;
    const loc = "jobs." + jobId;
    const steps = Array.isArray(job.steps) ? job.steps.filter(isObject) : [];
    const jobScopes = writeScopes(job.permissions);
    if(job.permissions === "write-all") {
      add("high","JOB_WRITE_ALL","Job grants every available token write scope",loc+".permissions",
        "This job asks GitHub for write access to all GITHUB_TOKEN permissions.",
        "Define only the specific required scopes under job permissions.", DOCS.permissions);
    } else if(jobScopes.length && untrustedEvent) {
      add("medium","JOB_WRITE","Write-capable job in externally triggered workflow",loc+".permissions",
        "Job write scopes: " + jobScopes.join(", ") + ". Whether this can be exploited requires reviewing the job's execution path.",
        "Use precise trigger conditions and minimum scopes; separate trusted publishers from PR checks.", DOCS.permissions);
    }
    if((hasPullRequest || hasPullRequestTarget) && isSelfHosted(job["runs-on"])) {
      add("medium", "SELF_HOSTED_PR", "Self-hosted runner processes PR-related workflow",loc+".runs-on",
        "Untrusted contributions can create persistent risks on self-hosted workers if job code is not fully trusted.",
        "Prefer GitHub-hosted or ephemeral isolated runners; tightly restrict who can trigger self-hosted jobs.", DOCS.runners);
    }
    if(typeof job.uses === "string") {
      const u = normalizedUses(job.uses);
      if(isExternalAction(u) && !isHashPinned(u)) {
        add("medium", "REUSABLE_UNPINNED", "Reusable workflow uses a mutable ref",loc+".uses",
          u + " may change when a tag or branch is moved.",
          "Reference an audited immutable commit SHA and keep updates reviewed.", DOCS.pin);
      }
      if(isExternalAction(u) && job.secrets === "inherit") {
        add("medium", "INHERITED_SECRETS", "Reusable workflow inherits caller secrets",loc+".secrets",
          "secrets: inherit shares available secrets with the called workflow.",
          "Pass only the named secrets required and review the called workflow's source and permissions.", DOCS.reusable);
      }
    }
    let headCheckoutIndex = -1;
    steps.forEach((step,i) => {
      const place = loc + ".steps[" + (i+1) + "]";
      const uses = normalizedUses(step.uses);
      if(isExternalAction(uses) && !isHashPinned(uses)) {
        add("medium", "ACTION_UNPINNED", "Third-party action uses a mutable ref",place+".uses",
          uses + " is not pinned to a 40-character immutable commit SHA.",
          "Pin this action to a reviewed full commit SHA; keep a version comment for Dependabot/Renovate.", DOCS.pin);
      }
      if(hasPullRequestTarget && /^actions\/checkout@/i.test(uses) && (containsHeadRef(step.with?.ref) || containsHeadRef(step.with?.repository))) {
        headCheckoutIndex = i;
      }
      if(containsUntrustedInterpolation(step.run)) {
        add("high", "SHELL_INTERPOLATION", "Untrusted event data interpolated directly into shell code",place+".run",
          "An event field such as PR title, issue title, comment body, or head ref appears inside run:. Attacker-controlled text could become shell syntax.",
          "Assign the expression to an env: variable, then reference the safely quoted environment variable in the script; validate data as needed.", DOCS.script);
      }
      if(typeof step.run === "string" && /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(step.run)) {
        add("medium", "REMOTE_SHELL", "Remote script piped into a shell",place+".run",
          "A network response is executed as shell commands during CI.",
          "Download a versioned asset, validate its hash or signature, then run the reviewed artifact.", DOCS.pin);
      }
    });
    if(hasPullRequestTarget && headCheckoutIndex >= 0 && steps.slice(headCheckoutIndex+1).some(s => typeof s.run==="string" && s.run.trim())) {
      add("high", "TARGET_UNTRUSTED_CODE", "PR head checkout followed by script execution under pull_request_target",loc+".steps",
        "A checkout of an external PR head precedes later run: steps in an event that can have privileged repository context.",
        "Use pull_request for untrusted build/test code and an isolated trusted workflow for any privileged action.", DOCS.targets);
    }
    if(hasWorkflowRun && hasArtifactDownload(steps) && hasRunStep(steps)) {
      add("medium", "WORKFLOW_RUN_ARTIFACT", "workflow_run downloads artifacts and executes shell steps",loc+".steps",
        "If artifacts originate from an untrusted prior workflow, treating their contents as trusted may expose secrets or write privileges.",
        "Validate provenance and contents; do not execute untrusted downloaded files in a privileged workflow.", DOCS.targets);
    }
  }
  findings.sort((a,b)=>level[a.severity]-level[b.severity] || a.where.localeCompare(b.where));
  if(findings.length > 70) {
    result.findings = findings.slice(0,69);
    result.findings.push({severity:"note",id:"TRUNCATED",title:"Findings limit reached",where:"workflow",description:"The report shows a bounded sample of the findings.",recommendation:"Review action pins at repository scale with complementary linters.",source:DOCS.pin});
  }
  for(const f of result.findings) result.counts[f.severity] += 1;
  return result;
}
