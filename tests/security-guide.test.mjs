import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {normalizeInput} from "../core.mjs";

const guide = readFileSync(new URL("../docs/FORK_PR_WORKFLOW_HARDENING.md", import.meta.url), "utf8");
const snippets = [...guide.matchAll(/\`\`\`yaml\n([\s\S]*?)\n\`\`\`/g)].map(x => x[1]);

test("hardening guide has one unsafe and one safer runnable YAML fixture", () => {
  assert.equal(snippets.length, 2);
  for (const workflowYaml of snippets) assert.equal(normalizeInput({workflowYaml}).ok, true);
});

test("untrusted PR target with broad token is caught by source-line heuristic", () => {
  const result = normalizeInput({workflowYaml: snippets[0]});
  assert.equal(result.ok, true);
  assert.ok(result.report.counts.high >= 1);
  const ids = new Set(result.report.findings.map(x => x.id));
  assert.ok(ids.has("TARGET_UNTRUSTED_CODE"), "expected checked-out fork head to trigger a high-severity rule");
  assert.ok(ids.has("TOKEN_WRITE_ALL"), "expected write-all to trigger a high-severity rule");
});

test("read-only fork PR fixture removes high-severity trust-boundary signal", () => {
  const result = normalizeInput({workflowYaml: snippets[1]});
  assert.equal(result.ok, true);
  assert.equal(result.report.counts.high, 0);
  assert.equal(result.report.counts.medium, 0);
});

test("hardening note discloses scope, risk and original sources", () => {
  assert.match(guide, /not a pen-test result/);
  assert.match(guide, /no secrets/i);
  assert.match(guide, /no independent maintainer approval/i);
  assert.match(guide, /securitylab\.github\.com/);
});
