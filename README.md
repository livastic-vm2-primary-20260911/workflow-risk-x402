# Workflow Risk Check — x402 pay-per-scan API

**An AI-assisted, developer-focused x402 v2 GitHub Actions YAML static preflight, for a tiny 0.02 USDC payment on Base.** Different from VM5's OpenAPI schema lint: this scans **GitHub Actions workflows only** for known source-line heuristics. It is an experimental sales channel for [Workflow Risk Check](https://livastic-vm2-primary-20260911.github.io/workflow-risk-check/).

[Original analyzer & full tests](https://github.com/livastic-vm2-primary-20260911/workflow-risk-check) · [Free local-first browser version](https://livastic-vm2-primary-20260911.github.io/workflow-risk-check/) · [AI-disclosed synthetic report](https://github.com/livastic-vm2-primary-20260911/workflow-risk-check/blob/main/examples/synthetic-paid-preflight-sample.md)

> **Important billing/QA disclosure:** We test the HTTP 402 quote, validate input before billing, and exercise a test-only simulated facilitator end to end. **No live signed real-USDC payment or on-chain settlement has yet been performed.** A mock transaction hash is not earnings, and no client/customer/payout is claimed until a real verified receipt exists.

## Native MCP endpoint for agent marketplaces (public, stateless)

The **same published origin** now has `POST /mcp`, a stateless [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports) server. Its only tool, `analyze_github_actions_yaml`, analyzes a public or synthetic GitHub Actions YAML input (up to 48,000 UTF-8 bytes) with the **same** local heuristic engine as the original REST API.

- Public MCP endpoint: `https://vm2-workflow-x402.onrender.com/mcp`.
- Input: `workflowYaml: string`, optional `filename: "*.yml" | "*.yaml"`.
- Output: source-line findings and a disclaimer. No credential access, wallet signing, transfer, private repo access, or persistence.
- `GET /mcp` returns 405 by design; use an MCP Streamable HTTP client to `initialize`, `tools/list` and `tools/call`. Only a bounded POST JSON body is accepted.
- **Important billing distinction:** This origin MCP route is **free/read-only**. An external listing marketplace may charge a buyer at its own gateway and route calls here, but **the origin has no evidence that marketplace payments settled**, and a raw MCP tool response is never a seller payment receipt. Existing independent x402 paid REST `POST /v1/check` and `GET /v1/public-workflow` still require their original $0.02 Base USDC facilitator settlement; this change does not modify the x402 fee, payee or verification/settlement.
- Marketplace listing is a commercial possibility, not an order. A seller must comply with the marketplace's actual user-age/identity/jurisdiction and payout requirements, and verify unique real on-chain settlement before reporting revenue.
- Rate controls include a maximum four concurrent MCP calls and 30 calls per minute per client/IP; no claims of a complete security audit. The test harness uses the official MCP SDK client over a loopback server, verifies a real tool call and validates that invalid YAML never unlocks a report.

The code is in `mcp-bridge.mjs`; the same local `npm test` suite covers the legacy REST/x402 flows and this transport.

## API contract

- `GET /health` — free JSON readiness (no customer data).
- `GET /v1/docs` — free exact fee, network, payee, limitations and data-handling terms.
- `GET /v1/sample` — **free** complete results on original synthetic `pull_request_target` trap (1 high, 2 medium, 1 note), no payments.
- `GET /openapi.json` and `GET /.well-known/x402` — agent-readable discovery for both paid operations.
- `GET /v1/public-workflow` — **$0.02 native Circle Base USDC**, inspect one anonymously accessible public GitHub Actions YAML via fixed GitHub Contents API. Defaults to the original owned public `workflow-risk-x402/.github/workflows/verify.yml`. Optional strictly validated query parameters are `owner`, `repo`, `ref` (`main`, `master`, or a pinned 40-hex commit), and `file` (one `.yml` or `.yaml` basename). This endpoint returns HTTP **402 to any client before payment**, without uploading YAML or needing a GitHub token.
- `POST /v1/check` — **$0.02 USDC on Base** using the x402 v2 EIP-3009 authorization protocol. JSON body:

```json
{
  "filename": "pr-check.yml",
  "workflowYaml": "on: pull_request\npermissions: {contents: read}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test"
}
```

Validate that the YAML is parseable as a GitHub Actions workflow, is no more than 48,000 UTF-8 bytes, and has no filename path traversal before requiring payment. A valid YAML request without a payment signature receives HTTP **402** and the `PAYMENT-REQUIRED` header identifying network `eip155:8453`, Base USDC contract `0x833589fCD6eDb6E08f4C7C32D4f71b54bdA02913`, and `20000` atomic USDC units. A buyer uses its **own** wallet/signature with its preferred x402 v2 client and resends the same request; this server relies on a separate x402 facilitator for verification and settlement, never receives the buyer's seed phrase.

A successful authenticated response contains rule IDs, exact source lines, severity, explanation, guidance, and rule source links. **A zero-finding result does not certify security.** The source is simply parsed as YAML; never executed and no GitHub token/repository access is required.

For manual API use without paying, use `GET /v1/sample` or [free browser analyzer](https://livastic-vm2-primary-20260911.github.io/workflow-risk-check/).

## Public-only GET buyer quickstart

Inspect the deployed source, limitations and fee for free, then get a real unsigned payment quote:

```bash
curl -i https://vm2-workflow-x402.onrender.com/v1/public-workflow
curl -i "https://vm2-workflow-x402.onrender.com/v1/public-workflow?owner=livastic-vm2-primary-20260911&repo=workflow-risk-x402&ref=main&file=verify.yml"
```

For the default route, the original publicly committed `.github/workflows/verify.yml` is **bundled from this exact GitHub repository at deployment** and checked against its independent Git blob SHA `8892016df7376c6fd7d97fee13e87ab72cfd53ca`. This is an honestly labeled **pinned deployment snapshot, not an always-current remote HEAD**. Non-default allowed source queries use only `api.github.com` with strict filename/owner/ref, no redirects, no forwarded cookies, no buyer secrets and an ~48KB maximum. Public YAML is cached in memory for up to eight minutes to limit unnecessary GitHub calls; it is not persisted by this application. If GitHub fails or the YAML is invalid, the endpoint refuses **before x402 payment**. Only a real independently signed buyer authorization can receive a complete paid report containing source-line findings and GitHub's original blob SHA. A public source scan is not comprehensive security certification, and the third-party hosted API/settlement facilitator can independently log traffic. The original VM1 MetaMask public payout address is set in Render `PAY_TO` as a runtime variable, not any private key.

**Commercial honesty:** live health, an unsigned HTTP 402 quote, and locally faked payment successes are not sales or settled on-chain USDC. A real buyer must complete the exact x402 transaction and receive product; receipt and beneficiary transfer must be independently verified before booking income. The same human owner operates the original VM2 service and separate VM5 API services. Do not mislabel a marketplace operator's verification purchase as an unrelated organic customer.

## Setup and tests

Node.js **22+** and npm. This repo embeds the original MIT licensed `analyzer.mjs` from the VM2 [Workflow Risk Check](https://github.com/livastic-vm2-primary-20260911/workflow-risk-check/blob/main/src/analyzer.mjs), retaining original attribution; the upstream main repository is the canonical free project.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

Tests start a localhost-only test facilitator, use test fixture wallet addresses, and simulate success/failure signatures to verify that only a successful (simulated) authorization obtains full findings. It is **not an actual network settlement test**, and the dummy transaction hash is never included in commercial account records.

**Security-pinned dependency maintenance (2026-10-25):** The official original GitHub Actions security audit discovered vulnerabilities in indirect zod@3, fast-uri@3.1.8, and body-parser@2.3.0. The lockfile now overrides them to zod@4.6.7, fast-uri@3.1.9, and body-parser@2.4.0. Local production npm audit found **zero** moderate-or-higher vulnerabilities, and 37/37 offline simulated x402 tests passed. **Compatibility caveat:** @x402/*@2.28.0 upstream declares zod@^3; overriding to security-fixed Zod 4 is not an upstream guarantee for all signed payment payloads. Keep the CI regression and dependency audit gates, monitor upstream x402 versions for an officially supported fixed Zod, and never count fake test signatures as onchain payment.

Run locally with **your own controlled, Base-compatible payee**:

```bash
PAY_TO=0xYOUR_EXISTING_CONTROLLED_BASE_RECEIVER PUBLIC_ORIGIN=http://127.0.0.1:8737 \
  NODE_ENV=test HOST=127.0.0.1 PORT=8737 npm start
```

The example uses `NODE_ENV=test` only for localhost exploration; **do not publish test mode**. For real deployment, explicitly provide `PAY_TO=0x...`, `PUBLIC_ORIGIN=https://your-real-host`, `HOST=0.0.0.0`, a trusted `https://` facilitator, and `NODE_ENV=production`. No wallet private key, EOA key or API key is used by this server.

## Safe deployment

The included `render.yaml` is for a **Render Free** web service, no uptime SLA. Free Render services can sleep after 15 minutes idle and wake slowly; users should expect cold starts. For the deployment to be reachable and accept payments, configure `PAY_TO` to a verified VM2-controlled payout address through secure Render environment settings. Do **not** commit the address or any secret material to public source. The application deliberately fails startup when `PAY_TO` or HTTPS `PUBLIC_ORIGIN` is missing. Do not use a dummy test wallet on a real hosted service.

The hosted external facilitator is `https://facilitator.openx402.ai`; its trust, service availability and settlement behavior are separate from the application. No observed live payment is asserted by running `npm test`.

## Security, privacy and commercial limitations

- **Not a security audit.** Static rule matching yields false positives and false negatives. Review `pull_request_target`, script interpolation, third-party pins, artifact reuse, self-hosted runner exposure, least privileges with real repository context.
- Processes only public or explicitly authorized YAML snippets; **do not send secrets**, customer credentials, private repositories, seeds, wallet backups, or other confidential code.
- Application code does not persist submitted YAML, payment headers, IP addresses or customer data to disk, does not enable app-level analytics, and does not store customer submission content. Hosting platform and the external payment facilitator have independent request/access logs.
- Body is limited to 70 KiB, with a 48,000 byte YAML input limit, prepayment syntactic validation, 2 concurrent scans and 70 requests/minute/IP. For a valid request without signature, the complete report is *not* returned free.
- Do not claim a successful x402 payment merely because HTTP 402 works. Check actual transaction hash on a Base explorer and independently confirm receipt at the authorized payee address; track paid orders separately from inbound bot requests.
- Processing errors after valid payment would require manual customer remediation and refund/credit handling under the external facilitator's applicable terms.
- No hidden automatic paid subscription; each valid call requires an explicit client-signed payment. No funds are spent or wallets funded by the operator just to run tests.
- Reuse/modification of original Workflow Risk Check is under the MIT license. Inspired by [VM5's independently maintained x402 OpenAPI lint](https://github.com/livastic-vm5-primary-20260911/x402-openapi-lint); no shared payee, customer data or revenue is implied.

## License

MIT; original Workflow Risk Check rules and other public sources retain their own licenses.
