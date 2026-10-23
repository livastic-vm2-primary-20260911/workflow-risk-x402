# GitHub Actions fork-PR trust boundary — defensive checklist

**Scope:** a public GitHub repository receiving an untrusted pull request. This is a hardening guide and regression fixture for Workflow Risk Check, not a pen-test result, claim of exploitation, or security certification. The examples contain **no credentials, tokens, private repositories, or executable attack payloads**.

## Threat boundary

A fork contributor may change files in their PR. A workflow triggered by `pull_request_target` executes in the base repository's security context. Combining that event with a checkout of the fork's head, a write-enabled `GITHUB_TOKEN`, or secrets can move untrusted code into a privileged job. Merely using `pull_request_target` does **not** prove an exploit; the dangerous condition is where untrusted changes are later executed with privileged credentials.

### Insecure illustration — DO NOT DEPLOY

```yaml
name: Example of unsafe PR trust boundary
on:
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
```

Here an untrusted fork-controlled revision could be checked out under `pull_request_target`. The broad workflow token is also unnecessary. This example is deliberately static; do not run it in an actual privileged repository.

### Safer unprivileged illustration

```yaml
name: Read-only fork PR lint
on:
  pull_request:
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - run: npm run lint
```

The second workflow runs on the less-privileged `pull_request` event, explicitly requests read-only token permissions, uses a SHA-pinned third-party action, and disables persistence of the checkout token. The `lint` script is still **code from the PR**: never inject credentials, secrets, cloud tokens, or self-hosted runners into this job. A fork may provide malicious package scripts; the isolation is the security property, not trust in the PR code itself. A hash pin must be reviewed and updated when the upstream maintainer releases a security update.

## Practical rollout for repository owners

1. Inventory all workflows using `pull_request_target`, `workflow_run`, write scopes, `secrets.*`, artifacts or reusable workflows. Prefer an isolated source-only reader job that never executes fork code when privileged context is essential.
2. Split analysis of untrusted PR revisions into short-lived, least-privilege, non-self-hosted jobs with no secrets. Do not pass untrusted text directly into shell scripts through `${{ github.event.* }}`; pass it via carefully quoted environment variables and validate formats.
3. Require a human maintainer to approve any privileged follow-up or merge-critical policy change; avoid having untrusted artifacts or runner caches cross from low-trust to privileged jobs. Third-party actions should be reviewed and pinned to full source commit hashes.
4. Confirm the workflow trigger and effective token grants in the repository's own settings. Review branch protections, fork approval policies, dependency scripts, job-level permissions, and organization defaults; **a green static scan does not establish overall security**.
5. Test only on a repository you own or are explicitly authorized to configure. Use a fictional PR fixture and remove it after validation. Never test these unsafe samples against someone else's CI.

**Reproduce locally:** `npm test` runs the paired static fixtures through the original parser and asserts that the unsafe case produces high-severity diagnostics and the lower-privilege case does not. It neither starts a GitHub workflow nor calls the network. The API never stores user YAML in application logic, but external hosting and facilitator logs have separate rules.

Primary references: [GitHub's automatic token permissions](https://docs.github.com/en/actions/security-guides/automatic-token-authentication), [GitHub Security Lab: preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/), and [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions).

*Authorship: one owner, AI-assisted original defensive guidance; no independent maintainer approval, customer audit, or paid reward implied by writing this file.*
