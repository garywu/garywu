# Security Posture Policies (Conftest)

This repository contains our centralized OPA/Conftest Rego policies that govern the security posture of our Cloudflare fleet. 
We use an **Atlantis-style PR Gating** approach. Every PR that modifies a `wrangler.jsonc` file or a `.github/workflows/*.yml` file will be evaluated against these rules.

## How to Enroll a Repository

To enroll a repository in the security checks, add the following file to `.github/workflows/security-check.yml`:

```yaml
name: Security Checks
on: [pull_request]
jobs:
  security:
    uses: garywu/standard/.github/workflows/security-check.yml@main
```

## How to Read a Rego File

Rego is the language used by the Open Policy Agent (OPA).
- A `deny` block that evaluates to `true` means the policy *failed*, and the PR will be blocked.
- A `warn` block will surface a comment/warning but will not block the PR.
- We rely on heuristics to determine if a worker is a "backend" (e.g. no assets binding, doesn't end in `-frontend`).

## Adding a New Policy
1. Add your rule to `policies/wrangler-config.rego` or `policies/gha-secrets.rego`.
2. Add a passing and failing test fixture in `policies/__tests__/`.
3. Initially start the rule as `warn[msg]`. After a week of observation with 0 false positives, promote it to `deny[msg]`.
