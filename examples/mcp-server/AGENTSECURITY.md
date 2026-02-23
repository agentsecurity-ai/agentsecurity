---
name: github-mcp-server
description: "Model Context Protocol server that wraps GitHub. Restricted to an allowlisted repository, enforces HITL on commits."
security_tier: strict
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: block

metadata:
  author: "developer-productivity"
  org: "business"
  last_reviewed: "2026-02-23"
  framework: "mcp"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never delete branches or repositories"
    - "Never execute arbitrary python code"
    - "Never modify GitHub Actions workflows in .github/workflows/"
  max_autonomous_steps: 20
  escalation_on_uncertainty: true
  fail_mode: closed
```

## Tools

```yaml
tools:
  - name: github_read
    permission: read_only
    scope:
      allowed_repos: ["example-corp/agentsecurity"]
    requires_confirmation: false

  - name: github_write
    permission: write_only
    scope:
      allowed_repos: ["example-corp/agentsecurity"]
      denied_paths: [".github/workflows/"]
      denied_operations: ["delete_repository", "delete_branch"]
    requires_confirmation: true
```

## Runtime

```yaml
runtime:
  network:
    outbound_allowlist:
      - "api.github.com"
  timeout:
    per_step_seconds: 30
    total_seconds: 1200
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "create_pull_request"
    - "commit_code"
  approval_mechanism: slack
  approval_timeout_seconds: 600
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "stdout"
  format: json
```
