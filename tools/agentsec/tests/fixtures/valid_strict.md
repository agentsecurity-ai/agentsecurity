---
name: test-strict-agent
description: "A strict tier agent with full security controls for validation testing"
security_tier: strict
version: "0.1"

governance:
  - OWASP-LLM-TOP10
  - NIST-AI-RMF

enforcement: block

metadata:
  author: "test-team"
  org: "test-org"
  last_reviewed: "2026-02-22"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute eval() or exec()"
    - "Never access files outside workspace"
  max_autonomous_steps: 50
  escalation_on_uncertainty: true
  fail_mode: closed
```

## Tools

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./src/"]
      denied_paths: ["./.env"]
    requires_confirmation: true

  - name: web_search
    permission: read_only
    scope:
      allowed_domains: ["docs.python.org"]
    requires_confirmation: false
```

## Runtime

```yaml
runtime:
  sandbox:
    required: true
    type: docker
    capabilities:
      network: restricted
      filesystem: scoped
  network:
    outbound_allowlist:
      - "api.example.com"
  timeout:
    per_step_seconds: 30
    total_seconds: 600
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "file_deletion"
    - "external_api_calls"
  approval_mechanism: cli_prompt
  approval_timeout_seconds: 300
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "file://./logs/agent.log"
  format: json
  retention_days: 365
  alert_on:
    - "policy_violation"
```
