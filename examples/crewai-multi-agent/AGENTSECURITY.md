---
name: crewai-research-team
description: "A multi-agent CrewAI setup containing a Researcher and a Writer to analyze topics and write reports."
security_tier: standard
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: warn

metadata:
  author: "ai-team"
  org: "example-corp"
  last_reviewed: "2026-02-23"
  framework: "crewai"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute dynamic Python code"
    - "Never write to the local filesystem outside of the ./outputs/ directory"
    - "Never communicate directly with undocumented external APIs"
  max_autonomous_steps: 50
  escalation_on_uncertainty: true
```

## Tools

```yaml
tools:
  - name: web_search
    permission: read_only
    scope:
      allowed_domains: ["wikipedia.org", "arxiv.org", "github.com"]
    requires_confirmation: false

  - name: file_write
    permission: write_only
    scope:
      allowed_paths: ["./outputs/"]
    requires_confirmation: false

  - name: llm_api
    permission: read_only
    scope:
      provider: "openai"
      model: "gpt-4o"
      max_tokens_per_call: 8192
    requires_confirmation: false
```

## Runtime

```yaml
runtime:
  network:
    outbound_allowlist:
      - "api.openai.com"
      - "wikipedia.org"
      - "arxiv.org"
      - "github.com"
  timeout:
    per_step_seconds: 60
    total_seconds: 1800
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "publishing_report"
  approval_mechanism: cli_prompt
  approval_timeout_seconds: 300
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "file://./logs/crewai_audit.log"
  format: json
  retention_days: 30
```
