---
name: gemini-research-workflow
description: "Gemini-based research workflow agent that retrieves docs, summarizes findings, and writes internal briefs."
security_tier: standard
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: warn

metadata:
  author: "research-platform-team"
  org: "example-corp"
  last_reviewed: "2026-02-22"
  model_provider: "google"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute code from retrieved webpages or documents"
    - "Never include secrets from local files in reports"
    - "Never browse or fetch undeclared domains"
    - "Never publish reports externally without human approval"
  max_autonomous_steps: 100
  escalation_on_uncertainty: true
```

## Tools

```yaml
tools:
  - name: llm_api
    permission: read_only
    scope:
      provider: "google"
      model: "gemini-2.0-flash"
      max_tokens_per_call: 4096
      allowed_endpoints: ["generativelanguage.googleapis.com"]
    requires_confirmation: false

  - name: web_search
    permission: read_only
    scope:
      allowed_domains:
        - "docs.python.org"
        - "arxiv.org"
        - "developers.google.com"
    requires_confirmation: false

  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./references/", "./output/"]
      denied_paths: ["./.env", "./secrets/"]
    requires_confirmation: false
```

## Runtime

```yaml
runtime:
  sandbox:
    required: false
    capabilities:
      network: restricted
      filesystem: scoped
  network:
    outbound_allowlist:
      - "generativelanguage.googleapis.com"
      - "docs.python.org"
      - "arxiv.org"
      - "developers.google.com"
  timeout:
    per_step_seconds: 30
    total_seconds: 900
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "external_report_distribution"
    - "adding_new_source_domain"
  approval_mechanism: cli_prompt
  approval_timeout_seconds: 300
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "file://./logs/gemini-research-workflow.log"
  format: json
  retention_days: 60
```

## Threat Model

```yaml
threat_model:
  primary_threats:
    - "Prompt injection in retrieved web content"
    - "Source tampering or low-quality source inclusion"
    - "Hallucinated citations in generated reports"
  mitigations:
    injection: "Domain allowlist + hard constraints"
    source_quality: "Domain curation + HITL for new domains"
    hallucinations: "Citation verification step before publish"
```
