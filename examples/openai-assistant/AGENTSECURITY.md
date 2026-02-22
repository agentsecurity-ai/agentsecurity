---
name: openai-support-agent
description: "OpenAI-based support triage agent that summarizes tickets, drafts responses, and updates issue metadata."
security_tier: standard
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: warn

metadata:
  author: "support-platform-team"
  org: "example-corp"
  last_reviewed: "2026-02-22"
  model_provider: "openai"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute shell commands generated from ticket content"
    - "Never expose full customer PII in generated responses"
    - "Never call undeclared external endpoints"
    - "Never auto-close tickets without confidence >= 0.9 and human review"
  max_autonomous_steps: 80
  escalation_on_uncertainty: true
```

## Tools

```yaml
tools:
  - name: llm_api
    permission: read_only
    scope:
      provider: "openai"
      model: "gpt-5-mini"
      max_tokens_per_call: 4096
      allowed_endpoints: ["api.openai.com"]
    requires_confirmation: false

  - name: ticketing_api
    permission: read_write
    scope:
      allowed_operations: [read_ticket, update_tags, draft_reply]
      denied_operations: [delete_ticket, close_ticket, export_all]
    requires_confirmation: true

  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./kb/", "./output/"]
      denied_paths: ["./secrets/", "./.env"]
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
      - "api.openai.com"
      - "tickets.example.internal"
  timeout:
    per_step_seconds: 30
    total_seconds: 600
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "ticket_status_change"
    - "customer_visible_response_send"
  approval_mechanism: web_ui
  approval_timeout_seconds: 300
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "file://./logs/openai-support-agent.log"
  format: json
  retention_days: 90
```

## Threat Model

```yaml
threat_model:
  primary_threats:
    - "Prompt injection through user-submitted ticket text"
    - "Sensitive customer info leakage in drafted responses"
    - "Unauthorized ticket state transitions from model hallucinations"
  mitigations:
    injection: "Strict tool allowlist + no shell tools + HITL"
    pii_leakage: "Redaction filters + audit review"
    state_change: "Approval gate on status changes"
```
