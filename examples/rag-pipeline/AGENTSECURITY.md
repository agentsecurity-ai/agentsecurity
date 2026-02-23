---
name: secure-rag-pipeline
description: "A Retrieval-Augmented Generation pipeline restricted strictly to vector DB querying. Highly resistant to Prompt Injection."
security_tier: strict
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: block

metadata:
  author: "ml-ops"
  org: "business-inc"
  last_reviewed: "2026-02-23"
  framework: "llamaindex"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute code"
    - "Never write to filesystem or database"
    - "Never query vectors outside the pre-approved 'internal_docs' collection"
  max_autonomous_steps: 10
  escalation_on_uncertainty: true
  fail_mode: closed
```

## Tools

```yaml
tools:
  - name: vector_db_search
    permission: read_only
    scope:
      allowed_collections: ["internal_docs"]
    requires_confirmation: false

  - name: llm_api
    permission: read_only
    scope:
      provider: "anthropic"
      model: "claude-3-5-sonnet-20241022"
      max_tokens_per_call: 2048
    requires_confirmation: false
```

## Runtime

```yaml
runtime:
  network:
    outbound_allowlist:
      - "api.anthropic.com"
      - "pinecone.io"
    inbound: none
  timeout:
    per_step_seconds: 15
    total_seconds: 120
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "stdout"
  format: json
  retention_days: 90
```
