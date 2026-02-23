---
name: med-compliance-agent
description: "Healthcare agent handling PHI. Operates within HIPAA bounds, no data transmission outside the boundary."
security_tier: regulated
version: "0.1"

governance:
  - OWASP-LLM-TOP10
  - HIPAA
  - NIST-AI-RMF

enforcement: block_and_audit

metadata:
  author: "clinical-ai"
  org: "health-system"
  last_reviewed: "2026-02-23"
  data_classification: "phi"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never store PHI outside of the secure local vault"
    - "Never transmit patient names or IDs over external network"
    - "Never execute generic python code"
  max_autonomous_steps: 15
  data_handling:
    pii_detection: required
    pii_anonymization: required
    data_residency: "US"
```

## Tools

```yaml
tools:
  - name: ehr_read
    permission: read_only
    scope:
      allowed_endpoints: ["https://api.internal.hospital.local/fhir/"]
    requires_confirmation: false

  - name: ehr_write
    permission: write_only
    scope:
      allowed_endpoints: ["https://api.internal.hospital.local/fhir/"]
    requires_confirmation: true
    audit_every_call: true

  - name: llm_api
    permission: read_only
    scope:
      provider: "anthropic"
      model: "claude-3-opus-20240229"
      # Model must run on HIPAA BAA-covered tenant
      allowed_endpoints: ["api.anthropic.com"]
```

## Runtime

```yaml
runtime:
  sandbox:
    required: true
    type: gvisor
  network:
    outbound_allowlist:
      - "api.anthropic.com"
      - "api.internal.hospital.local"
  timeout:
    per_step_seconds: 15
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "any_write_operation"
    - "diagnosis_generation"
  approval_mechanism: web_ui
  require_justification: true
  dual_approval: true
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "s3://hipaa-audit-logs/"
  format: json
  retention_days: 2555
  tamper_protection: true
```
