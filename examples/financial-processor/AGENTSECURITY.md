---
name: financial-processor
description: "Processes financial transactions via Stripe API, reads customer database, generates invoices. Handles PII and payment data."
security_tier: strict
version: "0.1"

governance:
  - OWASP-LLM-TOP10
  - NIST-AI-RMF
  - PCI-DSS

enforcement: block

metadata:
  author: "fintech-team"
  org: "fintech-corp"
  last_reviewed: "2026-02-22"
  contact: "security@fintech-corp.com"
  data_classification: "confidential"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute eval(), exec(), or equivalent dynamic code execution"
    - "Never log credit card numbers, CVVs, or full account numbers"
    - "Never transmit financial data to undeclared endpoints"
    - "Never process transactions exceeding the declared max_transaction_value"
    - "Never bypass human approval for transactions above $100"
    - "Never store PII in plaintext"
    - "Never access production database with write permissions"
  max_autonomous_steps: 50
  escalation_on_uncertainty: true
  fail_mode: closed
  data_handling:
    pii_detection: required
    pii_anonymization: required
    pci_scope: true
```

## Tools

```yaml
tools:
  - name: stripe_api
    permission: write
    scope:
      allowed_operations: [create_charge, refund, list_charges]
      denied_operations: [delete_customer, modify_account, transfer_funds]
      max_transaction_value: 500
      currency: "USD"
      max_requests_per_minute: 30
    requires_confirmation: true
    audit_every_call: true

  - name: customer_database
    permission: read_only
    scope:
      allowed_schemas: ["public"]
      allowed_tables: ["customers", "invoices", "products"]
      denied_tables: ["payment_methods", "bank_accounts", "internal_notes"]
      denied_operations: ["DROP", "ALTER", "TRUNCATE", "DELETE", "UPDATE", "INSERT"]
    requires_confirmation: false
    audit_every_call: true

  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./output/invoices/"]
      denied_paths: ["./", "./config/", "./secrets/"]
    requires_confirmation: true

  - name: email_service
    permission: write
    scope:
      allowed_recipients: ["@fintech-corp.com"]
      max_emails_per_hour: 50
      template_only: true
    requires_confirmation: true
```

## Runtime

```yaml
runtime:
  sandbox:
    required: true
    type: docker
    image: "fintech-corp/agent-sandbox:latest"
    capabilities:
      network: restricted
      filesystem: scoped
      process_spawn: false
  network:
    outbound_allowlist:
      - "api.stripe.com"
      - "db.fintech-corp.internal"
      - "smtp.fintech-corp.internal"
    inbound: none
    tls_minimum_version: "1.2"
  resources:
    max_memory_mb: 256
    max_cpu_seconds: 120
  timeout:
    per_step_seconds: 15
    total_seconds: 300
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "stripe_charge_above_100"
    - "refund_processing"
    - "customer_communication"
    - "invoice_generation"
    - "any_write_to_production"
  approval_mechanism: web_ui
  approval_timeout_seconds: 120
  require_justification: true
  escalation_contact: "finance-ops@fintech-corp.com"
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "s3://fintech-corp-audit/agents/financial-processor/"
  format: json
  retention_days: 2555
  fields:
    - timestamp
    - agent_name
    - session_id
    - action
    - tool_used
    - parameters_hash
    - transaction_amount
    - result
    - approval_status
    - approver_identity
    - pci_scope_flag
  tamper_protection: true
  tamper_mechanism: "sigstore"
  alert_on:
    - "policy_violation"
    - "transaction_above_limit"
    - "pii_detected_in_output"
    - "undeclared_api_call"
  incident_response:
    auto_suspend_on_critical: true
    notification_channel: "pagerduty://finance-security"
```

## Threat Model

```yaml
threat_model:
  primary_threats:
    - "Prompt injection to authorize fraudulent transactions"
    - "PII/PCI data exfiltration through model outputs"
    - "Transaction amount manipulation via tool parameter injection"
    - "Unauthorized access to payment methods table"
  mitigations:
    fraud: "Transaction limits + HITL + dual confirmation for high-value"
    data_exfil: "Network allowlist + PII detection + output filtering"
    amount_manipulation: "Server-side validation + audit logging"
    unauthorized_access: "Read-only DB + table allowlisting + query logging"
```
