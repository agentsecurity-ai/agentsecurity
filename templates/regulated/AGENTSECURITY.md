---
# =============================================================================
# AGENTSECURITY.md — Regulated Tier
# =============================================================================
# For healthcare, finance, government, and any domain with formal compliance
# requirements (HIPAA, PCI-DSS, SOC2, EU AI Act, etc.).
#
# All strict tier requirements apply PLUS:
# - Full compliance mapping to declared frameworks
# - Tamper-proof audit logging with signed records
# - Human approval on ALL external actions (not just destructive)
# - Mandatory incident response plan
# - Data residency and classification requirements
# - Bi-weekly policy review cadence
#
# Docs: https://agentsecurity.in/specification
# =============================================================================

name: my-regulated-agent          # Replace with your agent name
description: "Description including data classification and regulatory scope"
security_tier: regulated
version: "0.1"

governance:
  - OWASP-LLM-TOP10
  - NIST-AI-RMF
  - ISO-42001
  - EU-AI-ACT
  # Add domain-specific:
  # - HIPAA
  # - PCI-DSS
  # - SOC2
  # - GDPR

enforcement: block_and_audit      # Block + create tamper-evident audit record

metadata:
  author: "your-name"
  org: "your-org"
  last_reviewed: "2026-02-22"
  contact: "security@your-org.com"
  data_classification: "confidential"
  regulatory_jurisdiction: "EU"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute eval(), exec(), or equivalent dynamic code execution"
    - "Never run shell commands without explicit declaration in Tools section"
    - "Never access files outside the declared scope"
    - "Never transmit data to undeclared external endpoints"
    - "Never store or log credentials, API keys, or PII in plaintext"
    - "Never bypass human approval for any action"
    - "Never modify system configuration files"
    - "Never install packages or dependencies without declaration"
    - "Never process PII without explicit consent record"
    - "Never transmit data outside declared data residency boundaries"
    - "Never operate without active audit logging"
    - "Never make decisions that require professional human judgment"
  max_autonomous_steps: 25
  escalation_on_uncertainty: true
  fail_mode: closed
  data_handling:
    pii_detection: required
    pii_anonymization: required
    data_residency: "EU"            # Data must not leave this jurisdiction
    data_retention_max_days: 30
    right_to_deletion: supported
```

## Tools

<!-- Regulated tier: ALL tools must be declared with narrowest possible scope. -->
<!-- Every tool must have requires_confirmation: true. -->

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./workspace/"]
      denied_paths: ["./secrets/", "./.env", "./config/", "./logs/"]
    requires_confirmation: true
    data_classification_allowed: ["public", "internal"]
    audit_every_call: true

  # - name: database
  #   permission: read_only
  #   scope:
  #     allowed_schemas: ["public"]
  #     denied_tables: ["users_pii", "payment_details"]
  #     denied_operations: ["DROP", "ALTER", "TRUNCATE", "DELETE"]
  #     query_logging: true
  #   requires_confirmation: true
  #   data_classification_allowed: ["public"]
  #   audit_every_call: true

  # - name: llm_api
  #   permission: read_only
  #   scope:
  #     provider: "google"          # openai | anthropic | google
  #     model: "gemini-2.0-flash"
  #     allowed_endpoints: ["generativelanguage.googleapis.com"]
  #     max_tokens_per_call: 2048
  #   requires_confirmation: true
  #   audit_every_call: true
```

## Runtime

<!-- Regulated tier: Sandbox is MANDATORY with audited configuration. -->

```yaml
runtime:
  sandbox:
    required: true
    type: gvisor                    # Prefer gvisor/kata for stronger isolation
    capabilities:
      network: restricted
      filesystem: scoped
      process_spawn: false
      privilege_escalation: false
      ptrace: false
    configuration_audit: true       # Sandbox config changes are logged
  network:
    outbound_allowlist:
      - "api.approved-service.com"
    inbound: none
    dns_filtering: true
    tls_minimum_version: "1.3"
    certificate_pinning: true
  resources:
    max_memory_mb: 256
    max_cpu_seconds: 120
    max_disk_mb: 512
  timeout:
    per_step_seconds: 15
    total_seconds: 300
```

## Human-in-the-Loop

<!-- Regulated tier: ALL external actions require human approval. -->

```yaml
human_in_the_loop:
  always_require:
    - "any_write_operation"
    - "any_delete_operation"
    - "any_external_api_call"
    - "any_database_operation"
    - "any_network_request"
    - "sending_communications"
    - "code_execution"
    - "configuration_changes"
    - "data_export"
    - "pii_processing"
  approval_mechanism: web_ui        # Must have audit trail
  approval_timeout_seconds: 120     # Shorter timeout for regulated
  require_justification: true
  escalation_contact: "compliance-team@your-org.com"
  dual_approval: true               # Two humans must approve critical actions
  dual_approval_actions:
    - "pii_processing"
    - "data_export"
    - "production_deployment"
  approver_role_required: "security_reviewer"  # RBAC on approvers
```

## Audit

<!-- Regulated tier: Tamper-proof audit logging is MANDATORY. -->

```yaml
audit:
  enabled: true
  log_target: "s3://your-org-compliance-logs/agents/"
  format: json
  retention_days: 2555              # 7 years for financial compliance
  fields:
    - timestamp
    - agent_name
    - session_id
    - action
    - tool_used
    - parameters_hash
    - result
    - approval_status
    - approver_identity
    - approver_role
    - policy_version
    - data_classification
    - jurisdiction
    - compliance_controls_satisfied
  tamper_protection: true
  tamper_mechanism: "sigstore"      # sigstore | gpg | blockchain_anchor
  immutable_storage: true           # Write-once storage (S3 Object Lock, etc.)
  alert_on:
    - "policy_violation"
    - "escalation_triggered"
    - "sandbox_boundary_hit"
    - "approval_timeout"
    - "repeated_denied_actions"
    - "pii_detected_in_output"
    - "data_residency_violation"
  incident_response:
    auto_suspend_on_critical: true
    notification_channel: "pagerduty://compliance-team"
    incident_report_template: "./security/incident-template.md"
    post_mortem_required: true
```

## Compliance Mapping

<!-- Regulated tier: Map each control to specific framework requirements. -->
<!-- This enables automated compliance reporting via agentsec CLI. -->

```yaml
compliance_mapping:
  NIST-AI-RMF:
    MAP-1.1: "Agent purpose and boundaries defined in description + constraints"
    MAP-1.5: "Risk assessment in threat_model section"
    MEASURE-2.6: "Audit logging with tamper protection"
    MANAGE-1.3: "Human-in-the-loop with dual approval"
    GOVERN-1.1: "Policy review cadence: bi-weekly"

  OWASP-LLM-TOP10:
    LLM01: "Prompt injection mitigated via input sanitization (constraints.hard_no)"
    LLM02: "Insecure output handling mitigated via output filtering"
    LLM06: "Sensitive info disclosure mitigated via PII detection + anonymization"
    LLM07: "Insecure plugin design mitigated via tool allowlisting"
    LLM08: "Excessive agency mitigated via HITL + max_autonomous_steps"

  ISO-42001:
    "6.1.2": "Risk assessment documented in threat_model"
    "8.4": "AI system monitoring via audit logging"
    "9.2": "Internal audit via bi-weekly policy review"

  EU-AI-ACT:
    "Article 9": "Risk management via constraints + threat_model"
    "Article 12": "Record-keeping via tamper-proof audit"
    "Article 13": "Transparency via description + constraints"
    "Article 14": "Human oversight via human_in_the_loop"
```

## Threat Model

```yaml
threat_model:
  primary_threats:
    - "Prompt injection via user input or retrieved documents"
    - "Tool escalation beyond declared scope"
    - "Data exfiltration through undeclared endpoints"
    - "Confused deputy attack via malicious tool responses"
    - "PII leakage through model outputs or logs"
    - "Data residency violation through cross-border data transfer"
    - "Insider threat through compromised approver credentials"
    - "Supply chain attack through compromised dependencies"
  mitigations:
    prompt_injection: "Input sanitization + output filtering + system prompt locking"
    tool_escalation: "Strict allowlisting + runtime sandbox + HITL + dual approval"
    data_exfiltration: "Network allowlist + audit logging + anomaly detection"
    confused_deputy: "Tool response validation + result type checking"
    pii_leakage: "PII detection + anonymization + output filtering + log scrubbing"
    data_residency: "Geo-fenced infrastructure + network policy + audit alerts"
    insider_threat: "Dual approval + RBAC + audit trail + session monitoring"
    supply_chain: "Dependency pinning + SBOM + vulnerability scanning"
  red_team_cadence: "monthly"
  threat_model_ref: "./security/detailed-threat-model.md"
```

## Incident Response

```yaml
incident_response:
  plan_location: "./security/incident-response-plan.md"
  severity_levels:
    critical: "Agent suspended, security team paged, post-mortem within 24h"
    high: "Agent suspended, security team notified, review within 48h"
    medium: "Alert logged, review in next bi-weekly cycle"
    low: "Logged for trend analysis"
  contacts:
    primary: "security-oncall@your-org.com"
    escalation: "ciso@your-org.com"
    legal: "legal@your-org.com"
    regulator: "compliance@your-org.com"
  communication_template: "./security/incident-communication-template.md"
  tested: true                      # Incident response plan has been exercised
  last_drill: "2026-01-15"
```

<!-- ======================================================================= -->
<!-- LIMITATIONS ACKNOWLEDGMENT (Regulated Tier)                             -->
<!--                                                                         -->
<!-- 1. CERTIFICATION DISCLAIMER: This file declares design intent aligned   -->
<!--    with the listed frameworks. It is NOT a substitute for formal        -->
<!--    certification by an accredited auditor. Use this as input to your    -->
<!--    audit process, not as the audit itself.                              -->
<!--                                                                         -->
<!-- 2. AUTONOMY IMPACT: Regulated tier severely constrains agent autonomy.  -->
<!--    This is intentional for high-risk domains. If the agent becomes      -->
<!--    impractical, that's a signal to re-evaluate whether the task         -->
<!--    should be automated at all, not to lower the security tier.          -->
<!--                                                                         -->
<!-- 3. RUNTIME ENFORCEMENT GAP: Even with block_and_audit enforcement,      -->
<!--    policy checking at the spec level is static. You MUST deploy a       -->
<!--    runtime proxy/gateway for regulated workloads. This spec is one      -->
<!--    layer of defense, not the only layer.                                -->
<!--                                                                         -->
<!-- 4. COMPLIANCE MAPPING ACCURACY: The compliance_mapping section provides -->
<!--    suggested control mappings. Your compliance team must verify these   -->
<!--    mappings against your specific regulatory interpretation.            -->
<!--                                                                         -->
<!-- 5. MULTI-AGENT & DELEGATION: If this agent delegates to sub-agents,    -->
<!--    each MUST have its own regulated-tier AGENTSECURITY.md. Cross-agent -->
<!--    trust delegation is not yet specified (planned for v0.2).           -->
<!--                                                                         -->
<!-- 6. STALE POLICY RISK: Regulated tier requires bi-weekly review. Set a  -->
<!--    calendar reminder. The validator warns when last_reviewed exceeds   -->
<!--    14 days.                                                             -->
<!-- ======================================================================= -->
