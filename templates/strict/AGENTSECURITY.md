---
# =============================================================================
# AGENTSECURITY.md — Strict Tier
# =============================================================================
# Maximum enforcement for agents with access to sensitive data, financial
# systems, or destructive capabilities.
#
# All tools MUST be declared. All destructive actions require human approval.
# Sandbox is mandatory. Full audit logging is required.
#
# Docs: https://agentsecurity.dev/specification
# =============================================================================

name: my-agent                    # Replace with your agent name
description: "Brief description — include data sensitivity and capabilities"
security_tier: strict
version: "0.1"

governance:
  - OWASP-LLM-TOP10
  - NIST-AI-RMF

enforcement: block                # Block violations, don't just warn

metadata:
  author: "your-name"
  org: "your-org"
  last_reviewed: "2026-02-22"
  contact: "security@your-org.com"
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
    - "Never bypass human approval for actions marked requires_confirmation"
    - "Never modify system configuration files"
    - "Never install packages or dependencies without declaration"
  max_autonomous_steps: 50
  escalation_on_uncertainty: true
  fail_mode: closed               # On error/uncertainty, deny action (not allow)
```

## Tools

<!-- Strict tier: ALL tools MUST be declared with narrow scopes. -->
<!-- Wildcards (*) and admin permissions will be flagged as HIGH severity. -->

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./src/", "./data/output/"]
      denied_paths: ["./secrets/", "./.env", "./config/production/"]
    requires_confirmation: true     # All file writes need approval

  # Declare every tool your agent uses:
  # - name: database
  #   permission: read_only          # Prefer read_only; use read_write only if needed
  #   scope:
  #     allowed_schemas: ["public"]
  #     denied_operations: ["DROP", "ALTER", "TRUNCATE"]
  #   requires_confirmation: true

  # - name: external_api
  #   permission: read_write
  #   scope:
  #     allowed_operations: [read, create]
  #     max_requests_per_minute: 10
  #   requires_confirmation: true

  # - name: llm_api
  #   permission: read_only
  #   scope:
  #     provider: "anthropic"       # openai | anthropic | google
  #     model: "claude-sonnet-4-5"
  #     max_tokens_per_call: 4096
  #     allowed_endpoints: ["api.anthropic.com"]
  #   requires_confirmation: false
```

## Runtime

<!-- Strict tier: Sandbox is MANDATORY. -->

```yaml
runtime:
  sandbox:
    required: true
    type: docker                    # docker | gvisor | wasm
    image: "your-org/agent-sandbox:latest"
    capabilities:
      network: restricted
      filesystem: scoped
      process_spawn: false
      privilege_escalation: false
  network:
    outbound_allowlist:
      - "api.your-service.com"
      # Explicitly list every allowed external endpoint
    inbound: none
    dns_filtering: true
  resources:
    max_memory_mb: 512
    max_cpu_seconds: 300
    max_disk_mb: 1024
  timeout:
    per_step_seconds: 30
    total_seconds: 600
```

## Human-in-the-Loop

<!-- Strict tier: ALL destructive actions require human approval. -->

```yaml
human_in_the_loop:
  always_require:
    - "any_write_operation"
    - "any_delete_operation"
    - "external_api_calls"
    - "database_modifications"
    - "file_creation_or_modification"
    - "sending_communications"
    - "code_deployment"
    - "configuration_changes"
  approval_mechanism: cli_prompt    # cli_prompt | web_ui | slack
  approval_timeout_seconds: 300     # Fail-closed: auto-deny after timeout
  require_justification: true       # Agent must explain WHY it needs the action
  escalation_contact: "security-oncall@your-org.com"
  dual_approval: false              # Set true for regulated tier
```

## Audit

<!-- Strict tier: Full audit logging is REQUIRED. -->

```yaml
audit:
  enabled: true
  log_target: "s3://your-org-logs/agents/"    # Use durable storage
  format: json
  retention_days: 365
  fields:
    - timestamp
    - agent_name
    - session_id
    - action
    - tool_used
    - parameters_hash                # Hash params, don't log sensitive values
    - result
    - approval_status
    - approver_identity
    - policy_version
  tamper_protection: false           # Set true for regulated tier
  alert_on:
    - "policy_violation"
    - "escalation_triggered"
    - "sandbox_boundary_hit"
    - "approval_timeout"
    - "repeated_denied_actions"
  incident_response:
    auto_suspend_on_critical: true   # Suspend agent on critical violation
    notification_channel: "slack://security-alerts"
```

## Threat Model

<!-- Strict tier should include a threat model summary. -->
<!-- Reference detailed threat model in separate file if needed. -->

```yaml
threat_model:
  primary_threats:
    - "Prompt injection via user input"
    - "Tool escalation beyond declared scope"
    - "Data exfiltration through undeclared endpoints"
    - "Confused deputy attack via malicious tool responses"
  mitigations:
    prompt_injection: "Input sanitization + output filtering + system prompt locking"
    tool_escalation: "Strict allowlisting + runtime sandbox + HITL"
    data_exfiltration: "Network allowlist + audit logging + anomaly detection"
    confused_deputy: "Tool response validation + result type checking"
  # For detailed threat model, reference:
  # threat_model_ref: "./security/threat-model.md"
```

<!-- ======================================================================= -->
<!-- LIMITATIONS ACKNOWLEDGMENT (Strict Tier)                                -->
<!--                                                                         -->
<!-- 1. AUTONOMY TRADEOFF: Strict tier significantly reduces agent autonomy. -->
<!--    This is intentional. If strict feels too restrictive, evaluate        -->
<!--    whether your agent truly needs the restricted capabilities.          -->
<!--                                                                         -->
<!-- 2. RUNTIME ENFORCEMENT: This policy is checked statically (CI/CD) and   -->
<!--    at agent startup. Full runtime enforcement requires a proxy/gateway  -->
<!--    that intercepts tool calls — not yet part of this spec (v0.2+).     -->
<!--                                                                         -->
<!-- 3. DYNAMIC TOOLS: LLMs can generate novel tool invocations. Static     -->
<!--    analysis catches ~80% of patterns. The remaining 20% requires       -->
<!--    runtime monitoring. Plan for both.                                   -->
<!--                                                                         -->
<!-- 4. MULTI-AGENT: If this agent delegates to sub-agents, each sub-agent  -->
<!--    needs its own AGENTSECURITY.md. Cross-agent trust is not yet        -->
<!--    specified (planned for v0.2).                                        -->
<!-- ======================================================================= -->
