---
# =============================================================================
# AGENTSECURITY.md — Standard Tier
# =============================================================================
# Balanced security policy for production agents handling non-sensitive data.
# Enforces tool allowlisting, HITL for high-risk actions, and audit logging.
#
# Docs: https://agentsecurity.in/specification
# =============================================================================

name: my-agent                    # Replace with your agent name
description: "Brief description of what your agent does"
security_tier: standard
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: warn                 # Change to 'block' for stricter enforcement

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
  max_autonomous_steps: 100
  escalation_on_uncertainty: true   # Agent must ask for help when unsure
```

## Tools

<!-- Standard tier REQUIRES all tools to be declared. -->
<!-- The agentsec validator will flag any undeclared tool usage in your code. -->

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./src/", "./data/", "/tmp/agent/"]
      denied_paths: ["./secrets/", "./.env"]
    requires_confirmation: false

  # Example: API tool with scope limits
  # - name: my_api
  #   permission: read_write
  #   scope:
  #     allowed_operations: [read, create]
  #     denied_operations: [delete, admin]
  #   requires_confirmation: true

  # Example: Read-only external service
  # - name: web_search
  #   permission: read_only
  #   scope:
  #     allowed_domains: ["docs.python.org", "stackoverflow.com"]

  # Example: LLM provider scope (works for OpenAI, Claude, Gemini, etc.)
  # - name: llm_api
  #   permission: read_only
  #   scope:
  #     provider: "openai"          # openai | anthropic | google
  #     model: "gpt-5-mini"         # e.g. claude-sonnet, gemini-2.0-flash
  #     max_tokens_per_call: 4096
  #     allowed_endpoints: ["api.openai.com"]
```

## Runtime

<!-- Standard tier recommends sandboxing. -->
<!-- If sandbox is not possible, compensate with stricter tool permissions. -->

```yaml
runtime:
  sandbox:
    required: false                 # Recommended: set to true
    type: docker                    # docker | gvisor | wasm | process
    capabilities:
      network: restricted
      filesystem: scoped
  network:
    outbound_allowlist:
      - "api.your-service.com"
      # Add allowed external endpoints
    inbound: none
  resources:
    max_memory_mb: 512
    max_cpu_seconds: 300
  timeout:
    per_step_seconds: 30
    total_seconds: 600
```

## Human-in-the-Loop

<!-- Standard tier requires HITL for high-risk actions. -->

```yaml
human_in_the_loop:
  always_require:
    - "file_deletion"
    - "database_write_operations"
    - "sending_external_communications"
    - "code_deployment"
  approval_mechanism: cli_prompt    # cli_prompt | web_ui | slack
  approval_timeout_seconds: 300     # Fail-closed: auto-deny after timeout
  escalation_contact: "oncall@your-org.com"
```

## Audit

<!-- Standard tier recommends audit logging. -->

```yaml
audit:
  enabled: true
  log_target: "file://./logs/agentsec.log"
  format: json
  retention_days: 90
  fields:
    - timestamp
    - agent_name
    - action
    - tool_used
    - result
    - approval_status
  alert_on:
    - "policy_violation"
    - "escalation_triggered"
```

<!-- ======================================================================= -->
<!-- LIMITATIONS ACKNOWLEDGMENT (Standard Tier)                              -->
<!--                                                                         -->
<!-- 1. STATIC ANALYSIS GAPS: The validator scans code statically. Dynamic   -->
<!--    tool calls generated at runtime may not be caught. Consider adding   -->
<!--    runtime monitoring for full coverage.                                -->
<!--                                                                         -->
<!-- 2. NOT A CERTIFICATION: Declaring OWASP alignment means you've designed -->
<!--    with OWASP in mind. It does not constitute formal certification.     -->
<!--                                                                         -->
<!-- 3. POLICY STALENESS: Review this file per the cadence in your tier      -->
<!--    (quarterly for standard). The validator warns when last_reviewed     -->
<!--    exceeds the cadence.                                                 -->
<!--                                                                         -->
<!-- 4. TEMPLATE BLINDNESS: Don't just copy this template — customize the    -->
<!--    Tools, Constraints, and HITL sections for YOUR agent's actual        -->
<!--    capabilities. A generic policy is security theater.                  -->
<!-- ======================================================================= -->
