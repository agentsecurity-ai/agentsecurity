---
# =============================================================================
# AGENTSECURITY.md — Basic Tier
# =============================================================================
# Minimal security policy for hobby projects, prototypes, and internal tools.
# Copy this file to your project root and customize the values below.
#
# Docs: https://agentsecurity.dev/specification
# =============================================================================

name: my-agent                    # Replace with your agent name (lowercase, hyphens ok)
description: "Brief description of what your agent does"
security_tier: basic
version: "0.1"

# Optional: uncomment if you want compliance alignment
# governance:
#   - OWASP-LLM-TOP10

enforcement: warn                 # warn = log violations but don't block
# metadata:
#   author: "your-name"
#   last_reviewed: "2026-02-22"
---

## Constraints

<!-- Define absolute boundaries your agent must never cross. -->
<!-- Even in basic tier, these are non-negotiable. -->

```yaml
constraints:
  hard_no:
    - "Never execute eval() or equivalent dynamic code execution"
    - "Never access files outside the project directory"
    - "Never transmit credentials or secrets to external services"
```

## Tools

<!-- List every tool/API your agent can use. -->
<!-- Basic tier: allowlisting is recommended but not enforced by the validator. -->

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./"]

  # Add your tools here:
  # - name: my_api
  #   permission: read_only
  # - name: llm_api
  #   permission: read_only
  #   scope:
  #     provider: "openai|anthropic|google"
  #     model: "your-model-name"
```

## Runtime

<!-- Basic tier does not require sandboxing, but it's still good practice. -->

```yaml
runtime:
  sandbox:
    required: false
  timeout:
    total_seconds: 600
```

## Human-in-the-Loop

<!-- Basic tier: HITL is optional. Uncomment to enable for specific actions. -->

```yaml
human_in_the_loop:
  # always_require:
  #   - "file_deletion"
  #   - "external_api_calls"
  approval_mechanism: cli_prompt
```

<!-- ======================================================================= -->
<!-- LIMITATIONS ACKNOWLEDGMENT (Basic Tier)                                 -->
<!-- This policy defines intent, not runtime enforcement.                     -->
<!-- Basic tier provides minimal guardrails. For production agents handling   -->
<!-- sensitive data, upgrade to 'standard' or higher.                        -->
<!-- ======================================================================= -->
