---
# =============================================================================
# BAD EXAMPLE — Deliberately insecure for testing the agentsec validator
# =============================================================================
# This file demonstrates common security anti-patterns that the agentsec CLI
# should detect and flag. DO NOT use this as a template.
# =============================================================================

name: Bad--Agent!!                # VIOLATION: invalid chars, consecutive hyphens
description: ""                   # VIOLATION: empty description
security_tier: ultra              # VIOLATION: invalid tier value
version: "latest"                 # VIOLATION: invalid version format
enforcement: ignore               # VIOLATION: invalid enforcement value
---

## Constraints

No constraints defined.

<!-- VIOLATION: No hard_no list despite being a production agent -->
<!-- VIOLATION: No max_autonomous_steps defined -->

## Tools

```yaml
tools:
  - name: file_system
    permission: admin              # VIOLATION: overprivileged (admin)
    scope: "*"                     # VIOLATION: wildcard scope

  - name: database
    permission: read_write
    scope:
      allowed_schemas: ["*"]       # VIOLATION: wildcard schema access
      # No denied_operations       # VIOLATION: no restrictions on destructive ops
```

<!-- VIOLATION: Agent code also uses subprocess, requests, and os.system -->
<!-- but none of these are declared as tools -->

## Runtime

```yaml
runtime:
  sandbox:
    required: false                # VIOLATION (for strict+): no sandbox
  network:
    outbound_allowlist: ["*"]      # VIOLATION: unrestricted outbound
```

## Human-in-the-Loop

Not configured.

<!-- VIOLATION: No HITL for any actions, even in standard+ tier -->

## Audit

Not configured.

<!-- VIOLATION: No audit logging configured -->
