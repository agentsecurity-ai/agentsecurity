---
name: modular-agent
description: "An agent that uses modular security packs"
security_tier: standard
version: "0.1"
extends:
  - "../../packages/agentsec/src/agentsec/packs/pii_protection.md"
  - "../../packages/agentsec/src/agentsec/packs/strict_runtime.md"
---

## Tools

```yaml
tools:
  - name: web_search
    permission: read_only
    scope:
      allowed_domains: ["google.com", "github.com"]
```
