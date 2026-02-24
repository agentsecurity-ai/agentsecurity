---
name: test-basic-agent
description: "A basic test agent for validation testing"
security_tier: basic
version: "0.1"
enforcement: warn
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute eval()"
```

## Tools

```yaml
tools:
  - name: file_system
    permission: read_only
    scope:
      allowed_paths: ["./"]
```
