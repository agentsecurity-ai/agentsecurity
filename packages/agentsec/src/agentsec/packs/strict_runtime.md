---
name: strict-runtime-pack
description: "Hardened runtime constraints for high-risk agents"
security_tier: strict
version: "0.1"
---

## Runtime

```yaml
runtime:
  sandbox:
    required: true
    type: docker
    options:
      network: none
      read_only_root: true
  timeout:
    total_seconds: 300
    per_step_seconds: 30
```

## Audit

```yaml
audit:
  enabled: true
  tamper_protection: true
  retention_days: 90
```
