---
name: pii-protection-pack
description: "Standard constraints to prevent PII and secret leakage"
security_tier: basic
version: "0.1"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never log or transmit raw API keys, bearer tokens, or database credentials"
    - "Never output Social Security Numbers, Credit Card numbers, or personal email addresses"
    - "Redact all PII before sending data to third-party logging services"
  PII_FILTER: true
```
