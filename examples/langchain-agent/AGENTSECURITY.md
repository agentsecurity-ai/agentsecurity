---
name: langchain-research-agent
description: "LangChain agent that searches documentation, summarizes findings, and generates reports. Read-only access to web and file system."
security_tier: standard
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: warn

metadata:
  author: "dev-team"
  org: "example-corp"
  last_reviewed: "2026-02-22"
  framework: "langchain"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute eval() or equivalent dynamic code execution"
    - "Never write to files outside ./output/"
    - "Never access internal APIs or databases"
    - "Never transmit user queries to third parties beyond the declared LLM API"
  max_autonomous_steps: 100
  escalation_on_uncertainty: true
```

## Tools

```yaml
tools:
  - name: web_search
    permission: read_only
    scope:
      allowed_domains:
        - "docs.python.org"
        - "langchain.readthedocs.io"
        - "stackoverflow.com"
        - "arxiv.org"
    requires_confirmation: false

  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./docs/", "./output/"]
      denied_paths: ["./.env", "./secrets/"]
    requires_confirmation: false

  - name: llm_api
    permission: read_only
    scope:
      provider: "anthropic"
      model: "claude-sonnet-4-5-20250929"
      # Equivalent provider patterns:
      # provider: "openai", model: "gpt-5-mini"
      # provider: "google", model: "gemini-2.0-flash"
      max_tokens_per_call: 4096
    requires_confirmation: false
```

## Runtime

```yaml
runtime:
  sandbox:
    required: false
    capabilities:
      network: restricted
      filesystem: scoped
  network:
    outbound_allowlist:
      - "api.anthropic.com"
      - "docs.python.org"
      - "langchain.readthedocs.io"
  timeout:
    per_step_seconds: 30
    total_seconds: 600
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "file_creation_in_output_directory"
  approval_mechanism: cli_prompt
  approval_timeout_seconds: 300
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "file://./logs/agent.log"
  format: json
  retention_days: 30
```
