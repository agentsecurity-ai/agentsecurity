---
name: claude-code-dev-agent
description: "Claude Code agent for software development. Reads, writes, and executes code in a project workspace. Has shell access for build/test commands."
security_tier: standard
version: "0.1"

governance:
  - OWASP-LLM-TOP10

enforcement: warn

metadata:
  author: "developer"
  last_reviewed: "2026-02-22"
  framework: "claude-code"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute rm -rf on paths outside the project directory"
    - "Never push to remote repositories without explicit human approval"
    - "Never modify .git/config or global git configuration"
    - "Never access or transmit .env files or credentials"
    - "Never install packages from untrusted sources"
    - "Never run commands with sudo or elevated privileges"
  max_autonomous_steps: 100
  escalation_on_uncertainty: true
```

## Tools

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./"]
      denied_paths: ["./.env", "./.env.local", "./secrets/", "~/.ssh/"]
    requires_confirmation: false

  - name: bash
    permission: read_write
    scope:
      allowed_commands:
        - "npm *"
        - "pnpm *"
        - "yarn *"
        - "python *"
        - "pytest *"
        - "git status"
        - "git diff *"
        - "git add *"
        - "git commit *"
        - "git log *"
        - "ls *"
        - "mkdir *"
      denied_commands:
        - "rm -rf /"
        - "sudo *"
        - "curl * | bash"
        - "wget * | sh"
        - "git push *"
        - "git config --global *"
    requires_confirmation: false

  - name: git_push
    permission: write
    scope:
      allowed_remotes: ["origin"]
      denied_branches: ["main", "master"]
    requires_confirmation: true     # Always ask before pushing

  - name: web_search
    permission: read_only
    requires_confirmation: false

  - name: llm_api
    permission: read_only
    scope:
      provider: "anthropic"
      model: "claude-sonnet-4-5"
      allowed_endpoints: ["api.anthropic.com"]
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
      - "registry.npmjs.org"
      - "pypi.org"
      - "github.com"
  timeout:
    per_step_seconds: 120
    total_seconds: 3600
```

## Human-in-the-Loop

```yaml
human_in_the_loop:
  always_require:
    - "git_push"
    - "package_installation"
    - "file_deletion_outside_tmp"
    - "production_deployment"
  approval_mechanism: cli_prompt
  approval_timeout_seconds: 600
```

## Audit

```yaml
audit:
  enabled: true
  log_target: "file://./logs/claude-code.log"
  format: json
  retention_days: 30
```
