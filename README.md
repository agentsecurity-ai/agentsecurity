# AgentSecurity

**The Security Contract for Autonomous Agents**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Spec: CC-BY-4.0](https://img.shields.io/badge/Spec-CC--BY--4.0-green.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)

An open standard for defining security boundaries of autonomous AI agents. Like `README.md`, but for security.

---

## The Problem

AI agents are shipped with increasing autonomy but undefined security boundaries. Most developers don't understand prompt injection, tool escalation, or compliance requirements — yet they deploy agents that can execute code, call APIs, and modify production systems.

## The Solution

`AGENTSECURITY.md` — a declarative security policy file that defines what an agent is allowed to do, what it must never do, and what requires human approval. **Before the agent runs.**

```bash
# Install
pip install agentsec

# Initialize a security policy
agentsec init --tier standard

# Validate your policy
agentsec validate .

# Scan codebase for violations
agentsec check .
```

## Security Tiers

| Tier | Use Case | Tool Allowlisting | HITL | Sandbox | Audit |
|---|---|---|---|---|---|
| `basic` | Prototypes, internal tools | recommended | optional | no | optional |
| `standard` | Production agents | required | high-risk | recommended | recommended |
| `strict` | Sensitive data, financial | required | destructive ops | required | required |
| `regulated` | Healthcare, finance, gov | required | all external | required + audited | tamper-proof |

## Quick Example

```yaml
---
name: my-agent
description: "Processes support tickets and generates responses"
security_tier: standard
version: "0.1"
governance:
  - OWASP-LLM-TOP10
enforcement: warn
---
```

```yaml
## Tools

tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./src/", "./data/"]
    requires_confirmation: false

  - name: email_api
    permission: write
    requires_confirmation: true
```

## Project Structure

```
agentsecurity/
├── spec/                    # The standard
│   ├── AGENTSECURITY.md     # Human-readable specification
│   └── agentsecurity.schema.json  # JSON Schema
├── templates/               # Copy-paste starters
│   ├── basic/
│   ├── standard/
│   ├── strict/
│   └── regulated/
├── examples/                # Real-world examples
│   ├── langchain-agent/
│   ├── claude-code-project/
│   ├── financial-processor/
│   └── vulnerable-agent/    # Deliberately insecure (for testing)
├── packages/agentsec/      # CLI validator (Python)
├── docs/                    # Documentation website
└── references/              # OWASP, NIST, ISO reference material
```

## CLI Commands

| Command | Description |
|---|---|
| `agentsec validate [path]` | Validate AGENTSECURITY.md against the spec |
| `agentsec check [path]` | Scan codebase for violations |
| `agentsec report [path]` | Generate security scorecard (text/JSON/badge) |
| `agentsec init --tier <tier>` | Create AGENTSECURITY.md from template |
| `agentsec read-properties [path]` | Output policy as JSON |
| `agentsec to-prompt [path]` | Generate system prompt XML snippet |

## Validation Rules

The CLI checks 12+ rules mapped to OWASP, NIST, and ISO controls:

- **ASEC-001–007**: Schema compliance (required fields, valid values)
- **ASEC-010–011**: Tool declarations and privilege analysis
- **ASEC-012**: Human-in-the-loop configuration
- **ASEC-013**: Sandbox requirements
- **ASEC-014**: Audit logging
- **ASEC-015**: Network policy
- **ASEC-020**: Dangerous code patterns (eval, exec, curl|bash)
- **ASEC-021**: Hardcoded secrets
- **ASEC-022**: Undeclared tool usage

## What This Is NOT

- **Not a runtime guarantee** — defines intent, not enforcement
- **Not a certification** — aligns with frameworks, doesn't certify
- **Not a runtime firewall** — that's a separate layer (planned for v0.2+)

These limitations are explicitly documented in the spec and every template.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions welcome for:
- Spec improvements (open RFC first)
- New validation rules (with tests)
- Framework examples
- Compliance mappings

## License

- **Specification:** [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)
- **Tooling:** [Apache-2.0](LICENSE)

## Links

- [Specification](spec/AGENTSECURITY.md)
- [Templates](templates/)
- [Examples](examples/)
- [Security Policy](SECURITY.md)
