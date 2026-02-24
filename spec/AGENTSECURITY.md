# AGENTSECURITY.md Specification v0.1

> The open standard for defining security boundaries of autonomous AI agents.

## Overview

`AGENTSECURITY.md` is a declarative security policy file that lives in the root of any AI agent project. It defines what an agent is allowed to do, what it must never do, and what requires human approval — **before the agent runs**.

This specification is framework-agnostic. It works with LangChain, CrewAI, AutoGen, Claude Code, custom agents, and any future framework.

### Design Principles

1. **Simplicity over completeness** — A developer with zero security background should understand every field
2. **Progressive disclosure** — Metadata loads at startup (~100 tokens); full policy loads on activation
3. **Secure defaults** — Each tier ships with sensible defaults; override only what you need
4. **Declarative, not imperative** — Describes boundaries, not implementation
5. **Honest about limitations** — This file defines intent, not runtime guarantee (see [Limitations](#limitations))

---

## File Format

An `AGENTSECURITY.md` file consists of two parts:

1. **YAML Frontmatter** (machine-readable metadata, enclosed in `---`)
2. **Markdown Body** (human-readable security policy)

### YAML Frontmatter

```yaml
---
# ============================================================
# REQUIRED FIELDS
# ============================================================

# Unique identifier for this agent's security policy
# Constraints: 1-64 chars, lowercase alphanumeric + hyphens
# Must not start/end with hyphen, no consecutive hyphens
name: my-agent-name

# What this agent does (helps other agents/tools discover the policy)
# Constraints: 1-512 chars
description: "Processes customer support tickets and generates responses"

# Security enforcement level (see Tier Definitions below)
# Values: basic | standard | strict | regulated
security_tier: standard

# Spec version this file conforms to
version: "0.1"

# ============================================================
# OPTIONAL FIELDS
# ============================================================

# Compliance framework alignment
# Known values: NIST-AI-RMF, OWASP-LLM-TOP10, ISO-42001, EU-AI-ACT
governance:
  - OWASP-LLM-TOP10

# What happens when a policy violation is detected
# Values: warn | block | block_and_audit
# Default: warn
enforcement: warn

# Arbitrary key-value metadata for extensibility
metadata:
  author: "team-name"
  org: "company-name"
  last_reviewed: "2026-02-22"
  contact: "security@example.com"
---
```

### Markdown Body

The body contains the human-readable security policy. The following sections are **recommended** but not structurally enforced. Agents and tools parse these sections for richer context.

```markdown
## Constraints
Hard rules the agent must never violate.

## Tools
Declared tool permissions with scope and limits.

## Runtime
Sandbox, network, and resource requirements.

## Human-in-the-Loop
When human approval is required.

## Audit
Logging targets, format, and retention.
```

---

## Field Definitions

### `name` (required)
- **Type:** string
- **Constraints:** 1-64 characters. Only lowercase Unicode alphanumeric characters and hyphens (`-`). Must not start or end with a hyphen. Must not contain consecutive hyphens (`--`).
- **Purpose:** Machine-readable identifier. Should match the project or agent name.

### `description` (required)
- **Type:** string
- **Constraints:** 1-512 characters. Non-empty.
- **Purpose:** Human and machine-readable summary of what the agent does and what security context applies. Include keywords that help discovery (e.g., "financial", "customer data", "code execution").

### `security_tier` (required)
- **Type:** enum
- **Values:** `basic`, `standard`, `strict`, `regulated`
- **Purpose:** Sets the baseline security requirements. See [Tier Definitions](#tier-definitions) for what each tier enforces by default.

### `version` (required)
- **Type:** string
- **Constraints:** Must match pattern `major.minor` (e.g., `"0.1"`, `"1.0"`)
- **Purpose:** Spec version this file conforms to. Allows tooling to handle backward compatibility.

### `governance` (optional)
- **Type:** array of strings
- **Known values:** `NIST-AI-RMF`, `OWASP-LLM-TOP10`, `ISO-42001`, `EU-AI-ACT`
- **Purpose:** Declares which compliance frameworks this agent aligns with. Tooling maps policy rules to specific framework controls.
- **Note:** Declaring governance is a statement of intent, not a certification claim. See [Limitations](#limitations).

### `enforcement` (optional)
- **Type:** enum
- **Values:** `warn`, `block`, `block_and_audit`
- **Default:** `warn`
- **Purpose:** Controls what happens when a violation is detected by tooling or runtime enforcement.
  - `warn` — Log the violation but allow the action
  - `block` — Prevent the action from executing
  - `block_and_audit` — Prevent the action and write a tamper-evident audit record

### `metadata` (optional)
- **Type:** object (string keys to string values)
- **Purpose:** Extensibility. Add any key-value pairs relevant to your organization (author, team, review cadence, contact info).

---

## Tier Definitions

Each tier sets **default requirements**. Individual requirements can be overridden in the markdown body (e.g., a `basic` tier agent can still declare a sandbox requirement).

| Requirement | `basic` | `standard` | `strict` | `regulated` |
|---|---|---|---|---|
| Tool allowlisting | recommended | required | required | required |
| Human-in-the-loop | optional | high-risk actions | all destructive actions | all external actions |
| Sandbox required | no | recommended | required | required + audited |
| Network restrictions | none | outbound allowlist | strict allowlist | default-deny + audit |
| Audit logging | optional | recommended | required | required + tamper-proof |
| Secret scanning | recommended | required | required | required + rotation policy |
| Compliance mapping | none | OWASP | OWASP + NIST | OWASP + NIST + ISO + EU AI Act |
| Max autonomous steps | unlimited | 100 | 50 | 25 |
| Policy review cadence | none | quarterly | monthly | bi-weekly |
| Incident response plan | none | recommended | required | required + tested |

### Choosing a Tier

- **`basic`** — Hobby projects, internal tools, prototypes. Minimal friction, basic guardrails.
- **`standard`** — Production agents handling non-sensitive data. Balanced security and autonomy.
- **`strict`** — Agents with access to sensitive data, financial systems, or destructive capabilities.
- **`regulated`** — Healthcare, finance, government, or any domain with formal compliance requirements.

**Important:** Choosing a higher tier reduces agent autonomy. This is by design — the tradeoff between security and autonomy is explicit, not hidden. If `strict` feels too restrictive, that's a signal to examine whether your agent truly needs the capabilities you're restricting.

---

## Recommended Body Sections

### Constraints

Define hard boundaries the agent must never cross. These are absolute — no tier override, no exception.

```yaml
constraints:
  hard_no:
    - "Never execute eval(), exec(), or equivalent dynamic code execution"
    - "Never run shell commands without explicit declaration in Tools section"
    - "Never access files outside the declared scope"
    - "Never transmit data to undeclared external endpoints"
  max_autonomous_steps: 50
  escalation_on_uncertainty: true
```

**Addressing over-restriction:** Constraints should be specific, not vague. "Never do anything dangerous" is useless. "Never execute `rm -rf` on paths outside `/tmp/sandbox/`" is actionable. Agents can still operate freely within declared boundaries.

### Tools

Declare every tool the agent is permitted to use, with explicit permissions and limits.

```yaml
tools:
  - name: stripe_api
    permission: write
    scope:
      max_transaction_value: 500
      allowed_operations: [create_charge, refund]
    requires_confirmation: true

  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["/workspace/", "/tmp/sandbox/"]
      denied_paths: ["/etc/", "/root/", "~/.ssh/"]
    requires_confirmation: false

  - name: web_search
    permission: read_only
    scope:
      allowed_domains: ["docs.python.org", "stackoverflow.com"]
    requires_confirmation: false
```

**Addressing undeclared tool detection:** The `agentsec check` CLI scans your codebase for tool invocations and flags any not declared here. This catches both:
- Tools you forgot to declare (accidental gap)
- Tools an agent might invoke dynamically (requires runtime enforcement for full coverage — see [Limitations](#limitations))

**Addressing overprivilege:** Wildcards (`*`) and admin-level permissions are flagged as warnings by the validator. Scope your permissions narrowly. The principle of least privilege applies to agents just as it does to human users.

### Runtime

Define the execution environment requirements.

```yaml
runtime:
  sandbox:
    required: true
    type: docker                    # docker | gvisor | wasm | process
    capabilities:
      network: restricted           # unrestricted | restricted | none
      filesystem: scoped            # unrestricted | scoped | read_only | none
      process_spawn: false
  network:
    outbound_allowlist:
      - "api.stripe.com"
      - "api.openai.com"
    inbound: none
  resources:
    max_memory_mb: 512
    max_cpu_seconds: 300
    max_disk_mb: 1024
  timeout:
    per_step_seconds: 30
    total_seconds: 600
```

**Addressing sandbox limitations:** Not all environments support Docker or gVisor. The `type` field allows declaring what's available. The validator checks if your declared sandbox type is realistic for your deployment target. If no sandbox is possible, the policy should compensate with stricter tool permissions and HITL requirements.

### Human-in-the-Loop

Define when human approval is required.

```yaml
human_in_the_loop:
  # Actions that always require approval
  always_require:
    - "financial_transactions_above_100"
    - "file_deletion"
    - "external_api_calls_to_new_endpoints"
    - "code_deployment"

  # Actions that require approval only in strict/regulated tiers
  high_risk_require:
    - "database_write_operations"
    - "sending_communications"

  # How approval is requested
  approval_mechanism: cli_prompt    # cli_prompt | web_ui | slack | email
  approval_timeout_seconds: 300     # Auto-deny after timeout (fail-closed)
  escalation_contact: "oncall@example.com"
```

**Addressing autonomy vs. security tradeoff:** The HITL section makes this tradeoff explicit and tunable. In `basic` tier, HITL is optional. In `standard`, only high-risk actions need approval. The approval timeout ensures agents don't hang forever waiting for humans — they fail closed (deny) rather than fail open (allow).

### Audit

Define logging and observability requirements.

```yaml
audit:
  enabled: true
  log_target: "file:///var/log/agentsec/agent.log"  # or s3:// or syslog://
  format: json                      # json | cef | syslog
  retention_days: 90
  fields:
    - timestamp
    - agent_name
    - action
    - tool_used
    - parameters
    - result
    - approval_status
  tamper_protection: false          # true for regulated tier (signed logs)
  alert_on:
    - "policy_violation"
    - "escalation_triggered"
    - "sandbox_boundary_hit"
```

**Addressing stale policies:** The `metadata.last_reviewed` field and tier-specific review cadence (bi-weekly for regulated, quarterly for standard) create accountability. The validator warns when `last_reviewed` exceeds the cadence for the declared tier.

---

## Progressive Disclosure (Agent Integration)

Inspired by the [Agent Skills](https://agentskills.io) progressive disclosure model:

### Layer 1: Discovery (~50-100 tokens)

At startup, agents/tools scan for `AGENTSECURITY.md` and load only the YAML frontmatter. This tells the agent its security context without consuming significant context window.

Recommended system prompt injection format:

```xml
<agent_security_policy>
  <name>financial-processor</name>
  <tier>strict</tier>
  <enforcement>block</enforcement>
  <description>Processes financial transactions with Stripe API</description>
</agent_security_policy>
```

### Layer 2: Activation (~500-2000 tokens)

When the agent begins executing, the full markdown body is loaded. The agent now knows its constraints, tool permissions, HITL requirements, and audit expectations.

**Addressing context overhead:** Keep the main AGENTSECURITY.md under 200 lines. Move detailed reference material (compliance mappings, incident response procedures, data classification tables) to separate files in a `security/` subdirectory and reference them:

```markdown
## Compliance Details
See [security/compliance-mapping.md](security/compliance-mapping.md) for full NIST control mapping.
```

### Layer 3: On-Demand References

Detailed compliance mappings, threat models, and audit procedures are loaded only when specifically needed — never at startup.

---

## Limitations

This section exists because honest security tooling acknowledges its boundaries.

### What AGENTSECURITY.md IS

- A declarative security policy for pre-build and design-time enforcement
- A machine-readable contract that tooling can validate
- A communication tool between developers, security teams, and compliance officers
- An input to CI/CD gates that can block insecure agent deployments

### What AGENTSECURITY.md IS NOT

- **Not a runtime guarantee.** A declared policy does not prevent a compromised or hallucinating LLM from violating it. Runtime enforcement requires additional infrastructure (proxy, gateway, sidecar) that is separate from this spec.
- **Not a certification.** Declaring `governance: [NIST-AI-RMF]` does not mean your agent is NIST-certified. It means you've designed it with NIST alignment in mind. Formal certification requires independent audit.
- **Not tamper-proof by itself.** The file can be modified by anyone with repo access. For production use, consider signing the file (e.g., GPG or Sigstore) and verifying signatures in CI.
- **Not a substitute for security expertise.** Templates provide safe defaults, but complex agent architectures need human security review.

### Known Gaps (Actively Being Addressed)

| Gap | Status | Mitigation |
|---|---|---|
| Dynamic tool invocation detection | Partial | Static analysis catches declared patterns; runtime proxy needed for dynamic |
| Multi-agent trust boundaries | Spec v0.2 | Currently each agent has its own policy; cross-agent delegation is not yet specified |
| LLM-specific prompt injection defense | Out of scope | This is a deployment concern, not an architecture specification concern |
| Framework-specific tool registration formats | In progress | Plugins for LangChain, CrewAI, Claude Code under development |

---

## Model Coverage & Failure Scenarios

`AGENTSECURITY.md` is model-agnostic by design. The same controls apply whether your agent uses OpenAI, Claude, Gemini, or open-weight/local models.

### Coverage Matrix

| Model / Agent Stack | Typical Failure Pattern | AGENTSECURITY.md Control(s) |
|---|---|---|
| OpenAI-based agents | Tool call overreach (unexpected writes, shell actions) | `tools` allowlisting + `requires_confirmation` + `constraints.hard_no` |
| Claude-based coding agents | High-impact command execution mistakes in repo operations | command-scoped tool declarations + HITL on push/deploy/delete |
| Gemini-based research/workflow agents | Prompt injection from retrieved content causing policy bypass attempts | `constraints.hard_no` + outbound allowlist + escalation on uncertainty |
| Any model with plugins/tools | Secret leakage to logs or external endpoints | `audit` field controls + network allowlist + secret scanning (`agentsec check`) |
| Multi-provider gateways | Inconsistent behavior across providers for same prompt | provider-agnostic policy in one file + strict runtime constraints |

### Real-World Agent Mistakes This Spec Is Meant To Reduce

1. Retrieved content (web/docs/email) includes hidden instructions and the agent follows them.
2. The agent hallucinates a "safe" command and executes a destructive variant.
3. A tool with broad permissions is used for a narrow task, causing unnecessary blast radius.
4. Credentials or PII are echoed into logs during debugging and retained too long.
5. An undeclared external endpoint is contacted because model output generated a new URL.

These patterns are not vendor-specific. They recur across model families because they come from agent architecture and tool orchestration, not from one model brand.

### User Install & Usage Paths

```bash
# Path A: Install CLI package (post-publish)
pip install agentsec
agentsec init --tier standard
agentsec validate .
agentsec check .

# Path B: Use only the policy file (no install needed)
# Copy a template AGENTSECURITY.md into your project root, then customize it.
```

---

## Validation

Use the `agentsec` CLI to validate your policy:

```bash
# Install
pip install agentsec

# Validate AGENTSECURITY.md against the spec schema
agentsec validate .

# Scan codebase for violations against declared policy
agentsec check .

# Initialize a new AGENTSECURITY.md from a template
agentsec init --tier standard

# Generate a security scorecard
agentsec report . --format json
```

### What the Validator Checks

1. **Schema compliance** — All required fields present and valid
2. **Tier consistency** — Declared tier matches the controls defined in the body
3. **Tool coverage** — All tools used in code are declared in the Tools section
4. **Privilege analysis** — Flags overprivileged permissions (wildcards, admin scopes)
5. **HITL coverage** — Verifies human approval is configured for tier-required actions
6. **Sandbox declaration** — Flags missing sandbox when code execution is detected
7. **Secret exposure** — Scans for hardcoded API keys, passwords, tokens
8. **Network policy** — Flags unrestricted outbound access
9. **Audit configuration** — Verifies logging is configured per tier requirements
10. **Dangerous patterns** — Flags `eval()`, `exec()`, `curl | bash`, and similar

### Addressing False Positives

The validator uses `# agentsec-ignore: <rule-id>` inline comments to suppress specific findings with justification:

```python
# agentsec-ignore: ASEC-003 — subprocess used for sandboxed test execution only
subprocess.call(["pytest", "tests/"])
```

All suppressions are included in the report for audit trail.

---

## Versioning & Backward Compatibility

- Spec version follows `major.minor` format
- Minor versions (0.1 → 0.2) add optional fields; existing files remain valid
- Major versions (0.x → 1.0) may require migration; a migration tool will be provided
- The `version` field in frontmatter allows tooling to apply the correct validation rules

---

## Contributing

This is an open standard. Contributions welcome at [github.com/agentsecurity-ai/agentsecurity](https://github.com/agentsecurity-ai/agentsecurity).

- **Spec changes:** Open an RFC issue before submitting PRs
- **New rules:** Add to `packages/agentsec/src/agentsec/rules/` with tests
- **Framework plugins:** Add to `examples/` with a working AGENTSECURITY.md
- **Compliance mappings:** Add to `packages/agentsec/src/agentsec/mappings/`

## License

- Specification: [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/)
- Tooling: [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
