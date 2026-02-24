# Compliance Frameworks Reference

How AGENTSECURITY.md maps to major AI governance frameworks.

## NIST AI Risk Management Framework (AI RMF)

| NIST Function | NIST Control | AGENTSECURITY.md Mapping |
|---|---|---|
| GOVERN | 1.1 - Policies for AI risk | AGENTSECURITY.md IS the policy artifact |
| GOVERN | 1.2 - Accountability | metadata.author, metadata.org, escalation contacts |
| MAP | 1.1 - Purpose and context | name + description fields |
| MAP | 1.5 - Risk identification | Constraints + threat model sections |
| MEASURE | 2.6 - Monitoring and logging | Audit section with log targets |
| MEASURE | 2.7 - Testing and evaluation | agentsec CLI scanning |
| MANAGE | 1.3 - Risk responses | HITL, sandbox, tool scope restrictions |
| MANAGE | 2.2 - Human oversight | Human-in-the-Loop section |
| MANAGE | 4.1 - Incident response | Audit alerts + incident response plan (regulated) |

## ISO/IEC 42001:2023 — AI Management System

| ISO Clause | AGENTSECURITY.md Mapping |
|---|---|
| 5.2 - AI Policy | The file itself is the policy artifact |
| 6.1.2 - Risk assessment | Constraints + threat model |
| 6.1.3 - Risk treatment | Tool restrictions, HITL, sandbox |
| 8.4 - System monitoring | Audit logging configuration |
| 9.2 - Internal audit | Review cadence enforcement (last_reviewed) |

## EU AI Act

| Article | AGENTSECURITY.md Mapping |
|---|---|
| Article 9 - Risk management | Constraints + threat model + tiered enforcement |
| Article 12 - Record-keeping | Tamper-proof audit logging (regulated tier) |
| Article 13 - Transparency | Description field + constraints disclosure |
| Article 14 - Human oversight | Human-in-the-Loop with dual approval |

## OWASP Top 10 for LLM Applications

See [owasp-llm-top10.md](owasp-llm-top10.md) for detailed control mapping.

## Important Disclaimer

Declaring `governance: [NIST-AI-RMF]` in AGENTSECURITY.md is a **statement of design intent**, not a certification claim. Formal compliance requires independent audit against the framework's full requirements. AGENTSECURITY.md covers the agent architecture layer — it does not address organizational governance, training, or broader management system requirements.
