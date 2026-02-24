# OWASP Top 10 for LLM Applications (2025 Edition)

Reference document for the AgentSecurity specification. Maps OWASP LLM risks to AGENTSECURITY.md controls.

## 1. Prompt Injection (LLM01)
**Risk:** Malicious inputs causing the LLM to perform unauthorized actions or reveal sensitive data.
**AgentSecurity Control:** `constraints.hard_no` + `tools` scope restrictions + input sanitization
**ASEC Rules:** ASEC-016 (constraints check)

## 2. Insecure Output Handling (LLM02)
**Risk:** LLM-generated code/content creates vulnerabilities when rendered or executed without validation.
**AgentSecurity Control:** `constraints.hard_no` (no eval/exec) + `runtime.sandbox`
**ASEC Rules:** ASEC-020 (dangerous pattern detection)

## 3. Training Data Poisoning (LLM03)
**Risk:** Manipulation of data used to fine-tune the model.
**AgentSecurity Control:** Out of scope (pre-training concern, not deployment architecture)

## 4. Model Denial of Service (LLM04)
**Risk:** Attackers consuming excessive resources causing service degradation.
**AgentSecurity Control:** `runtime.resources` (max_memory, max_cpu) + `constraints.max_autonomous_steps`
**ASEC Rules:** ASEC-016 (step limit check)

## 5. Supply Chain Vulnerabilities (LLM05)
**Risk:** Vulnerabilities in third-party libraries, models, or plugins.
**AgentSecurity Control:** `tools` declaration (explicit dependency tracking) + secret scanning
**ASEC Rules:** ASEC-021 (secret detection), ASEC-022 (undeclared tools)

## 6. Sensitive Information Disclosure (LLM06)
**Risk:** LLM revealing PII, secrets, or confidential data.
**AgentSecurity Control:** Secret scanning + `constraints.hard_no` (no plaintext secrets) + PII detection
**ASEC Rules:** ASEC-021 (secret detection)

## 7. Insecure Plugin Design (LLM07)
**Risk:** Plugins performing actions without proper authorization or validation.
**AgentSecurity Control:** `tools` section with explicit permissions, scopes, and confirmation requirements
**ASEC Rules:** ASEC-010 (tool declaration), ASEC-022 (undeclared tool usage)

## 8. Excessive Agency (LLM08)
**Risk:** LLMs taking autonomous actions leading to unintended consequences.
**AgentSecurity Control:** `human_in_the_loop` + `constraints.max_autonomous_steps` + `tools.requires_confirmation`
**ASEC Rules:** ASEC-011 (overprivilege), ASEC-012 (HITL check), ASEC-016 (step limits)

## 9. Overreliance (LLM09)
**Risk:** Users trusting LLM output without verification.
**AgentSecurity Control:** `human_in_the_loop` for critical decisions (human verification step)

## 10. Model Theft (LLM10)
**Risk:** Extraction or unauthorized access to proprietary models.
**AgentSecurity Control:** Out of scope (infrastructure concern, not agent architecture)

---

**Source:** [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
