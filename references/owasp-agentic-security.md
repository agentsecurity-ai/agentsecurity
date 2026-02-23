# OWASP Agentic Security Risks

Reference document for agent-specific security threats. Extends the OWASP LLM Top 10 with autonomous agent risks.

## 1. Autonomous Action Loops
**Risk:** Agent enters recursive loops consuming resources and potentially causing DoS.
**AgentSecurity Control:** `constraints.max_autonomous_steps` + `runtime.timeout`
**Tier:** Required at standard+

## 2. Tool Abuse & Unauthorized API Calls
**Risk:** Agent using available tools in unintended ways (e.g., destructive commands, data exfiltration).
**AgentSecurity Control:** `tools` section with explicit allowlisting, scope restrictions, denied operations
**Tier:** Recommended at basic, required at standard+

## 3. Memory Injection (Long-Term Memory Poisoning)
**Risk:** Attacker injects malicious instructions into agent memory for later retrieval and execution.
**AgentSecurity Control:** `constraints.hard_no` for memory boundaries + context separation
**Tier:** Addressed in constraints section

## 4. Goal Misalignment / Reward Hacking
**Risk:** Agent achieves goals in harmful ways.
**AgentSecurity Control:** `human_in_the_loop` for destructive actions + `constraints.escalation_on_uncertainty`
**Tier:** HITL required at standard+

## 5. Sandboxing Failures (Container Escape)
**Risk:** Agent breaks out of execution environment to access host system.
**AgentSecurity Control:** `runtime.sandbox` with type declaration + capability restrictions
**Tier:** Required at strict+
**ASEC Rules:** ASEC-013 (sandbox requirement check)

## 6. Multi-Agent Coordination Failures
**Risk:** Compromised agent propagates malicious instructions to other agents.
**AgentSecurity Control:** Each agent has its own AGENTSECURITY.md (planned: cross-agent trust in v0.2)
**Tier:** Per-agent policy enforcement

---

**Source:** Based on emerging agentic AI security research and OWASP community discussions.
