"""Validate AGENTSECURITY.md against the spec schema and security rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .parser import AgentSecurityPolicy


@dataclass
class Finding:
    """A single validation finding."""

    rule_id: str
    severity: str  # "high", "medium", "low", "info"
    message: str
    file: str = ""
    line: int = 0
    control: str = ""  # OWASP/NIST control reference

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "control": self.control,
        }


@dataclass
class ValidationResult:
    """Complete validation result for a policy."""

    agent_name: str = ""
    tier: str = ""
    enforcement: str = ""
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    controls: dict[str, bool] = field(default_factory=dict)
    timestamp: str = ""

    @property
    def passed(self) -> bool:
        return not any(f.severity == "high" for f in self.findings)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def to_dict(self) -> dict:
        return {
            "agent": self.agent_name,
            "tier": self.tier,
            "enforcement": self.enforcement,
            "score": self.score,
            "passed": self.passed,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
            "controls": self.controls,
            "timestamp": self.timestamp,
        }


# Valid values
VALID_TIERS = {"basic", "standard", "strict", "regulated"}
VALID_ENFORCEMENT = {"warn", "block", "block_and_audit"}
VALID_GOVERNANCE = {
    "NIST-AI-RMF", "OWASP-LLM-TOP10", "ISO-42001", "EU-AI-ACT",
    "SOC2", "HIPAA", "PCI-DSS", "GDPR",
}
NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")

# Tier requirement levels
TIER_REQUIRES_TOOLS = {"standard", "strict", "regulated"}
TIER_REQUIRES_HITL = {"standard", "strict", "regulated"}
TIER_REQUIRES_SANDBOX = {"strict", "regulated"}
TIER_REQUIRES_AUDIT = {"strict", "regulated"}
TIER_REQUIRES_THREAT_MODEL = {"strict", "regulated"}

# Review cadence per tier (days)
TIER_REVIEW_CADENCE = {
    "basic": None,
    "standard": 90,
    "strict": 30,
    "regulated": 14,
}


def validate_policy(policy: AgentSecurityPolicy) -> ValidationResult:
    """Run all validation rules against a parsed policy.

    Args:
        policy: Parsed AgentSecurityPolicy object.

    Returns:
        ValidationResult with all findings.
    """
    result = ValidationResult(
        agent_name=policy.name,
        tier=policy.security_tier,
        enforcement=policy.enforcement,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )

    # Run all rules
    _check_required_fields(policy, result)
    _check_name_format(policy, result)
    _check_tier_value(policy, result)
    _check_version_format(policy, result)
    _check_enforcement_value(policy, result)
    _check_governance_values(policy, result)
    _check_description_quality(policy, result)
    _check_tool_declarations(policy, result)
    _check_overprivileged_tools(policy, result)
    _check_hitl_configuration(policy, result)
    _check_sandbox_requirement(policy, result)
    _check_audit_configuration(policy, result)
    _check_network_policy(policy, result)
    _check_constraints(policy, result)
    _check_policy_staleness(policy, result)

    # Calculate score
    result.score = _calculate_score(result)

    # Map controls
    result.controls = _map_controls(result)

    return result


def _check_required_fields(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-001: Check that all required frontmatter fields are present."""
    required = {
        "name": policy.name,
        "description": policy.description,
        "security_tier": policy.security_tier,
        "version": policy.version,
    }
    for field_name, value in required.items():
        if not value or not str(value).strip():
            result.findings.append(Finding(
                rule_id="ASEC-001",
                severity="high",
                message=f"Missing required field: '{field_name}'",
                file=policy.file_path,
                control="Spec compliance",
            ))


def _check_name_format(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-002: Validate name format."""
    if not policy.name:
        return
    if not NAME_PATTERN.match(policy.name):
        result.findings.append(Finding(
            rule_id="ASEC-002",
            severity="high",
            message=(
                f"Invalid name '{policy.name}'. Must be 1-64 chars, lowercase "
                "alphanumeric + hyphens, no leading/trailing/consecutive hyphens."
            ),
            file=policy.file_path,
            control="Spec compliance",
        ))
    if "--" in policy.name:
        result.findings.append(Finding(
            rule_id="ASEC-002",
            severity="high",
            message=f"Name '{policy.name}' contains consecutive hyphens ('--').",
            file=policy.file_path,
            control="Spec compliance",
        ))
    if len(policy.name) > 64:
        result.findings.append(Finding(
            rule_id="ASEC-002",
            severity="high",
            message=f"Name '{policy.name}' exceeds 64 character limit.",
            file=policy.file_path,
            control="Spec compliance",
        ))


def _check_tier_value(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-003: Validate security_tier is a known value."""
    if policy.security_tier and policy.security_tier not in VALID_TIERS:
        result.findings.append(Finding(
            rule_id="ASEC-003",
            severity="high",
            message=(
                f"Invalid security_tier '{policy.security_tier}'. "
                f"Must be one of: {', '.join(sorted(VALID_TIERS))}"
            ),
            file=policy.file_path,
            control="Spec compliance",
        ))


def _check_version_format(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-004: Validate version format."""
    if policy.version and not VERSION_PATTERN.match(policy.version):
        result.findings.append(Finding(
            rule_id="ASEC-004",
            severity="medium",
            message=(
                f"Invalid version '{policy.version}'. "
                "Must match 'major.minor' format (e.g., '0.1', '1.0')."
            ),
            file=policy.file_path,
            control="Spec compliance",
        ))


def _check_enforcement_value(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-005: Validate enforcement mode."""
    if policy.enforcement and policy.enforcement not in VALID_ENFORCEMENT:
        result.findings.append(Finding(
            rule_id="ASEC-005",
            severity="high",
            message=(
                f"Invalid enforcement '{policy.enforcement}'. "
                f"Must be one of: {', '.join(sorted(VALID_ENFORCEMENT))}"
            ),
            file=policy.file_path,
            control="Spec compliance",
        ))


def _check_governance_values(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-006: Validate governance framework references."""
    for g in policy.governance:
        if g not in VALID_GOVERNANCE:
            result.findings.append(Finding(
                rule_id="ASEC-006",
                severity="low",
                message=(
                    f"Unknown governance framework '{g}'. "
                    f"Known values: {', '.join(sorted(VALID_GOVERNANCE))}"
                ),
                file=policy.file_path,
                control="Spec compliance",
            ))


def _check_description_quality(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-007: Check description is meaningful."""
    if policy.description and len(policy.description) < 10:
        result.findings.append(Finding(
            rule_id="ASEC-007",
            severity="medium",
            message="Description is too short. Provide a meaningful summary of the agent's purpose and security context.",
            file=policy.file_path,
            control="Spec compliance",
        ))
    if policy.description and len(policy.description) > 512:
        result.findings.append(Finding(
            rule_id="ASEC-007",
            severity="low",
            message="Description exceeds 512 characters. Keep it concise for efficient discovery.",
            file=policy.file_path,
            control="Spec compliance",
        ))


def _check_tool_declarations(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-010: Check tool declarations exist for tiers that require them."""
    if policy.security_tier in TIER_REQUIRES_TOOLS and not policy.tools:
        result.findings.append(Finding(
            rule_id="ASEC-010",
            severity="high",
            message=(
                f"Tier '{policy.security_tier}' requires tool declarations. "
                "Add a Tools section with declared tool permissions."
            ),
            file=policy.file_path,
            control="OWASP-LLM07",
        ))

    # Check each tool has required fields
    for i, tool in enumerate(policy.tools):
        if not tool.get("name"):
            result.findings.append(Finding(
                rule_id="ASEC-010",
                severity="high",
                message=f"Tool #{i + 1} is missing a 'name' field.",
                file=policy.file_path,
                control="OWASP-LLM07",
            ))
        if not tool.get("permission"):
            result.findings.append(Finding(
                rule_id="ASEC-010",
                severity="medium",
                message=f"Tool '{tool.get('name', f'#{i + 1}')}' is missing a 'permission' field.",
                file=policy.file_path,
                control="OWASP-LLM07",
            ))


def _check_overprivileged_tools(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-011: Flag overprivileged tool permissions."""
    dangerous_permissions = {"admin", "root", "superuser", "full"}
    for tool in policy.tools:
        name = tool.get("name", "unnamed")
        permission = str(tool.get("permission", ""))

        if permission in dangerous_permissions:
            result.findings.append(Finding(
                rule_id="ASEC-011",
                severity="high",
                message=f"Tool '{name}' has overprivileged permission '{permission}'. Use least-privilege.",
                file=policy.file_path,
                control="OWASP-LLM08",
            ))

        # Check for wildcard scopes
        scope = tool.get("scope", {})
        if scope == "*" or (isinstance(scope, dict) and any(v == "*" for v in scope.values() if isinstance(v, str))):
            result.findings.append(Finding(
                rule_id="ASEC-011",
                severity="high",
                message=f"Tool '{name}' has wildcard scope ('*'). Narrow the scope to specific resources.",
                file=policy.file_path,
                control="OWASP-LLM08",
            ))

        # Check for wildcard in lists
        if isinstance(scope, dict):
            for key, val in scope.items():
                if isinstance(val, list) and "*" in val:
                    result.findings.append(Finding(
                        rule_id="ASEC-011",
                        severity="medium",
                        message=f"Tool '{name}' scope '{key}' contains wildcard. Be specific.",
                        file=policy.file_path,
                        control="OWASP-LLM08",
                    ))


def _check_hitl_configuration(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-012: Check HITL configuration for tiers that require it."""
    if policy.security_tier in TIER_REQUIRES_HITL and not policy.human_in_the_loop:
        severity = "high" if policy.security_tier in {"strict", "regulated"} else "medium"
        result.findings.append(Finding(
            rule_id="ASEC-012",
            severity=severity,
            message=(
                f"Tier '{policy.security_tier}' requires human-in-the-loop configuration. "
                "Add a Human-in-the-Loop section."
            ),
            file=policy.file_path,
            control="NIST-AI-RMF:MANAGE-1.3",
        ))

    # Check strict/regulated have approval for destructive ops
    if policy.security_tier in {"strict", "regulated"} and policy.tools:
        for tool in policy.tools:
            name = tool.get("name", "unnamed")
            permission = str(tool.get("permission", ""))
            if permission in {"write", "read_write", "admin"} and not tool.get("requires_confirmation"):
                result.findings.append(Finding(
                    rule_id="ASEC-012",
                    severity="medium",
                    message=(
                        f"Tool '{name}' has '{permission}' permission but "
                        "requires_confirmation is not set. "
                        f"Tier '{policy.security_tier}' expects HITL for write operations."
                    ),
                    file=policy.file_path,
                    control="NIST-AI-RMF:MANAGE-1.3",
                ))


def _check_sandbox_requirement(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-013: Check sandbox requirement for tiers that need it."""
    sandbox = policy.runtime.get("sandbox", {}) if isinstance(policy.runtime, dict) else {}
    sandbox_required = sandbox.get("required", False)

    if policy.security_tier in TIER_REQUIRES_SANDBOX and not sandbox_required:
        result.findings.append(Finding(
            rule_id="ASEC-013",
            severity="high",
            message=(
                f"Tier '{policy.security_tier}' requires sandbox. "
                "Set runtime.sandbox.required: true."
            ),
            file=policy.file_path,
            control="OWASP-Agentic-5",
        ))


def _check_audit_configuration(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-014: Check audit logging for tiers that require it."""
    audit_enabled = policy.audit.get("enabled", False) if isinstance(policy.audit, dict) else False

    if policy.security_tier in TIER_REQUIRES_AUDIT and not audit_enabled:
        result.findings.append(Finding(
            rule_id="ASEC-014",
            severity="high",
            message=(
                f"Tier '{policy.security_tier}' requires audit logging. "
                "Add an Audit section with enabled: true."
            ),
            file=policy.file_path,
            control="ISO-42001:8.4",
        ))

    # Check regulated tier requires tamper protection
    if policy.security_tier == "regulated" and audit_enabled:
        tamper = policy.audit.get("tamper_protection", False)
        if not tamper:
            result.findings.append(Finding(
                rule_id="ASEC-014",
                severity="medium",
                message="Regulated tier recommends tamper_protection: true for audit logs.",
                file=policy.file_path,
                control="ISO-42001:8.4",
            ))


def _check_network_policy(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-015: Check for unrestricted network access."""
    network = {}
    if isinstance(policy.runtime, dict):
        network = policy.runtime.get("network", {})
    if not isinstance(network, dict):
        network = {}

    allowlist = network.get("outbound_allowlist", [])
    if isinstance(allowlist, list) and "*" in allowlist:
        result.findings.append(Finding(
            rule_id="ASEC-015",
            severity="high",
            message="Unrestricted outbound network access ('*'). Specify allowed domains.",
            file=policy.file_path,
            control="OWASP-Agentic-5",
        ))

    # Warn if no network policy for standard+ tiers
    if policy.security_tier in {"standard", "strict", "regulated"} and not network:
        result.findings.append(Finding(
            rule_id="ASEC-015",
            severity="medium",
            message=(
                f"Tier '{policy.security_tier}' should define network restrictions. "
                "Add runtime.network.outbound_allowlist."
            ),
            file=policy.file_path,
            control="OWASP-Agentic-5",
        ))


def _check_constraints(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-016: Check constraints section quality."""
    if not policy.constraints:
        if policy.security_tier in {"standard", "strict", "regulated"}:
            result.findings.append(Finding(
                rule_id="ASEC-016",
                severity="medium",
                message="No constraints defined. Add a Constraints section with hard_no rules.",
                file=policy.file_path,
                control="OWASP-LLM08",
            ))
        return

    hard_no = policy.constraints.get("hard_no", [])
    if not hard_no and policy.security_tier in {"standard", "strict", "regulated"}:
        result.findings.append(Finding(
            rule_id="ASEC-016",
            severity="medium",
            message="Constraints section has no hard_no rules. Define absolute boundaries.",
            file=policy.file_path,
            control="OWASP-LLM08",
        ))

    max_steps = policy.constraints.get("max_autonomous_steps")
    tier_limits = {"basic": None, "standard": 100, "strict": 50, "regulated": 25}
    expected = tier_limits.get(policy.security_tier)
    if expected and max_steps and int(max_steps) > expected:
        result.findings.append(Finding(
            rule_id="ASEC-016",
            severity="low",
            message=(
                f"max_autonomous_steps ({max_steps}) exceeds recommended "
                f"limit for '{policy.security_tier}' tier ({expected})."
            ),
            file=policy.file_path,
            control="OWASP-LLM08",
        ))


def _check_policy_staleness(policy: AgentSecurityPolicy, result: ValidationResult):
    """ASEC-017: Check if policy has been reviewed within cadence."""
    last_reviewed = policy.metadata.get("last_reviewed", "")
    if not last_reviewed:
        if policy.security_tier in {"standard", "strict", "regulated"}:
            result.findings.append(Finding(
                rule_id="ASEC-017",
                severity="low",
                message="No 'last_reviewed' date in metadata. Add metadata.last_reviewed for tracking.",
                file=policy.file_path,
                control="Governance",
            ))
        return

    cadence_days = TIER_REVIEW_CADENCE.get(policy.security_tier)
    if not cadence_days:
        return

    try:
        reviewed_date = datetime.strptime(last_reviewed, "%Y-%m-%d")
        if datetime.utcnow() - reviewed_date > timedelta(days=cadence_days):
            result.findings.append(Finding(
                rule_id="ASEC-017",
                severity="medium",
                message=(
                    f"Policy was last reviewed on {last_reviewed}, which exceeds the "
                    f"'{policy.security_tier}' tier cadence of {cadence_days} days. "
                    "Review and update last_reviewed."
                ),
                file=policy.file_path,
                control="Governance",
            ))
    except ValueError:
        result.findings.append(Finding(
            rule_id="ASEC-017",
            severity="low",
            message=f"Invalid last_reviewed date format '{last_reviewed}'. Use YYYY-MM-DD.",
            file=policy.file_path,
            control="Governance",
        ))


def _calculate_score(result: ValidationResult) -> int:
    """Calculate a security score from 0-100 based on findings."""
    score = 100
    for f in result.findings:
        if f.severity == "high":
            score -= 15
        elif f.severity == "medium":
            score -= 8
        elif f.severity == "low":
            score -= 3
    return max(0, score)


def _map_controls(result: ValidationResult) -> dict[str, bool]:
    """Map findings to compliance control status."""
    controls = {
        "OWASP-LLM07": True,   # Insecure Plugin Design
        "OWASP-LLM08": True,   # Excessive Agency
        "OWASP-LLM06": True,   # Sensitive Info Disclosure
        "NIST-AI-RMF": True,
        "ISO-42001": True,
    }
    for f in result.findings:
        if f.control.startswith("OWASP-LLM07"):
            controls["OWASP-LLM07"] = False
        elif f.control.startswith("OWASP-LLM08"):
            controls["OWASP-LLM08"] = False
        elif f.control.startswith("OWASP-LLM06"):
            controls["OWASP-LLM06"] = False
        elif f.control.startswith("NIST"):
            controls["NIST-AI-RMF"] = False
        elif f.control.startswith("ISO"):
            controls["ISO-42001"] = False
    return controls
