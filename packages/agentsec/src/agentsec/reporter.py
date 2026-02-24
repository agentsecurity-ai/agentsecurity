"""Output formatting for agentsec validation results."""

from __future__ import annotations

import json
from typing import TextIO

from .validator import ValidationResult


def report_text(result: ValidationResult, stream: TextIO | None = None) -> str:
    """Generate human-readable text report.

    Args:
        result: Validation result to format.
        stream: Optional stream to write to.

    Returns:
        Formatted text report.
    """
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append(f"  AgentSecurity Check — {result.agent_name or '(unnamed)'}")
    lines.append(f"  Tier: {result.tier or '(none)'} | Enforcement: {result.enforcement or 'warn'}")
    lines.append("  " + "─" * 60)
    lines.append("")

    if not result.findings:
        lines.append("  PASS  All checks passed. No findings.")
        lines.append("")
    else:
        # Group by severity
        for severity in ["high", "medium", "low", "info"]:
            severity_findings = [f for f in result.findings if f.severity == severity]
            for f in severity_findings:
                icon = _severity_icon(f.severity)
                tag = f"[{f.severity.upper()}]"
                location = f" ({f.file}:{f.line})" if f.file and f.line else ""
                lines.append(f"  {icon} {tag:7s} {f.message}{location}")
                if f.control:
                    lines.append(f"           Control: {f.control}")

    # Summary
    lines.append("")
    lines.append("  " + "─" * 60)
    total = len(result.findings)
    lines.append(
        f"  Score: {result.score}/100 | "
        f"Findings: {total} "
        f"({result.high_count} high, {result.medium_count} medium, {result.low_count} low)"
    )

    # Controls
    if result.controls:
        ctrl_strs = []
        for ctrl, passed in result.controls.items():
            icon = "+" if passed else "X"
            ctrl_strs.append(f"{ctrl} {icon}")
        lines.append(f"  Controls: {' | '.join(ctrl_strs)}")

    # Status
    if result.passed:
        lines.append("")
        lines.append("  RESULT: PASS")
    else:
        lines.append("")
        lines.append("  RESULT: FAIL (high severity findings detected)")

    lines.append("")

    text = "\n".join(lines)
    if stream:
        stream.write(text)
    return text


def report_json(result: ValidationResult, stream: TextIO | None = None) -> str:
    """Generate machine-readable JSON report.

    Args:
        result: Validation result to format.
        stream: Optional stream to write to.

    Returns:
        JSON string.
    """
    text = json.dumps(result.to_dict(), indent=2)
    if stream:
        stream.write(text)
    return text


def report_badge(result: ValidationResult) -> str:
    """Generate a markdown badge for the security score.

    Returns:
        Markdown badge string.
    """
    tier = result.tier or "unknown"
    score = result.score

    if score >= 90:
        color = "brightgreen"
    elif score >= 70:
        color = "green"
    elif score >= 50:
        color = "yellow"
    elif score >= 30:
        color = "orange"
    else:
        color = "red"

    return (
        f"[![AgentSecurity: {tier}]"
        f"(https://img.shields.io/badge/AgentSecurity-{tier}_{score}%25-{color})]"
        f"(https://agentsecurity.in)"
    )


def _severity_icon(severity: str) -> str:
    """Return a text icon for severity level."""
    icons = {
        "high": "FAIL",
        "medium": "WARN",
        "low": "NOTE",
        "info": "INFO",
    }
    return icons.get(severity, "    ")
