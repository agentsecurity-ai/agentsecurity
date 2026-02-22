"""AgentSecurity CLI — validate and enforce AGENTSECURITY.md policies."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import __version__
from .parser import ParseError, parse_policy
from .reporter import report_badge, report_json, report_text
from .scanner import scan_codebase
from .validator import validate_policy


@click.group()
@click.version_option(version=__version__, prog_name="agentsec")
def main():
    """AgentSecurity CLI — The security contract for autonomous agents.

    Validate AGENTSECURITY.md policies, scan codebases for violations,
    and generate security scorecards.

    Docs: https://agentsecurity.dev
    """
    pass


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["high", "medium", "low"]),
              default="high", help="Exit with error on this severity or above.")
def validate(path: str, fmt: str, fail_on: str):
    """Validate AGENTSECURITY.md against the spec schema.

    Checks that all required fields are present, values are valid,
    and tier-specific requirements are met.
    """
    try:
        policy = parse_policy(path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ParseError as e:
        click.echo(f"Parse error: {e}", err=True)
        sys.exit(1)

    result = validate_policy(policy)

    if fmt == "json":
        click.echo(report_json(result))
    else:
        click.echo(report_text(result))

    if _should_fail(result, fail_on):
        sys.exit(1)


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
@click.option("--fail-on", type=click.Choice(["high", "medium", "low"]),
              default="high", help="Exit with error on this severity or above.")
def check(path: str, fmt: str, fail_on: str):
    """Scan codebase for security violations against declared policy.

    Combines schema validation with code scanning to detect:
    - Undeclared tool usage
    - Hardcoded secrets
    - Dangerous code patterns (eval, exec, curl|bash)
    - Policy compliance gaps
    """
    try:
        policy = parse_policy(path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ParseError as e:
        click.echo(f"Parse error: {e}", err=True)
        sys.exit(1)

    # Run schema validation
    result = validate_policy(policy)

    # Run code scanning
    scan_result = scan_codebase(path, policy)
    result.findings.extend(scan_result.findings)

    # Recalculate score with scan findings
    score = 100
    for f in result.findings:
        if f.severity == "high":
            score -= 15
        elif f.severity == "medium":
            score -= 8
        elif f.severity == "low":
            score -= 3
    result.score = max(0, score)

    if fmt == "json":
        click.echo(report_json(result))
    else:
        text = report_text(result)
        click.echo(text)

        # Show scan stats
        click.echo(f"  Files scanned: {scan_result.files_scanned}")
        if scan_result.detected_tools:
            click.echo(f"  Detected tools: {', '.join(sorted(scan_result.detected_tools))}")
        click.echo("")

    if _should_fail(result, fail_on):
        sys.exit(1)


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json", "badge"]),
              default="text", help="Output format.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write report to file.")
def report(path: str, fmt: str, output: str | None):
    """Generate a security scorecard for the agent.

    Includes validation findings, scan results, and compliance control mapping.
    """
    try:
        policy = parse_policy(path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ParseError as e:
        click.echo(f"Parse error: {e}", err=True)
        sys.exit(1)

    result = validate_policy(policy)
    scan_result = scan_codebase(path, policy)
    result.findings.extend(scan_result.findings)

    # Recalculate score
    score = 100
    for f in result.findings:
        if f.severity == "high":
            score -= 15
        elif f.severity == "medium":
            score -= 8
        elif f.severity == "low":
            score -= 3
    result.score = max(0, score)

    if fmt == "badge":
        text = report_badge(result)
    elif fmt == "json":
        text = report_json(result)
    else:
        text = report_text(result)

    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(f"Report written to {output}")
    else:
        click.echo(text)


@main.command(name="init")
@click.option("--tier", type=click.Choice(["basic", "standard", "strict", "regulated"]),
              default="standard", help="Security tier template to use.")
@click.option("--name", default=None, help="Agent name.")
@click.option("--output", "-o", type=click.Path(), default="AGENTSECURITY.md",
              help="Output file path.")
def init_cmd(tier: str, name: str | None, output: str):
    """Initialize a new AGENTSECURITY.md from a template.

    Creates a pre-configured security policy file based on the chosen tier.
    """
    output_path = Path(output)
    if output_path.exists():
        if not click.confirm(f"{output} already exists. Overwrite?"):
            click.echo("Aborted.")
            return

    # Find template
    template_dir = Path(__file__).parent.parent.parent.parent.parent / "templates" / tier
    template_file = template_dir / "AGENTSECURITY.md"

    if not template_file.exists():
        # Fallback: generate minimal template inline
        content = _generate_minimal_template(tier, name)
    else:
        content = template_file.read_text(encoding="utf-8")
        if name:
            content = content.replace("name: my-agent", f"name: {name}", 1)
            content = content.replace("name: my-regulated-agent", f"name: {name}", 1)

    output_path.write_text(content, encoding="utf-8")
    click.echo(f"Created {output} (tier: {tier})")
    click.echo("Next steps:")
    click.echo("  1. Edit the file to match your agent's actual tools and capabilities")
    click.echo("  2. Run 'agentsec validate .' to check your policy")
    click.echo("  3. Run 'agentsec check .' to scan your codebase")


@main.command(name="read-properties")
@click.argument("path", default=".", type=click.Path(exists=True))
def read_properties(path: str):
    """Output policy properties as JSON (for tooling integration)."""
    try:
        policy = parse_policy(path)
    except (FileNotFoundError, ParseError) as e:
        click.echo(json.dumps({"error": str(e)}), err=True)
        sys.exit(1)

    props = {
        "name": policy.name,
        "description": policy.description,
        "security_tier": policy.security_tier,
        "version": policy.version,
        "governance": policy.governance,
        "enforcement": policy.enforcement,
        "metadata": policy.metadata,
        "declared_tools": list(policy.declared_tool_names),
    }
    click.echo(json.dumps(props, indent=2))


@main.command(name="to-prompt")
@click.argument("path", default=".", type=click.Path(exists=True))
def to_prompt(path: str):
    """Generate system prompt XML snippet for agent integration.

    Output can be injected into an agent's system prompt to provide
    security context at startup (~50-100 tokens).
    """
    try:
        policy = parse_policy(path)
    except (FileNotFoundError, ParseError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    xml = (
        "<agent_security_policy>\n"
        f"  <name>{_xml_escape(policy.name)}</name>\n"
        f"  <tier>{_xml_escape(policy.security_tier)}</tier>\n"
        f"  <enforcement>{_xml_escape(policy.enforcement)}</enforcement>\n"
        f"  <description>{_xml_escape(policy.description)}</description>\n"
        f"  <location>{_xml_escape(policy.file_path)}</location>\n"
        "</agent_security_policy>"
    )
    click.echo(xml)


def _should_fail(result, fail_on: str) -> bool:
    """Determine if the CLI should exit with error."""
    severity_levels = {"low": 1, "medium": 2, "high": 3}
    threshold = severity_levels.get(fail_on, 3)
    for f in result.findings:
        level = severity_levels.get(f.severity, 0)
        if level >= threshold:
            return True
    return False


def _xml_escape(text: str) -> str:
    """Escape XML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _generate_minimal_template(tier: str, name: str | None) -> str:
    """Generate a minimal template when the bundled template is not found."""
    agent_name = name or "my-agent"
    return f"""---
name: {agent_name}
description: "Describe what your agent does"
security_tier: {tier}
version: "0.1"
enforcement: warn
metadata:
  author: "your-name"
  last_reviewed: "2026-02-22"
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never execute eval() or equivalent dynamic code execution"
    - "Never access files outside the declared scope"
  max_autonomous_steps: 100
```

## Tools

```yaml
tools:
  - name: file_system
    permission: read_write
    scope:
      allowed_paths: ["./"]
```

## Runtime

```yaml
runtime:
  sandbox:
    required: false
  timeout:
    total_seconds: 600
```
"""


if __name__ == "__main__":
    main()
