"""AgentSecurity CLI — validate and enforce AGENTSECURITY.md policies."""

from __future__ import annotations

import hmac
import json
import sys
from pathlib import Path

import click

from . import __version__
from .advisor import detect_frameworks, generate_enforcement_guides, generate_recommendations
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

    Docs: https://agentsecurity.in
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
        out = result.to_dict()
        if scan_result.framework_context:
            out["framework_context"] = scan_result.framework_context.to_dict()
        click.echo(json.dumps(out, indent=2))
    else:
        text = report_text(result)
        click.echo(text)

        # Show scan stats
        click.echo(f"  Files scanned: {scan_result.files_scanned}")
        if scan_result.detected_tools:
            click.echo(f"  Detected tools: {', '.join(sorted(scan_result.detected_tools))}")

        # Show detected frameworks
        ctx = scan_result.framework_context
        if ctx and ctx.frameworks:
            click.echo(f"  Frameworks: {', '.join(ctx.frameworks)}")
        if ctx and ctx.agent_platforms:
            click.echo(f"  Agent platforms: {', '.join(ctx.agent_platforms)}")

        # Show top recommendations
        if ctx and ctx.recommendations:
            critical = [r for r in ctx.recommendations if r.priority == "critical"]
            high = [r for r in ctx.recommendations if r.priority == "high"]
            top = (critical + high)[:3]
            if top:
                click.echo("")
                click.echo("  Recommendations:")
                for r in top:
                    click.echo(f"    [{r.priority.upper()}] {r.title}")

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


TIER_DESCRIPTIONS = {
    "basic": "Prototypes & internal tools. Minimal friction, basic guardrails.",
    "standard": "Production agents. Tool allowlisting, HITL for high-risk, OWASP alignment.",
    "strict": "Sensitive data & financial systems. Mandatory sandbox, full audit, NIST alignment.",
    "regulated": "Healthcare, finance, government. Tamper-proof audit, dual approval, full compliance.",
}


@main.command(name="init")
@click.option("--tier", type=click.Choice(["basic", "standard", "strict", "regulated"]),
              default=None, help="Security tier template to use.")
@click.option("--name", default=None, help="Agent name.")
@click.option("--output", "-o", type=click.Path(), default="AGENTSECURITY.md",
              help="Output file path.")
def init_cmd(tier: str | None, name: str | None, output: str):
    """Initialize a new AGENTSECURITY.md from a template.

    Creates a pre-configured security policy file based on the chosen tier.
    When run without --tier, launches an interactive selector.
    """
    # Interactive mode: prompt for tier and name if not provided
    if tier is None:
        tier = _interactive_tier_select()

    if name is None:
        name = click.prompt("Agent name", default="my-agent")

    output_path = Path(output).resolve()
    cwd = Path.cwd().resolve()
    if not str(output_path).startswith(str(cwd)):
        click.echo("Error: Output path must be within the current directory.", err=True)
        sys.exit(1)

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
    click.echo(f"\nCreated {output} (tier: {tier})")
    click.echo("Next steps:")
    click.echo("  1. Edit the file to match your agent's actual tools and capabilities")
    click.echo("  2. Run 'agentsec validate .' to check your policy")
    click.echo("  3. Run 'agentsec check .' to scan your codebase")
    click.echo("  4. Run 'agentsec suggest .' to get framework-specific recommendations")
    click.echo("  5. Run 'agentsec lock .' to protect against tampering")


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
@click.option("--verbose", "-v", is_flag=True, help="Include full policy details (Layer 2).")
@click.option("--compact", "-c", is_flag=True, help="Single-line output (token efficient).")
def to_prompt(path: str, verbose: bool, compact: bool):
    """Generate system prompt XML snippet for agent integration.

    Output can be injected into an agent's system prompt to provide
    security context at startup (~50-100 tokens).
    """
    try:
        policy = parse_policy(path)
    except (FileNotFoundError, ParseError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if not compact:
        xml = (
            "<agent_security_policy>\n"
            f"  <name>{_xml_escape(policy.name)}</name>\n"
            f"  <tier>{_xml_escape(policy.security_tier)}</tier>\n"
            f"  <enforcement>{_xml_escape(policy.enforcement)}</enforcement>\n"
            f"  <description>{_xml_escape(policy.description)}</description>\n"
            f"  <location>{_xml_escape(policy.file_path)}</location>\n"
        )
    else:
        xml = (
            f"<agent_security_policy name='{_xml_escape(policy.name)}' "
            f"tier='{_xml_escape(policy.security_tier)}' "
            f"enforcement='{_xml_escape(policy.enforcement)}' "
            f"location='{_xml_escape(policy.file_path)}'>"
        )
        if not verbose:
            xml += "</agent_security_policy>"
            click.echo(xml)
            return

    if verbose:
        if policy.constraints:
            indent = "  " if not compact else ""
            line_end = "\n" if not compact else ""
            xml += f"{indent}<constraints>{line_end}"
            for key, val in policy.constraints.items():
                xml += f"{indent}  <{key}>{_xml_escape(str(val))}</{key}>{line_end}"
            xml += f"{indent}</constraints>{line_end}"
        
        if policy.tools:
            indent = "  " if not compact else ""
            line_end = "\n" if not compact else ""
            xml += f"{indent}<declared_tools>{line_end}"
            for tool in policy.tools:
                xml += f"{indent}  <tool>{line_end}"
                for k, v in tool.items():
                    xml += f"{indent}    <{k}>{_xml_escape(str(v))}</{k}>{line_end}"
                xml += f"{indent}  </tool>{line_end}"
            xml += f"{indent}</declared_tools>{line_end}"

        if policy.runtime:
            indent = "  " if not compact else ""
            line_end = "\n" if not compact else ""
            xml += f"{indent}<runtime>{line_end}"
            for k, v in policy.runtime.items():
                xml += f"{indent}  <{k}>{_xml_escape(str(v))}</{k}>{line_end}"
            xml += f"{indent}</runtime>{line_end}"

        if policy.human_in_the_loop:
            indent = "  " if not compact else ""
            line_end = "\n" if not compact else ""
            xml += f"{indent}<human_in_the_loop>{line_end}"
            for k, v in policy.human_in_the_loop.items():
                xml += f"{indent}  <{k}>{_xml_escape(str(v))}</{k}>{line_end}"
            xml += f"{indent}</human_in_the_loop>{line_end}"

        if policy.audit:
            indent = "  " if not compact else ""
            line_end = "\n" if not compact else ""
            xml += f"{indent}<audit>{line_end}"
            for k, v in policy.audit.items():
                xml += f"{indent}  <{k}>{_xml_escape(str(v))}</{k}>{line_end}"
            xml += f"{indent}</audit>{line_end}"

    if not compact:
        xml += "</agent_security_policy>"
    else:
        xml += "</agent_security_policy>"

    click.echo(xml)


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text",
              help="Output format.")
def suggest(path: str, fmt: str):
    """Detect frameworks and suggest security recommendations.

    Scans the codebase to identify agent frameworks (LangChain, CrewAI,
    OpenAI SDK, etc.), agent platforms (Claude Code, Cursor, Copilot),
    and provides tailored recommendations for protecting AGENTSECURITY.md
    and enforcing security boundaries.
    """
    try:
        policy = parse_policy(path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ParseError as e:
        click.echo(f"Parse error: {e}", err=True)
        sys.exit(1)

    root = Path(path)
    if root.is_file():
        root = root.parent

    ctx = detect_frameworks(root)
    scan_result = scan_codebase(path, policy)

    ctx.recommendations = generate_recommendations(
        ctx=ctx,
        tier=policy.security_tier,
        enforcement=policy.enforcement,
        declared_tools=policy.declared_tool_names,
        detected_tools=scan_result.detected_tools,
        constraints=policy.constraints,
        runtime=policy.runtime,
        audit=policy.audit,
        hitl=policy.human_in_the_loop,
    )
    ctx.enforcement_guides = generate_enforcement_guides(ctx, policy.security_tier)

    if fmt == "json":
        click.echo(json.dumps(ctx.to_dict(), indent=2))
    else:
        click.echo("")
        click.echo(f"  AgentSecurity Advisor — {policy.name}")
        click.echo(f"  Tier: {policy.security_tier} | Language: {ctx.language or 'unknown'}")
        click.echo("  " + "─" * 60)

        if ctx.frameworks:
            click.echo(f"\n  Detected frameworks: {', '.join(ctx.frameworks)}")
        else:
            click.echo("\n  No agent frameworks detected.")

        if ctx.agent_platforms:
            click.echo(f"  Agent platforms: {', '.join(ctx.agent_platforms)}")

        if ctx.integrity_hash:
            click.echo(f"  Policy hash: {ctx.integrity_hash[:16]}...")

        if ctx.recommendations:
            click.echo(f"\n  Recommendations ({len(ctx.recommendations)}):")
            click.echo("  " + "─" * 60)
            for i, r in enumerate(ctx.recommendations, 1):
                click.echo(f"\n  {i}. [{r.priority.upper()}] {r.title}")
                click.echo(f"     {r.description}")
                click.echo(f"     Action:")
                for line in r.action.split("\n"):
                    click.echo(f"       {line}")

        if ctx.enforcement_guides:
            click.echo(f"\n  Enforcement Guides ({len(ctx.enforcement_guides)}):")
            click.echo("  " + "─" * 60)
            for guide in ctx.enforcement_guides:
                click.echo(f"    - {guide}")

        click.echo("")


@main.command(name="lock")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=".agentsecurity.lock",
              help="Lock file path.")
def lock_cmd(path: str, output: str):
    """Generate a lock file with the policy SHA-256 hash.

    The lock file can be used in CI/CD to detect unauthorized modifications
    to AGENTSECURITY.md. Agents must NEVER modify the lock file.
    """
    from .advisor import compute_policy_hash

    root = Path(path).resolve()
    if root.is_file():
        root = root.parent

    # Confine lock file output to within the project directory
    lock_output = Path(output).resolve()
    if not str(lock_output).startswith(str(root)):
        click.echo("Error: Lock file path must be within the project directory.", err=True)
        sys.exit(1)

    policy_hash = compute_policy_hash(root)
    if not policy_hash:
        click.echo("Error: No AGENTSECURITY.md found.", err=True)
        sys.exit(1)

    lock_content = (
        f"# AgentSecurity Lock File — DO NOT MODIFY\n"
        f"# This file is auto-generated by 'agentsec lock'\n"
        f"# It verifies AGENTSECURITY.md has not been tampered with.\n"
        f"#\n"
        f"# To verify: agentsec verify . --lock {output}\n"
        f"sha256: {policy_hash}\n"
    )

    lock_output.write_text(lock_content, encoding="utf-8")
    click.echo(f"Lock file written to {output}")
    click.echo(f"  SHA-256: {policy_hash}")
    click.echo(f"  Add {output} to version control.")
    click.echo(f"  Add to CI: agentsec verify . --lock {output}")


@main.command(name="verify")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--lock", "lock_file", type=click.Path(exists=True), default=".agentsecurity.lock",
              help="Lock file to verify against.")
def verify_cmd(path: str, lock_file: str):
    """Verify AGENTSECURITY.md has not been tampered with.

    Compares the current SHA-256 hash of AGENTSECURITY.md against the
    hash stored in the lock file. Exits with code 1 if tampered.
    """
    from .advisor import compute_policy_hash

    root = Path(path)
    if root.is_file():
        root = root.parent

    current_hash = compute_policy_hash(root)
    if not current_hash:
        click.echo("FAIL: No AGENTSECURITY.md found.", err=True)
        sys.exit(1)

    lock_path = Path(lock_file)
    expected_hash = ""
    try:
        lock_content = lock_path.read_text(encoding="utf-8")
    except (PermissionError, OSError) as e:
        click.echo(f"FAIL: Cannot read lock file: {e}", err=True)
        sys.exit(1)
    for line in lock_content.splitlines():
        line = line.strip()
        if line.startswith("sha256:"):
            expected_hash = line.split(":", 1)[1].strip()
            break

    if not expected_hash:
        click.echo(f"FAIL: No sha256 hash found in {lock_file}.", err=True)
        sys.exit(1)

    # Use timing-safe comparison to prevent hash oracle side-channel attacks
    if hmac.compare_digest(current_hash, expected_hash):
        click.echo(f"PASS: AGENTSECURITY.md integrity verified.")
        click.echo(f"  Hash: {current_hash[:16]}...")
    else:
        click.echo(f"FAIL: AGENTSECURITY.md has been modified!")
        click.echo(f"  Expected: {expected_hash[:16]}...")
        click.echo(f"  Current:  {current_hash[:16]}...")
        click.echo("  The security policy may have been tampered with.")
        sys.exit(1)


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
    """Escape XML special characters and control characters.

    Prevents XML injection via newlines, carriage returns, and special chars
    that could break the XML structure of to-prompt output.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
        .replace("\n", "&#10;")
        .replace("\r", "&#13;")
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


def _interactive_tier_select() -> str:
    """Interactive tier selection with descriptions."""
    click.echo("")
    click.echo("  Select a security tier for your agent:")
    click.echo("  " + "-" * 60)

    tiers = list(TIER_DESCRIPTIONS.items())
    for i, (tier_name, desc) in enumerate(tiers, 1):
        click.echo(f"  [{i}] {tier_name:10s} {desc}")

    click.echo("  " + "-" * 60)

    while True:
        choice = click.prompt("  Your choice", type=int, default=2)
        if 1 <= choice <= len(tiers):
            selected = tiers[choice - 1][0]
            click.echo(f"  Selected: {selected}")
            return selected
        click.echo("  Please enter a number between 1 and 4.")


if __name__ == "__main__":
    main()
