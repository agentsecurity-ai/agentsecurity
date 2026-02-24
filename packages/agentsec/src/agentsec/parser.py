"""Parse AGENTSECURITY.md files into structured data."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AgentSecurityPolicy:
    """Parsed representation of an AGENTSECURITY.md file."""

    # Required frontmatter fields
    name: str = ""
    description: str = ""
    security_tier: str = ""
    version: str = ""

    # Optional frontmatter fields
    governance: list[str] = field(default_factory=list)
    enforcement: str = "warn"
    extends: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    # Parsed body sections (raw text)
    body: str = ""
    constraints_section: str = ""
    tools_section: str = ""
    runtime_section: str = ""
    hitl_section: str = ""
    audit_section: str = ""

    # Parsed YAML blocks from body sections
    constraints: dict = field(default_factory=dict)
    tools: list[dict] = field(default_factory=list)
    runtime: dict = field(default_factory=dict)
    human_in_the_loop: dict = field(default_factory=dict)
    audit: dict = field(default_factory=dict)

    # Source info
    file_path: str = ""
    raw_frontmatter: dict = field(default_factory=dict)

    @property
    def declared_tool_names(self) -> set[str]:
        """Return set of declared tool names."""
        return {t.get("name", "") for t in self.tools if t.get("name")}


class ParseError(Exception):
    """Raised when AGENTSECURITY.md cannot be parsed."""


_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?\n)---[ \t]*\n", re.DOTALL)
_YAML_BLOCK_RE = re.compile(r"```ya?ml\s*\n(.*?)```", re.DOTALL)
_SECTION_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)


def find_policy_file(path: str | Path) -> Path:
    """Find AGENTSECURITY.md in the given path.

    Args:
        path: File path or directory. If directory, searches for AGENTSECURITY.md.

    Returns:
        Path to the AGENTSECURITY.md file.

    Raises:
        FileNotFoundError: If no AGENTSECURITY.md is found.
    """
    p = Path(path)
    if p.is_file():
        return p
    if p.is_dir():
        # Search for AGENTSECURITY.md (case-insensitive)
        for name in ["AGENTSECURITY.md", "agentsecurity.md", "AgentSecurity.md"]:
            candidate = p / name
            if candidate.exists():
                return candidate
    raise FileNotFoundError(
        f"No AGENTSECURITY.md found in {path}. "
        "Run 'agentsec init' to create one."
    )


def parse_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter and body from markdown content.

    Returns:
        Tuple of (frontmatter_dict, body_text).

    Raises:
        ParseError: If frontmatter is missing or invalid YAML.
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        raise ParseError(
            "Missing YAML frontmatter. AGENTSECURITY.md must start with "
            "'---' followed by YAML metadata and closing '---'."
        )

    raw_yaml = match.group(1)
    body = content[match.end():]

    try:
        frontmatter = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        raise ParseError(f"Invalid YAML in frontmatter: {e}") from e

    if not isinstance(frontmatter, dict):
        raise ParseError("Frontmatter must be a YAML mapping (key: value pairs).")

    return frontmatter, body


def _extract_sections(body: str) -> dict[str, str]:
    """Split markdown body into sections by ## headings."""
    sections: dict[str, str] = {}
    positions = [(m.start(), m.group(1).strip().lower()) for m in _SECTION_RE.finditer(body)]

    for i, (start, heading) in enumerate(positions):
        end = positions[i + 1][0] if i + 1 < len(positions) else len(body)
        sections[heading] = body[start:end]

    return sections


def _extract_yaml_blocks(text: str) -> list[dict]:
    """Extract and parse all YAML code blocks from a section."""
    blocks = []
    for match in _YAML_BLOCK_RE.finditer(text):
        try:
            parsed = yaml.safe_load(match.group(1))
            if isinstance(parsed, dict):
                blocks.append(parsed)
        except yaml.YAMLError:
            continue
    return blocks


def parse_policy(path: str | Path, seen_paths: set[str] | None = None) -> AgentSecurityPolicy:
    """Parse an AGENTSECURITY.md file into a structured policy object.

    Args:
        path: Path to the AGENTSECURITY.md file or directory containing it.
        seen_paths: Internal set to track recursive calls for cycle detection.

    Returns:
        Parsed AgentSecurityPolicy object.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ParseError: If the file cannot be parsed or has cyclic dependencies.
    """
    if seen_paths is None:
        seen_paths = set()

    file_path = find_policy_file(path)
    abs_path = str(file_path.resolve())

    if abs_path in seen_paths:
        raise ParseError(f"Cyclic dependency detected in policy extension: {abs_path}")
    
    seen_paths.add(abs_path)
    content = file_path.read_text(encoding="utf-8")

    # Strip comment lines from frontmatter area (lines starting with #
    # inside the YAML block are valid YAML comments, so we keep them)
    frontmatter, body = parse_frontmatter(content)

    policy = AgentSecurityPolicy(
        name=str(frontmatter.get("name", "")),
        description=str(frontmatter.get("description", "")),
        security_tier=str(frontmatter.get("security_tier", "")),
        version=str(frontmatter.get("version", "")),
        governance=frontmatter.get("governance", []) or [],
        enforcement=str(frontmatter.get("enforcement", "warn")),
        extends=frontmatter.get("extends", []) or [],
        metadata=frontmatter.get("metadata", {}) or {},
        body=body,
        file_path=str(file_path),
        raw_frontmatter=frontmatter,
    )

    # Handle extensions (recursion)
    if policy.extends:
        base_dir = file_path.parent
        for ext_path in policy.extends:
            full_path = base_dir / ext_path
            if not full_path.exists():
                raise ParseError(f"Extended policy not found: {ext_path}")
            
            base_policy = parse_policy(full_path, seen_paths=seen_paths.copy())
            # Merge base policy into current
            _merge_policies(policy, base_policy)

    # Parse body sections
    sections = _extract_sections(body)

    section_map = {
        "constraints": "constraints_section",
        "tools": "tools_section",
        "runtime": "runtime_section",
        "human-in-the-loop": "hitl_section",
        "audit": "audit_section",
    }

    for heading, attr in section_map.items():
        if heading in sections:
            setattr(policy, attr, sections[heading])

    # Extract YAML blocks from each section
    if policy.constraints_section:
        for block in _extract_yaml_blocks(policy.constraints_section):
            if "constraints" in block:
                policy.constraints = block["constraints"]
            elif "hard_no" in block:
                policy.constraints = block

    if policy.tools_section:
        for block in _extract_yaml_blocks(policy.tools_section):
            if "tools" in block and isinstance(block["tools"], list):
                policy.tools = block["tools"]

    if policy.hitl_section:
        for block in _extract_yaml_blocks(policy.hitl_section):
            if "human_in_the_loop" in block:
                policy.human_in_the_loop = block["human_in_the_loop"]

    if policy.runtime_section:
        for block in _extract_yaml_blocks(policy.runtime_section):
            if "runtime" in block:
                policy.runtime = block["runtime"]

    if policy.audit_section:
        for block in _extract_yaml_blocks(policy.audit_section):
            if "audit" in block:
                policy.audit = block["audit"]

    return policy


def _merge_policies(target: AgentSecurityPolicy, base: AgentSecurityPolicy):
    """Merge base policy into target policy (target takes precedence)."""
    # Merge constraints
    if base.constraints:
        if not target.constraints:
            target.constraints = base.constraints.copy()
        else:
            # Merge lists inside constraints (like hard_no)
            for key, val in base.constraints.items():
                if key not in target.constraints:
                    target.constraints[key] = val
                elif isinstance(val, list) and isinstance(target.constraints[key], list):
                    # Combine lists, avoiding duplicates
                    for item in val:
                        if item not in target.constraints[key]:
                            target.constraints[key].append(item)

    # Merge tools (by name)
    if base.tools:
        target_tool_names = target.declared_tool_names
        for tool in base.tools:
            if tool.get("name") not in target_tool_names:
                target.tools.append(tool)

    # Merge runtime
    if base.runtime:
        for key, val in base.runtime.items():
            if key not in target.runtime:
                target.runtime[key] = val

    # Merge HITL
    if base.human_in_the_loop:
        for key, val in base.human_in_the_loop.items():
            if key not in target.human_in_the_loop:
                target.human_in_the_loop[key] = val

    # Merge Audit
    if base.audit:
        for key, val in base.audit.items():
            if key not in target.audit:
                target.audit[key] = val
