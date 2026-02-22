"""Scan agent codebase for security violations against declared policy."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .parser import AgentSecurityPolicy
from .validator import Finding


# Dangerous patterns to detect in any file
DANGEROUS_PATTERNS = [
    (r"\beval\s*\(", "eval() usage detected", "OWASP-LLM02"),
    (r"\bexec\s*\(", "exec() usage detected", "OWASP-LLM02"),
    (r"curl\s+.*\|\s*(ba)?sh", "curl-pipe-to-shell detected", "OWASP-LLM02"),
    (r"wget\s+.*\|\s*(ba)?sh", "wget-pipe-to-shell detected", "OWASP-LLM02"),
    (r"\b__import__\s*\(", "Dynamic __import__() detected", "OWASP-LLM02"),
    (r"subprocess\.call\s*\(\s*['\"]", "subprocess.call with string command", "OWASP-LLM02"),
    (r"os\.system\s*\(", "os.system() usage detected", "OWASP-LLM02"),
    (r"os\.popen\s*\(", "os.popen() usage detected", "OWASP-LLM02"),
]

# Secret patterns to detect
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9]{16,}", "Possible API key"),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}", "Possible hardcoded secret"),
    (r"(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['\"]AKIA", "AWS Access Key ID"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][a-zA-Z0-9/+=]{40}", "AWS Secret Key"),
    (r"sk-proj-[a-zA-Z0-9_-]{20,}", "Possible OpenAI project API key"),
    (r"sk-ant-(?:api03-)?[a-zA-Z0-9_-]{20,}", "Possible Anthropic API key"),
    (r"sk-[a-zA-Z0-9]{20,}", "Possible OpenAI/Anthropic API key"),
    (r"AIza[0-9A-Za-z_-]{35}", "Possible Google API key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private key in source"),
]

# Python imports that indicate tool usage
PYTHON_TOOL_IMPORTS = {
    "subprocess": "subprocess",
    "os": "os",
    "requests": "http_client",
    "httpx": "http_client",
    "urllib": "http_client",
    "aiohttp": "http_client",
    "boto3": "aws_sdk",
    "stripe": "stripe_api",
    "openai": "openai_api",
    "anthropic": "anthropic_api",
    "google.generativeai": "gemini_api",
    "google.genai": "gemini_api",
    "vertexai": "gemini_api",
    "google.cloud.aiplatform": "gemini_api",
    "litellm": "llm_gateway",
    "sqlalchemy": "database",
    "psycopg2": "database",
    "pymongo": "database",
    "redis": "redis",
    "smtplib": "email_service",
    "paramiko": "ssh_client",
    "fabric": "ssh_client",
    "docker": "docker",
    "kubernetes": "kubernetes",
}

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash",
    ".yaml", ".yml", ".json", ".toml",
}

# Files and directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", "dist", "build", ".next",
    ".mypy_cache", ".ruff_cache", "egg-info",
}

SKIP_FILES = {
    "AGENTSECURITY.md", "agentsecurity.md",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
}

IGNORE_COMMENT_RE = re.compile(r"#\s*agentsec-ignore:\s*(\S+)")


@dataclass
class ScanResult:
    """Result of scanning a codebase."""

    findings: list[Finding]
    files_scanned: int
    detected_tools: set[str]


def scan_codebase(
    path: str | Path,
    policy: AgentSecurityPolicy,
) -> ScanResult:
    """Scan a codebase for security violations against a policy.

    Args:
        path: Root directory to scan.
        policy: The declared AGENTSECURITY.md policy.

    Returns:
        ScanResult with findings and metadata.
    """
    root = Path(path)
    if root.is_file():
        root = root.parent

    findings: list[Finding] = []
    files_scanned = 0
    detected_tools: set[str] = set()

    for file_path in _iter_files(root):
        files_scanned += 1
        content = _read_file_safe(file_path)
        if content is None:
            continue

        rel_path = str(file_path.relative_to(root))
        ignored_rules = _get_ignored_rules(content)

        # Check for dangerous patterns
        for pattern, desc, control in DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                rule_id = "ASEC-020"
                if rule_id not in ignored_rules:
                    findings.append(Finding(
                        rule_id=rule_id,
                        severity="high",
                        message=f"{desc}: {rel_path}:{line_num}",
                        file=rel_path,
                        line=line_num,
                        control=control,
                    ))

        # Check for hardcoded secrets
        for pattern, desc in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                rule_id = "ASEC-021"
                if rule_id not in ignored_rules:
                    findings.append(Finding(
                        rule_id=rule_id,
                        severity="high",
                        message=f"{desc} in {rel_path}:{line_num}",
                        file=rel_path,
                        line=line_num,
                        control="OWASP-LLM06",
                    ))

        # Detect tool usage in Python files
        if file_path.suffix == ".py":
            tools = _detect_python_tools(content)
            detected_tools.update(tools)

    # Check for undeclared tool usage
    declared = policy.declared_tool_names
    for tool in detected_tools:
        # Fuzzy match: check if any declared tool name contains the detected tool name
        if not _tool_is_declared(tool, declared):
            rule_id = "ASEC-022"
            findings.append(Finding(
                rule_id=rule_id,
                severity="high" if policy.security_tier in {"strict", "regulated"} else "medium",
                message=f"Undeclared tool usage: '{tool}' found in code but not in AGENTSECURITY.md Tools section.",
                file="(codebase)",
                control="OWASP-LLM07",
            ))

    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        detected_tools=detected_tools,
    )


def _iter_files(root: Path):
    """Iterate over scannable files in a directory tree."""
    if not root.is_dir():
        return
    for item in root.rglob("*"):
        if item.is_dir():
            continue
        if any(skip in item.parts for skip in SKIP_DIRS):
            continue
        if item.name in SKIP_FILES:
            continue
        if item.suffix in SCANNABLE_EXTENSIONS:
            yield item


def _read_file_safe(path: Path) -> str | None:
    """Read a file, returning None if it can't be read."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return None


def _get_ignored_rules(content: str) -> set[str]:
    """Extract agentsec-ignore rule IDs from file content."""
    ignored = set()
    for match in IGNORE_COMMENT_RE.finditer(content):
        ignored.add(match.group(1))
    return ignored


def _detect_python_tools(content: str) -> set[str]:
    """Detect tool usage from Python imports using AST."""
    tools = set()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        # Fall back to regex for non-parseable files
        return _detect_python_tools_regex(content)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                tool_name = _module_to_tool(alias.name)
                if tool_name:
                    tools.add(tool_name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                tool_name = _module_to_tool(node.module)
                if tool_name:
                    tools.add(tool_name)

    return tools


def _detect_python_tools_regex(content: str) -> set[str]:
    """Fallback: detect Python imports via regex."""
    tools = set()
    for module, tool_name in PYTHON_TOOL_IMPORTS.items():
        if re.search(rf"(?:^|\n)\s*(?:from\s+{module}|import\s+{module})\b", content):
            tools.add(tool_name)
    return tools


def _module_to_tool(module_name: str) -> str | None:
    """Map a Python import path to a known tool category."""
    if module_name in PYTHON_TOOL_IMPORTS:
        return PYTHON_TOOL_IMPORTS[module_name]

    # Match parent namespace keys for nested imports.
    parts = module_name.split(".")
    while len(parts) > 1:
        parts.pop()
        candidate = ".".join(parts)
        if candidate in PYTHON_TOOL_IMPORTS:
            return PYTHON_TOOL_IMPORTS[candidate]

    return PYTHON_TOOL_IMPORTS.get(parts[0])


def _tool_is_declared(detected: str, declared: set[str]) -> bool:
    """Check if a detected tool matches any declared tool name (fuzzy)."""
    detected_lower = detected.lower().replace("_", "").replace("-", "")
    for d in declared:
        d_lower = d.lower().replace("_", "").replace("-", "")
        if detected_lower in d_lower or d_lower in detected_lower:
            return True
        # Also check common aliases
        if detected_lower == "httpclient" and any(
            x in d_lower for x in ["web", "http", "api", "request", "fetch"]
        ):
            return True
        if detected_lower in {"openaiapi", "anthropicapi", "geminiapi", "llmgateway"} and any(
            x in d_lower for x in [
                "llm", "model", "openai", "anthropic", "gemini", "vertex", "genai", "provider",
            ]
        ):
            return True
    return False
