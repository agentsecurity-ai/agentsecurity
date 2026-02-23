"""Scan agent codebase for security violations against declared policy."""

from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from .advisor import FrameworkContext, detect_frameworks, generate_enforcement_guides, generate_recommendations
from .parser import AgentSecurityPolicy
from .validator import Finding


# Dangerous patterns to detect in any file
DANGEROUS_PATTERNS = [
    (r"\beval\s*\(", "eval() usage detected", "OWASP-LLM02"),
    (r"(?<!\.)\bexec\s*\(", "exec() usage detected", "OWASP-LLM02"),
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

# JavaScript/TypeScript imports that indicate tool usage
JS_TOOL_IMPORTS = {
    "child_process": "shell_execution",
    "fs": "file_system",
    "path": "file_system",
    "fs-extra": "file_system",
    "axios": "http_client",
    "node-fetch": "http_client",
    "got": "http_client",
    "undici": "http_client",
    "pg": "database",
    "mysql2": "database",
    "mongoose": "database",
    "sequelize": "database",
    "@prisma/client": "database",
    "prisma": "database",
    "drizzle-orm": "database",
    "ioredis": "redis",
    "redis": "redis",
    "nodemailer": "email_service",
    "openai": "openai_api",
    "@anthropic-ai/sdk": "anthropic_api",
    "@google/generative-ai": "gemini_api",
    "ssh2": "ssh_client",
    "dockerode": "docker",
    "@kubernetes/client-node": "kubernetes",
    "@aws-sdk/client-s3": "aws_sdk",
    "aws-sdk": "aws_sdk",
    "stripe": "stripe_api",
    "@sendgrid/mail": "email_service",
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

_TEST_FILE_RE = re.compile(
    r"(?:\.|/|^)(test|spec|tests|__tests__|__mocks__|fixtures|mocks|test-utils)"
    r"(?:\.|/)",
    re.IGNORECASE,
)


def _is_test_file(rel_path: str) -> bool:
    """Check if a file path indicates a test context."""
    return bool(_TEST_FILE_RE.search(rel_path))


@dataclass
class ScanResult:
    """Result of scanning a codebase."""

    findings: list[Finding]
    files_scanned: int
    detected_tools: set[str]
    framework_context: FrameworkContext | None = None


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
    ignore_patterns = _load_ignore_patterns(root)

    for file_path in _iter_files(root, ignore_patterns):
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
        is_test = _is_test_file(rel_path)
        for pattern, desc in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                rule_id = "ASEC-021"
                if rule_id not in ignored_rules:
                    if is_test:
                        severity = "info"
                        msg = f"{desc} in {rel_path}:{line_num} (test file — likely mock data)"
                    else:
                        severity = "high"
                        msg = f"{desc} in {rel_path}:{line_num}"
                    findings.append(Finding(
                        rule_id=rule_id,
                        severity=severity,
                        message=msg,
                        file=rel_path,
                        line=line_num,
                        control="OWASP-LLM06",
                    ))

        # Detect tool usage in Python files
        if file_path.suffix == ".py":
            tools = _detect_python_tools(content)
            detected_tools.update(tools)

        # Detect tool usage in JS/TS files
        if file_path.suffix in {".js", ".ts", ".jsx", ".tsx"}:
            tools = _detect_js_tools(content)
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

    # Detect frameworks and generate recommendations
    ctx = detect_frameworks(root)
    ctx.recommendations = generate_recommendations(
        ctx=ctx,
        tier=policy.security_tier,
        enforcement=policy.enforcement,
        declared_tools=declared,
        detected_tools=detected_tools,
        constraints=policy.constraints,
        runtime=policy.runtime,
        audit=policy.audit,
        hitl=policy.human_in_the_loop,
    )
    ctx.enforcement_guides = generate_enforcement_guides(ctx, policy.security_tier)

    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        detected_tools=detected_tools,
        framework_context=ctx,
    )


def _iter_files(root: Path, ignore_patterns: list[str] | None = None):
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
        if ignore_patterns:
            rel = str(item.relative_to(root))
            if any(
                fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(item.name, pat)
                for pat in ignore_patterns
            ):
                continue
        if item.suffix in SCANNABLE_EXTENSIONS:
            yield item


def _read_file_safe(path: Path) -> str | None:
    """Read a file, returning None if it can't be read."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        return None


def _load_ignore_patterns(root: Path) -> list[str]:
    """Load ignore patterns from .agentsecignore file."""
    ignore_file = root / ".agentsecignore"
    if not ignore_file.is_file():
        return []
    patterns: list[str] = []
    try:
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                patterns.append(stripped)
    except (PermissionError, OSError):
        return []
    return patterns


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


def _detect_js_tools(content: str) -> set[str]:
    """Detect tool usage from JS/TS import/require statements."""
    tools = set()
    for module, tool_name in JS_TOOL_IMPORTS.items():
        escaped = re.escape(module)
        pattern = (
            rf"""(?:from\s+['"]{escaped}['"]"""
            rf"""|require\s*\(\s*['"]{escaped}['"]\s*\))"""
        )
        if re.search(pattern, content):
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
