"""Tests for CLI commands: suggest, lock, verify."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentsec.cli import main

POLICY_CONTENT = """\
---
name: test-agent
description: "A test agent for CLI testing"
security_tier: standard
version: "0.1"
enforcement: warn
metadata:
  author: test
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never run eval()"
  max_autonomous_steps: 100
```

## Tools

```yaml
tools:
  - name: file_system
    permission: read_only
    scope:
      allowed_paths: ["./"]
```
"""


def _setup_project(tmpdir: str, extra_files: dict[str, str] | None = None) -> None:
    """Write AGENTSECURITY.md and optional extra files into tmpdir."""
    (Path(tmpdir) / "AGENTSECURITY.md").write_text(POLICY_CONTENT)
    if extra_files:
        for name, content in extra_files.items():
            p = Path(tmpdir) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)


# ─── suggest command ─────────────────────────────────────────────────────


class TestSuggestCommand:
    def test_suggest_text_output(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            result = runner.invoke(main, ["suggest", tmpdir])
            assert result.exit_code == 0
            assert "AgentSecurity Advisor" in result.output
            assert "test-agent" in result.output

    def test_suggest_json_output(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            result = runner.invoke(main, ["suggest", tmpdir, "--format", "json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "frameworks" in data
            assert "recommendations" in data
            assert "enforcement_guides" in data

    def test_suggest_detects_python_framework(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir, {"agent.py": "from langchain_core.prompts import ChatPromptTemplate\n"})
            result = runner.invoke(main, ["suggest", tmpdir, "--format", "json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "LangChain" in data["frameworks"]

    def test_suggest_detects_agent_platform(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir, {"CLAUDE.md": "# Instructions\n"})
            result = runner.invoke(main, ["suggest", tmpdir, "--format", "json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "Claude Code" in data["agent_platforms"]

    def test_suggest_shows_recommendations(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            result = runner.invoke(main, ["suggest", tmpdir])
            assert result.exit_code == 0
            assert "Recommendations" in result.output

    def test_suggest_shows_enforcement_guides(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            result = runner.invoke(main, ["suggest", tmpdir])
            assert result.exit_code == 0
            assert "Enforcement Guides" in result.output

    def test_suggest_no_policy_file(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(main, ["suggest", tmpdir])
            assert result.exit_code == 1


# ─── lock command ────────────────────────────────────────────────────────


class TestLockCommand:
    def test_lock_creates_file(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            result = runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            assert result.exit_code == 0
            assert Path(lock_path).exists()

    def test_lock_file_contains_hash(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            result = runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            assert result.exit_code == 0
            lock_content = Path(lock_path).read_text()
            assert "sha256:" in lock_content
            # SHA-256 hex digest is 64 chars
            lines = [l.strip() for l in lock_content.splitlines() if l.strip().startswith("sha256:")]
            assert len(lines) == 1
            hash_value = lines[0].split(":", 1)[1].strip()
            assert len(hash_value) == 64

    def test_lock_no_policy_file(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            result = runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            assert result.exit_code == 1
            assert "No AGENTSECURITY.md found" in result.output

    def test_lock_output_message(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            result = runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            assert "Lock file written" in result.output
            assert "SHA-256" in result.output


# ─── verify command ──────────────────────────────────────────────────────


class TestVerifyCommand:
    def test_verify_pass(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            # First lock
            runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            # Then verify
            result = runner.invoke(main, ["verify", tmpdir, "--lock", lock_path])
            assert result.exit_code == 0
            assert "PASS" in result.output

    def test_verify_fail_after_tampering(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            # Lock
            runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            # Tamper with policy
            policy_path = Path(tmpdir) / "AGENTSECURITY.md"
            policy_path.write_text(POLICY_CONTENT + "\n# TAMPERED BY AGENT\n")
            # Verify should fail
            result = runner.invoke(main, ["verify", tmpdir, "--lock", lock_path])
            assert result.exit_code == 1
            assert "FAIL" in result.output
            assert "modified" in result.output

    def test_verify_no_policy_file(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a lock file with a fake hash
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            Path(lock_path).write_text("sha256: " + "a" * 64 + "\n")
            result = runner.invoke(main, ["verify", tmpdir, "--lock", lock_path])
            assert result.exit_code == 1
            assert "FAIL" in result.output

    def test_verify_no_hash_in_lock(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            Path(lock_path).write_text("# Empty lock file\n")
            result = runner.invoke(main, ["verify", tmpdir, "--lock", lock_path])
            assert result.exit_code == 1
            assert "No sha256 hash" in result.output


# ─── check command (framework context integration) ───────────────────────


class TestCheckFrameworkContext:
    def test_check_json_includes_framework_context(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir, {"agent.py": "import openai\n"})
            result = runner.invoke(main, ["check", tmpdir, "--format", "json"])
            assert result.exit_code == 0 or result.exit_code == 1  # may fail on findings
            data = json.loads(result.output)
            assert "framework_context" in data
            assert "frameworks" in data["framework_context"]

    def test_check_text_shows_frameworks(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir, {"agent.py": "import openai\nclient = openai.OpenAI()\n"})
            result = runner.invoke(main, ["check", tmpdir])
            assert "Frameworks:" in result.output or "Detected tools:" in result.output

    def test_check_text_shows_recommendations(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            result = runner.invoke(main, ["check", tmpdir])
            assert "Recommendations:" in result.output


# ─── Red Team Security Fixes ─────────────────────────────────────────────


class TestXMLEscapeSecurity:
    """Red team fix: _xml_escape must handle newlines to prevent XML injection."""

    def test_xml_escape_newlines(self):
        from agentsec.cli import _xml_escape
        result = _xml_escape("line1\nline2")
        assert "\n" not in result
        assert "&#10;" in result

    def test_xml_escape_carriage_return(self):
        from agentsec.cli import _xml_escape
        result = _xml_escape("line1\rline2")
        assert "\r" not in result
        assert "&#13;" in result

    def test_xml_escape_special_chars(self):
        from agentsec.cli import _xml_escape
        result = _xml_escape('<script>alert("xss")</script>')
        assert "<" not in result
        assert ">" not in result
        assert "&lt;" in result
        assert "&gt;" in result


class TestPathTraversalProtection:
    """Red team fix: init --output must not write outside CWD."""

    def test_init_rejects_absolute_path_outside_cwd(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(
                main,
                ["init", "--tier", "basic", "--name", "test", "-o", "/tmp/evil/AGENTSECURITY.md"],
            )
            # Should fail unless /tmp/evil is under CWD
            assert result.exit_code == 1 or "Error" in (result.output or "")

    def test_lock_rejects_path_outside_project(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            result = runner.invoke(
                main,
                ["lock", tmpdir, "-o", "/tmp/evil.lock"],
            )
            assert result.exit_code == 1
            assert "Error" in result.output


class TestTimingSafeComparison:
    """Red team fix: verify must use timing-safe comparison."""

    def test_verify_uses_hmac_compare(self):
        """Verify command should use hmac.compare_digest (tested via correct behavior)."""
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            _setup_project(tmpdir)
            lock_path = str(Path(tmpdir) / ".agentsecurity.lock")
            runner.invoke(main, ["lock", tmpdir, "-o", lock_path])
            # Verify should still work correctly with timing-safe comparison
            result = runner.invoke(main, ["verify", tmpdir, "--lock", lock_path])
            assert result.exit_code == 0
            assert "PASS" in result.output
