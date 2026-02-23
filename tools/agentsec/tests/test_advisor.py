"""Tests for the advisor module (framework detection, tamper protection, recommendations)."""

import tempfile
from pathlib import Path

import pytest

from agentsec.advisor import (
    FrameworkContext,
    Recommendation,
    compute_policy_hash,
    detect_frameworks,
    generate_enforcement_guides,
    generate_recommendations,
    verify_policy_integrity,
)

POLICY_CONTENT = """\
---
name: test-agent
description: Test agent
security_tier: basic
version: "0.1"
enforcement: warn
---

## Constraints

```yaml
constraints:
  hard_no:
    - "Never run eval()"
```
"""


def _write_policy(tmpdir: str) -> None:
    """Write a minimal AGENTSECURITY.md into tmpdir."""
    (Path(tmpdir) / "AGENTSECURITY.md").write_text(POLICY_CONTENT)


# ─── Framework Detection ────────────────────────────────────────────────


class TestDetectFrameworks:
    def test_detect_langchain_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.py").write_text(
                "from langchain_core.prompts import ChatPromptTemplate\n"
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "LangChain" in ctx.frameworks

    def test_detect_openai_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text(
                "import openai\nclient = openai.OpenAI()\n"
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "OpenAI SDK" in ctx.frameworks

    def test_detect_anthropic_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text(
                "import anthropic\nclient = anthropic.Anthropic()\n"
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "Anthropic SDK" in ctx.frameworks

    def test_detect_crewai(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "crew.py").write_text(
                "from crewai import Agent, Task, Crew\n"
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "CrewAI" in ctx.frameworks

    def test_detect_autogen(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "multi.py").write_text(
                "from autogen import AssistantAgent\n"
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "AutoGen" in ctx.frameworks

    def test_detect_langchain_js(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agent.ts").write_text(
                'import { ChatOpenAI } from "@langchain/openai";\n'
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "LangChain.js" in ctx.frameworks

    def test_detect_vercel_ai_sdk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "route.ts").write_text(
                'import { streamText } from "ai";\n'
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "Vercel AI SDK" in ctx.frameworks

    def test_detect_from_package_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "package.json").write_text(
                '{"dependencies": {"openai": "^4.0.0", "@anthropic-ai/sdk": "^0.10"}}\n'
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "OpenAI SDK" in ctx.frameworks
            assert "Anthropic SDK" in ctx.frameworks

    def test_detect_from_requirements_txt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").write_text(
                "langchain>=0.1.0\nlangchain-openai>=0.0.5\n"
            )
            ctx = detect_frameworks(Path(tmpdir))
            assert "LangChain" in ctx.frameworks

    def test_no_frameworks_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "hello.py").write_text("print('hello')\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert ctx.frameworks == []

    def test_language_detection_python(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text("x = 1\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert ctx.language == "python"

    def test_language_detection_javascript(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.js").write_text("const x = 1;\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert ctx.language == "javascript"

    def test_language_detection_mixed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text("x = 1\n")
            (Path(tmpdir) / "app.js").write_text("const x = 1;\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert ctx.language == "mixed"


# ─── Agent Platform / Config Detection ───────────────────────────────────


class TestPlatformDetection:
    def test_detect_claude_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "CLAUDE.md").write_text("# Project instructions\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert "Claude Code" in ctx.agent_platforms
            assert "CLAUDE.md" in ctx.config_files

    def test_detect_cursor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / ".cursorrules").write_text("some rules\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert "Cursor" in ctx.agent_platforms

    def test_detect_docker(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "Dockerfile").write_text("FROM python:3.11\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert "Docker" in ctx.agent_platforms

    def test_detect_github_copilot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gh_dir = Path(tmpdir) / ".github"
            gh_dir.mkdir()
            (gh_dir / "copilot-instructions.md").write_text("# Copilot rules\n")
            ctx = detect_frameworks(Path(tmpdir))
            assert "GitHub Copilot" in ctx.agent_platforms

    def test_no_platforms_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = detect_frameworks(Path(tmpdir))
            assert ctx.agent_platforms == []


# ─── Tamper Protection ───────────────────────────────────────────────────


class TestTamperProtection:
    def test_compute_policy_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_policy(tmpdir)
            h = compute_policy_hash(Path(tmpdir))
            assert len(h) == 64  # SHA-256 hex digest
            assert h.isalnum()

    def test_hash_stable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_policy(tmpdir)
            h1 = compute_policy_hash(Path(tmpdir))
            h2 = compute_policy_hash(Path(tmpdir))
            assert h1 == h2

    def test_hash_changes_on_modification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "AGENTSECURITY.md"
            policy_path.write_text(POLICY_CONTENT)
            h1 = compute_policy_hash(Path(tmpdir))
            policy_path.write_text(POLICY_CONTENT + "\n# Tampered\n")
            h2 = compute_policy_hash(Path(tmpdir))
            assert h1 != h2

    def test_hash_empty_when_no_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            h = compute_policy_hash(Path(tmpdir))
            assert h == ""

    def test_verify_integrity_pass(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_policy(tmpdir)
            h = compute_policy_hash(Path(tmpdir))
            assert verify_policy_integrity(Path(tmpdir), h) is True

    def test_verify_integrity_fail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_policy(tmpdir)
            assert verify_policy_integrity(Path(tmpdir), "0" * 64) is False

    def test_verify_empty_hash_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_policy(tmpdir)
            assert verify_policy_integrity(Path(tmpdir), "") is False

    def test_case_insensitive_filename(self):
        """Should find agentsecurity.md (lowercase)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "agentsecurity.md").write_text(POLICY_CONTENT)
            h = compute_policy_hash(Path(tmpdir))
            assert len(h) == 64

    def test_integrity_hash_set_in_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_policy(tmpdir)
            ctx = detect_frameworks(Path(tmpdir))
            assert len(ctx.integrity_hash) == 64


# ─── Recommendations Engine ─────────────────────────────────────────────


class TestRecommendations:
    def _base_ctx(self, **kwargs) -> FrameworkContext:
        defaults = {
            "frameworks": [],
            "agent_platforms": [],
            "config_files": [],
            "language": "python",
            "integrity_hash": "a" * 64,
        }
        defaults.update(kwargs)
        return FrameworkContext(**defaults)

    def test_tamper_protection_always_recommended(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="basic", enforcement="warn",
            declared_tools=set(), detected_tools=set(),
            constraints={}, runtime={}, audit={}, hitl={},
        )
        tamper_recs = [r for r in recs if r.category == "tamper"]
        assert len(tamper_recs) >= 1
        assert tamper_recs[0].priority == "critical"

    def test_strict_tier_with_warn_enforcement(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="strict", enforcement="warn",
            declared_tools=set(), detected_tools=set(),
            constraints={"hard_no": ["x"]}, runtime={}, audit={}, hitl={},
        )
        enforcement_recs = [r for r in recs if "enforcement" in r.title.lower() or "upgrade" in r.title.lower()]
        assert any("block" in r.action.lower() for r in recs if r.category == "enforcement")

    def test_missing_constraints_recommendation(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="basic", enforcement="warn",
            declared_tools=set(), detected_tools=set(),
            constraints={}, runtime={}, audit={}, hitl={},
        )
        constraint_recs = [r for r in recs if "constraint" in r.title.lower() or "intent" in r.title.lower()]
        assert len(constraint_recs) >= 1

    def test_sandbox_recommended_for_shell(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="basic", enforcement="warn",
            declared_tools=set(), detected_tools={"subprocess"},
            constraints={"hard_no": ["x"]}, runtime={}, audit={}, hitl={},
        )
        sandbox_recs = [r for r in recs if "sandbox" in r.title.lower()]
        assert len(sandbox_recs) >= 1
        assert sandbox_recs[0].priority == "critical"

    def test_audit_recommended_for_strict(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="strict", enforcement="block",
            declared_tools=set(), detected_tools=set(),
            constraints={"hard_no": ["x"]}, runtime={}, audit={}, hitl={},
        )
        audit_recs = [r for r in recs if "audit" in r.title.lower()]
        assert len(audit_recs) >= 1

    def test_hitl_recommended_for_regulated(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="regulated", enforcement="block",
            declared_tools=set(), detected_tools=set(),
            constraints={"hard_no": ["x"]}, runtime={}, audit={"enabled": True}, hitl={},
        )
        hitl_recs = [r for r in recs if "human" in r.title.lower()]
        assert len(hitl_recs) >= 1

    def test_langchain_framework_recommendations(self):
        ctx = self._base_ctx(frameworks=["LangChain"])
        recs = generate_recommendations(
            ctx=ctx, tier="strict", enforcement="block",
            declared_tools=set(), detected_tools=set(),
            constraints={"hard_no": ["x"]}, runtime={}, audit={"enabled": True}, hitl={"always_require": []},
        )
        lc_recs = [r for r in recs if "LangChain" in r.title]
        assert len(lc_recs) >= 1

    def test_autogen_critical_recommendation(self):
        ctx = self._base_ctx(frameworks=["AutoGen"])
        recs = generate_recommendations(
            ctx=ctx, tier="basic", enforcement="warn",
            declared_tools=set(), detected_tools=set(),
            constraints={"hard_no": ["x"]}, runtime={}, audit={}, hitl={},
        )
        autogen_recs = [r for r in recs if "AutoGen" in r.title]
        assert len(autogen_recs) >= 1
        assert autogen_recs[0].priority == "critical"

    def test_claude_code_platform_recommendation(self):
        ctx = self._base_ctx(agent_platforms=["Claude Code"])
        recs = generate_recommendations(
            ctx=ctx, tier="basic", enforcement="warn",
            declared_tools=set(), detected_tools=set(),
            constraints={"hard_no": ["x"]}, runtime={}, audit={}, hitl={},
        )
        cc_recs = [r for r in recs if "Claude Code" in r.title]
        assert len(cc_recs) >= 1

    def test_hard_no_missing_with_detected_tools(self):
        ctx = self._base_ctx()
        recs = generate_recommendations(
            ctx=ctx, tier="basic", enforcement="warn",
            declared_tools=set(), detected_tools={"http_client", "database"},
            constraints={}, runtime={}, audit={}, hitl={},
        )
        hardno_recs = [r for r in recs if "hard_no" in r.title.lower()]
        assert len(hardno_recs) >= 1


# ─── Enforcement Guides ─────────────────────────────────────────────────


class TestEnforcementGuides:
    def test_universal_guides_always_present(self):
        ctx = FrameworkContext()
        guides = generate_enforcement_guides(ctx, "basic")
        assert any("UNIVERSAL" in g for g in guides)
        assert any("PRE-COMMIT" in g for g in guides)

    def test_framework_specific_guide(self):
        ctx = FrameworkContext(frameworks=["LangChain"])
        guides = generate_enforcement_guides(ctx, "strict")
        assert any("LANGCHAIN" in g for g in guides)

    def test_platform_specific_guide(self):
        ctx = FrameworkContext(agent_platforms=["Claude Code"])
        guides = generate_enforcement_guides(ctx, "basic")
        assert any("CLAUDE CODE" in g for g in guides)

    def test_strict_tier_file_permissions_guide(self):
        ctx = FrameworkContext()
        guides = generate_enforcement_guides(ctx, "strict")
        assert any("FILE PERMISSIONS" in g for g in guides)

    def test_basic_tier_no_file_permissions_guide(self):
        ctx = FrameworkContext()
        guides = generate_enforcement_guides(ctx, "basic")
        assert not any("FILE PERMISSIONS" in g for g in guides)


# ─── Dataclass Serialization ─────────────────────────────────────────────


class TestSerialization:
    def test_recommendation_to_dict(self):
        r = Recommendation(
            category="framework",
            priority="high",
            title="Test",
            description="Test desc",
            action="Do something",
        )
        d = r.to_dict()
        assert d["category"] == "framework"
        assert d["priority"] == "high"
        assert d["title"] == "Test"

    def test_framework_context_to_dict(self):
        ctx = FrameworkContext(
            frameworks=["LangChain"],
            agent_platforms=["Claude Code"],
            config_files=["CLAUDE.md"],
            language="python",
            integrity_hash="abc123",
        )
        d = ctx.to_dict()
        assert d["frameworks"] == ["LangChain"]
        assert d["agent_platforms"] == ["Claude Code"]
        assert d["language"] == "python"
        assert d["integrity_hash"] == "abc123"
        assert isinstance(d["recommendations"], list)
