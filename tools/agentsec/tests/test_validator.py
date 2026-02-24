"""Tests for the AGENTSECURITY.md validator."""

from pathlib import Path

import pytest

from agentsec.parser import parse_policy
from agentsec.validator import validate_policy

FIXTURES = Path(__file__).parent / "fixtures"


class TestValidateBasicTier:
    def test_valid_basic_passes(self):
        policy = parse_policy(FIXTURES / "valid_basic.md")
        result = validate_policy(policy)
        # Basic tier should have few or no findings
        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 0

    def test_basic_score_is_high(self):
        policy = parse_policy(FIXTURES / "valid_basic.md")
        result = validate_policy(policy)
        assert result.score >= 80


class TestValidateStrictTier:
    def test_valid_strict_passes(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        result = validate_policy(policy)
        high_findings = [f for f in result.findings if f.severity == "high"]
        assert len(high_findings) == 0

    def test_strict_has_all_controls(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        result = validate_policy(policy)
        assert result.controls.get("OWASP-LLM07") is True
        assert result.controls.get("OWASP-LLM08") is True


class TestValidateInvalidFile:
    def test_invalid_triggers_findings(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        assert len(result.findings) > 0

    def test_invalid_name_detected(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        name_findings = [f for f in result.findings if f.rule_id == "ASEC-002"]
        assert len(name_findings) > 0

    def test_invalid_tier_detected(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        tier_findings = [f for f in result.findings if f.rule_id == "ASEC-003"]
        assert len(tier_findings) > 0

    def test_invalid_version_detected(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        version_findings = [f for f in result.findings if f.rule_id == "ASEC-004"]
        assert len(version_findings) > 0

    def test_invalid_enforcement_detected(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        enforce_findings = [f for f in result.findings if f.rule_id == "ASEC-005"]
        assert len(enforce_findings) > 0

    def test_empty_description_detected(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        desc_findings = [f for f in result.findings if f.rule_id == "ASEC-001"]
        assert any("description" in f.message for f in desc_findings)

    def test_invalid_score_is_low(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        assert result.score < 50

    def test_invalid_does_not_pass(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        assert result.passed is False


class TestValidationResult:
    def test_to_dict(self):
        policy = parse_policy(FIXTURES / "valid_basic.md")
        result = validate_policy(policy)
        d = result.to_dict()
        assert "agent" in d
        assert "tier" in d
        assert "score" in d
        assert "findings" in d
        assert "summary" in d
        assert "controls" in d

    def test_finding_to_dict(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        result = validate_policy(policy)
        assert len(result.findings) > 0
        f = result.findings[0].to_dict()
        assert "rule_id" in f
        assert "severity" in f
        assert "message" in f


class TestTierSpecificRules:
    def test_strict_requires_sandbox(self):
        """Strict tier without sandbox should flag."""
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        # Force tier to strict for testing
        policy.security_tier = "strict"
        policy.name = "test-agent"
        policy.description = "A valid test description"
        policy.version = "0.1"
        policy.enforcement = "block"
        result = validate_policy(policy)
        sandbox_findings = [f for f in result.findings if f.rule_id == "ASEC-013"]
        assert len(sandbox_findings) > 0

    def test_standard_requires_tools(self):
        """Standard tier without tool declarations should flag."""
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        policy.security_tier = "standard"
        policy.name = "test-agent"
        policy.description = "A valid test description"
        policy.version = "0.1"
        policy.enforcement = "warn"
        policy.tools = []
        result = validate_policy(policy)
        tool_findings = [f for f in result.findings if f.rule_id == "ASEC-010"]
        assert len(tool_findings) > 0

    def test_regulated_requires_audit(self):
        """Regulated tier without audit should flag."""
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        policy.security_tier = "regulated"
        policy.name = "test-agent"
        policy.description = "A valid test description"
        policy.version = "0.1"
        policy.enforcement = "block_and_audit"
        policy.audit = {}
        result = validate_policy(policy)
        audit_findings = [f for f in result.findings if f.rule_id == "ASEC-014"]
        assert len(audit_findings) > 0


class TestOverprivilegedTools:
    def test_admin_permission_flagged(self):
        policy = parse_policy(FIXTURES / "valid_basic.md")
        policy.tools = [{"name": "db", "permission": "admin"}]
        result = validate_policy(policy)
        overprivilege = [f for f in result.findings if f.rule_id == "ASEC-011"]
        assert len(overprivilege) > 0

    def test_wildcard_scope_flagged(self):
        policy = parse_policy(FIXTURES / "valid_basic.md")
        policy.tools = [{"name": "fs", "permission": "read_write", "scope": "*"}]
        result = validate_policy(policy)
        overprivilege = [f for f in result.findings if f.rule_id == "ASEC-011"]
        assert len(overprivilege) > 0
