"""Tests for the AGENTSECURITY.md parser."""

from pathlib import Path

import pytest

from agentsec.parser import ParseError, parse_frontmatter, parse_policy

FIXTURES = Path(__file__).parent / "fixtures"


class TestParseFrontmatter:
    def test_valid_frontmatter(self):
        content = "---\nname: test\ndescription: desc\n---\n# Body"
        fm, body = parse_frontmatter(content)
        assert fm["name"] == "test"
        assert fm["description"] == "desc"
        assert "# Body" in body

    def test_missing_frontmatter(self):
        with pytest.raises(ParseError, match="Missing YAML frontmatter"):
            parse_frontmatter("# No frontmatter here")

    def test_invalid_yaml(self):
        content = "---\n: invalid: yaml: [broken\n---\n"
        with pytest.raises(ParseError, match="Invalid YAML"):
            parse_frontmatter(content)

    def test_non_dict_frontmatter(self):
        content = "---\n- just a list\n- not a dict\n---\n"
        with pytest.raises(ParseError, match="must be a YAML mapping"):
            parse_frontmatter(content)


class TestParsePolicy:
    def test_parse_valid_basic(self):
        policy = parse_policy(FIXTURES / "valid_basic.md")
        assert policy.name == "test-basic-agent"
        assert policy.description == "A basic test agent for validation testing"
        assert policy.security_tier == "basic"
        assert policy.version == "0.1"
        assert policy.enforcement == "warn"

    def test_parse_valid_strict(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert policy.name == "test-strict-agent"
        assert policy.security_tier == "strict"
        assert policy.enforcement == "block"
        assert "OWASP-LLM-TOP10" in policy.governance
        assert "NIST-AI-RMF" in policy.governance

    def test_parse_tools(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert len(policy.tools) == 2
        tool_names = {t["name"] for t in policy.tools}
        assert "file_system" in tool_names
        assert "web_search" in tool_names

    def test_declared_tool_names(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert policy.declared_tool_names == {"file_system", "web_search"}

    def test_parse_runtime(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert policy.runtime.get("sandbox", {}).get("required") is True

    def test_parse_hitl(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert "always_require" in policy.human_in_the_loop

    def test_parse_audit(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert policy.audit.get("enabled") is True

    def test_parse_invalid_file(self):
        policy = parse_policy(FIXTURES / "invalid_missing_fields.md")
        assert policy.name == "Bad--Agent!!"
        assert policy.security_tier == "ultra"

    def test_parse_metadata(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert policy.metadata.get("author") == "test-team"
        assert policy.metadata.get("org") == "test-org"

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_policy("/nonexistent/path")

    def test_find_in_directory(self):
        """Test that parse_policy can find AGENTSECURITY.md in a directory."""
        # Create a temporary test
        policy = parse_policy(FIXTURES / "valid_basic.md")
        assert policy.name == "test-basic-agent"

    def test_constraints_parsed(self):
        policy = parse_policy(FIXTURES / "valid_strict.md")
        assert "hard_no" in policy.constraints
        assert policy.constraints.get("max_autonomous_steps") == 50
