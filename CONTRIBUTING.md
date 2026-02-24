# Contributing to AgentSecurity

Thank you for your interest in contributing to the AgentSecurity open standard.

## Ways to Contribute

### Spec Improvements
- Open an **RFC issue** before submitting changes to the specification
- Discuss the rationale and expected impact
- PRs to `spec/AGENTSECURITY.md` or `spec/agentsecurity.schema.json` require RFC approval

### New Validation Rules
- Add rules to `tools/agentsec/src/agentsec/rules/` (or extend `validator.py`/`scanner.py`)
- Every rule must have:
  - A unique ID (`ASEC-XXX`)
  - A severity level (high, medium, low)
  - A mapped compliance control
  - Unit tests in `tools/agentsec/tests/`

### Framework Examples
- Add examples to `examples/` with a working AGENTSECURITY.md
- Include a README explaining the agent and how the policy applies

### Compliance Mappings
- Add or update mappings in `tools/agentsec/src/agentsec/mappings/`
- Mappings should reference specific control IDs from the framework

### Documentation
- Improve `site/` pages for clarity
- Fix typos, broken links, or unclear wording

### Bug Reports
- Open an issue with:
  - What you expected
  - What happened
  - Steps to reproduce
  - Your AGENTSECURITY.md file (sanitized)

## Development Setup

```bash
# Clone the repo
git clone https://github.com/agentsecurity/agentsecurity.git
cd agentsecurity

# Install the CLI in development mode
pip install -e "./tools/agentsec[dev]"

# Run tests
pytest tools/agentsec/tests/ -v

# Validate all templates
for dir in templates/*/; do agentsec validate "$dir/AGENTSECURITY.md"; done
```

## Code Style

- Python: follow PEP 8, use type hints, `from __future__ import annotations`
- Tests: use pytest, one test class per feature area
- Commit messages: concise, imperative mood ("Add rule ASEC-025" not "Added...")

## Pull Request Process

1. Fork the repo and create a feature branch
2. Add tests for new functionality
3. Ensure all tests pass: `pytest tools/agentsec/tests/ -v`
4. Ensure templates validate: `agentsec validate templates/standard/AGENTSECURITY.md`
5. Open a PR with a clear description of the change

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be respectful and constructive.

## License

By contributing, you agree that your contributions will be licensed under:
- **Specification:** CC-BY-4.0
- **Tooling:** Apache-2.0
