# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the AgentSecurity specification, CLI tool, or any related component, please report it responsibly.

**Email:** agentsec016@gmail.com

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Acknowledgment: within 48 hours
- Initial assessment: within 7 days
- Fix or mitigation: within 30 days

## Scope

The following are in scope for security reports:
- Bugs in the `agentsec` CLI that could lead to false negatives (missing real vulnerabilities)
- Schema validation bypasses
- Injection vulnerabilities in the parser or scanner
- Issues that could give users a false sense of security

The following are out of scope:
- Theoretical attacks against agents that already have an AGENTSECURITY.md (the spec defines intent, not runtime enforcement)
- Issues in third-party dependencies (report these upstream)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Disclosure Policy

We follow coordinated disclosure. We ask that you:
1. Do not publicly disclose the vulnerability until a fix is available
2. Do not exploit the vulnerability beyond what is necessary for demonstration
3. Provide reasonable time for us to address the issue
