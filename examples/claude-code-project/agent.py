"""
Claude Code Project — Example companion code for AGENTSECURITY.md

Demonstrates how AGENTSECURITY.md integrates with any coding agent
(Claude Code, GitHub Copilot, Cursor, Codex, Gemini Code Assist, etc.).

The security policy is tool-specific, not model-specific. The same
file_system and bash tool constraints apply regardless of which LLM
powers the coding agent.
"""

# --- AGENTSECURITY.md enforcement points ---
#
# 1. BASH: allowed_commands whitelist, denied_commands blocklist
# 2. FILE SYSTEM: denied_paths protects .env, secrets/, ~/.ssh/
# 3. GIT PUSH: requires_confirmation: true (always needs human approval)
# 4. NO SUDO: denied_commands includes "sudo *"
# 5. NO CURL|BASH: denied_commands includes "curl * | bash"

ALLOWED_COMMANDS = [
    "npm *", "pnpm *", "yarn *", "python *", "pytest *",
    "git status", "git diff *", "git add *", "git commit *",
    "git log *", "ls *", "mkdir *",
]

DENIED_COMMANDS = [
    "rm -rf /", "sudo *", "curl * | bash", "wget * | sh",
    "git push *", "git config --global *",
]

DENIED_PATHS = [".env", ".env.local", "secrets/", "~/.ssh/"]


def execute_command(cmd: str) -> str:
    """Execute a shell command with AGENTSECURITY.md enforcement.

    This function demonstrates how a coding agent should validate
    commands against the declared policy BEFORE execution.
    """
    # Check denied commands first
    for pattern in DENIED_COMMANDS:
        # Simple glob matching (production: use fnmatch)
        if pattern.endswith(" *"):
            prefix = pattern[:-2]
            if cmd.startswith(prefix):
                raise PermissionError(
                    f"Command '{cmd}' matches denied pattern '{pattern}' "
                    "in AGENTSECURITY.md tools.bash.scope.denied_commands"
                )
        elif cmd == pattern:
            raise PermissionError(
                f"Command '{cmd}' is explicitly denied in AGENTSECURITY.md"
            )

    # Check if command matches any allowed pattern
    allowed = False
    for pattern in ALLOWED_COMMANDS:
        if pattern.endswith(" *"):
            prefix = pattern[:-2]
            if cmd.startswith(prefix):
                allowed = True
                break
        elif cmd == pattern:
            allowed = True
            break

    if not allowed:
        raise PermissionError(
            f"Command '{cmd}' not in AGENTSECURITY.md "
            "tools.bash.scope.allowed_commands"
        )

    print(f"[EXEC] {cmd}")
    return f"(simulated output of: {cmd})"


def git_push(remote: str = "origin", branch: str = "feature") -> None:
    """Push to remote. ALWAYS requires human approval.

    AGENTSECURITY.md enforces:
      tools.git_push.requires_confirmation: true
      tools.git_push.scope.denied_branches: ["main", "master"]
    """
    if branch in ["main", "master"]:
        raise PermissionError(
            f"Push to '{branch}' denied by AGENTSECURITY.md "
            "tools.git_push.scope.denied_branches"
        )
    print(f"[HITL REQUIRED] git push {remote} {branch}")


def main():
    """
    Skeleton showing AGENTSECURITY.md enforcement for coding agents.

    This pattern works with ANY coding agent:
      - Claude Code (Anthropic)
      - GitHub Copilot Workspace (Microsoft/OpenAI)
      - Cursor (custom)
      - Codex CLI (OpenAI)
      - Gemini Code Assist (Google)
      - Aider, Continue, Cody, etc.

    The AGENTSECURITY.md policy defines what tools the agent can use
    and what commands are allowed/denied. The model powering the agent
    is irrelevant to the security boundary.
    """

    # Example: allowed command
    try:
        execute_command("pytest tests/ -v")
    except PermissionError as e:
        print(f"BLOCKED: {e}")

    # Example: denied command
    try:
        execute_command("sudo rm -rf /")
    except PermissionError as e:
        print(f"BLOCKED: {e}")

    # Example: git push requires approval
    try:
        git_push("origin", "feature/new-stuff")
    except PermissionError as e:
        print(f"BLOCKED: {e}")

    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")


if __name__ == "__main__":
    main()
