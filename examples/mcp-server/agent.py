"""
Secure MCP Server — Example companion code for AGENTSECURITY.md

Demonstrates how a Model Context Protocol container limits the
blast radius for exposed tools. The LLM consuming this MCP
will be bound by these policies.
"""

# --- Security policy integration ---
POLICY_TIER = "strict"
ALLOWED_REPOS = ["example-corp/agentsecurity"]
DENIED_PATHS = [".github/workflows/"]

def validate_repo_access(repo: str) -> bool:
    """Enforce tools.github_read.scope from AGENTSECURITY.md."""
    return repo in ALLOWED_REPOS

def validate_file_modify(repo: str, filepath: str) -> bool:
    """Enforce tools.github_write.scope from AGENTSECURITY.md."""
    if repo not in ALLOWED_REPOS:
        return False
    return not any(filepath.startswith(p.strip('/')) for p in DENIED_PATHS)

def main():
    """
    To run this example, use an MCP SDK.
    pip install mcp
    """

    # from mcp.server.fastmcp import FastMCP
    # mcp = FastMCP("github-mcp-server")
    
    # @mcp.tool()
    # def create_pull_request(repo_name: str, branch: str, title: str) -> str:
    #     if not validate_repo_access(repo_name):
    #         return "Access Denied: Repo not allowlisted."
    #     
    #     # Enforcement: HITL Required from AGENTSECURITY.md
    #     # if not request_slack_approval(f"Create PR on {repo_name}?"):
    #     #     return "Approval denied via Slack."
    #     
    #     return "PR created successfully."
    
    # print("Starting MCP Server...")
    # mcp.run()

    print("MCP Server (skeleton)")
    print(f"Policy Tier: {POLICY_TIER}")
    print(f"Allowed Repos: {ALLOWED_REPOS}")
    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")

if __name__ == "__main__":
    main()
