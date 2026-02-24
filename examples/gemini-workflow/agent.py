"""
Gemini Research Workflow — Example companion code for AGENTSECURITY.md

Demonstrates AGENTSECURITY.md integration with Google's Gemini API.
The security policy is model-agnostic — swap the provider and the
same constraints, tool boundaries, and HITL gates apply.
"""

# --- AGENTSECURITY.md enforcement points ---
#
# 1. WEB SEARCH: Only allowed_domains can be fetched
# 2. FILE SYSTEM: Only ./references/ and ./output/ are writable
# 3. HITL: external_report_distribution requires approval
# 4. NETWORK: Only generativelanguage.googleapis.com + allowed domains

MAX_STEPS = 100
ALLOWED_SEARCH_DOMAINS = [
    "docs.python.org",
    "arxiv.org",
    "developers.google.com",
]


def search_web(query: str, domain: str) -> str:
    """Search within allowed domains only.

    AGENTSECURITY.md enforces:
      tools.web_search.scope.allowed_domains
    """
    if domain not in ALLOWED_SEARCH_DOMAINS:
        raise PermissionError(
            f"Domain '{domain}' not in AGENTSECURITY.md "
            "tools.web_search.scope.allowed_domains"
        )
    # In production: call search API
    return f"Results for '{query}' from {domain}"


def write_report(path: str, content: str) -> None:
    """Write a research report to allowed output directory.

    AGENTSECURITY.md enforces:
      tools.file_system.scope.allowed_paths: ["./references/", "./output/"]
    """
    import os
    allowed = ["./references/", "./output/"]
    if not any(os.path.normpath(path).startswith(os.path.normpath(a)) for a in allowed):
        raise PermissionError(
            f"Path '{path}' not in AGENTSECURITY.md "
            "tools.file_system.scope.allowed_paths"
        )
    print(f"[WRITE] {path} ({len(content)} chars)")


def distribute_report(path: str, recipients: list) -> None:
    """Distribute report externally. REQUIRES human approval.

    AGENTSECURITY.md enforces:
      human_in_the_loop.always_require: external_report_distribution
    """
    print(f"[HITL REQUIRED] Distribute {path} to {recipients}")
    # Block until human approves


def main():
    """
    Skeleton showing AGENTSECURITY.md enforcement with Gemini.

    To run with real Gemini API:
      pip install google-generativeai
      export GOOGLE_API_KEY=...

    Same policy works with any model:
      - OpenAI: pip install openai
      - Anthropic: pip install anthropic
      - Mistral: pip install mistralai
      - Local models via Ollama, vLLM, etc.
    """

    # import google.generativeai as genai
    # genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    # model = genai.GenerativeModel("gemini-2.0-flash")

    print("Gemini Research Workflow (skeleton)")
    print(f"Max Steps: {MAX_STEPS}")
    print(f"Allowed Domains: {ALLOWED_SEARCH_DOMAINS}")
    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")


if __name__ == "__main__":
    main()
