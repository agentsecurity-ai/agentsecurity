"""
LangChain Research Agent — Example companion code for AGENTSECURITY.md

Demonstrates how to load the security policy at agent startup and
integrate constraints into the agent's execution flow.

This example is model-agnostic: swap the LLM provider by changing
the model class and API key. The AGENTSECURITY.md policy applies
regardless of which model you use.
"""

import os

# --- Security policy integration ---
# In production, load AGENTSECURITY.md at startup and inject tier context.
# The agentsec CLI can generate the prompt snippet:
#   agentsec to-prompt .
#
# Example output (inject into system prompt):
#   <agent_security_policy>
#     <name>langchain-research-agent</name>
#     <tier>standard</tier>
#     <enforcement>warn</enforcement>
#   </agent_security_policy>

SECURITY_TIER = "standard"
MAX_STEPS = 100
ALLOWED_DOMAINS = [
    "docs.python.org",
    "langchain.readthedocs.io",
    "stackoverflow.com",
    "arxiv.org",
]
DENIED_PATHS = [".env", "secrets/"]


def check_url_allowed(url: str) -> bool:
    """Enforce runtime.network.outbound_allowlist from AGENTSECURITY.md."""
    from urllib.parse import urlparse
    domain = urlparse(url).hostname or ""
    return any(domain.endswith(d) for d in ALLOWED_DOMAINS)


def check_path_allowed(path: str) -> bool:
    """Enforce tools.file_system.scope from AGENTSECURITY.md."""
    return not any(denied in path for denied in DENIED_PATHS)


def main():
    """
    Skeleton showing where AGENTSECURITY.md controls integrate.

    To run with a real LLM, install your preferred provider:
      pip install langchain langchain-openai    # OpenAI
      pip install langchain langchain-anthropic  # Anthropic
      pip install langchain langchain-google     # Google
      pip install langchain langchain-community  # Open source
    """

    # 1. Load security policy
    # from agentsec.parser import parse_policy
    # policy = parse_policy(".")
    # print(f"Agent: {policy.name}, Tier: {policy.security_tier}")

    # 2. Initialize LLM (swap provider here — policy stays the same)
    # from langchain_openai import ChatOpenAI
    # llm = ChatOpenAI(model="gpt-4o")
    #
    # from langchain_anthropic import ChatAnthropic
    # llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
    #
    # from langchain_google_genai import ChatGoogleGenerativeAI
    # llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash")

    # 3. Define tools with AGENTSECURITY.md enforcement
    # Every tool here must be declared in AGENTSECURITY.md
    # Undeclared tools will be flagged by: agentsec check .

    # 4. Run agent with step limit from policy
    # agent.invoke({"input": query}, config={"max_iterations": MAX_STEPS})

    print("LangChain Research Agent (skeleton)")
    print(f"Security Tier: {SECURITY_TIER}")
    print(f"Max Steps: {MAX_STEPS}")
    print(f"Allowed Domains: {ALLOWED_DOMAINS}")
    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")


if __name__ == "__main__":
    main()
