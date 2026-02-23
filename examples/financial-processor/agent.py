"""
Financial Processor — Example companion code for AGENTSECURITY.md

Demonstrates strict-tier security enforcement for financial agents.
This policy applies regardless of the underlying LLM — the security
boundaries are on the TOOLS, not the model.
"""

# --- AGENTSECURITY.md enforcement: STRICT tier ---
#
# 1. ALL tool calls logged (audit_every_call: true)
# 2. Transaction limit: max_transaction_value: 500
# 3. DB is READ-ONLY with table allowlist
# 4. Denied tables: payment_methods, bank_accounts
# 5. Every write operation requires human approval
# 6. Sandbox REQUIRED (Docker)

MAX_TRANSACTION = 500
ALLOWED_DB_TABLES = ["customers", "invoices", "products"]
DENIED_DB_TABLES = ["payment_methods", "bank_accounts", "internal_notes"]


def create_charge(amount: float, currency: str = "USD") -> dict:
    """Create a Stripe charge. Enforces transaction limit + HITL.

    AGENTSECURITY.md:
      tools.stripe_api.scope.max_transaction_value: 500
      tools.stripe_api.requires_confirmation: true
    """
    if amount > MAX_TRANSACTION:
        raise PermissionError(
            f"Amount ${amount} exceeds AGENTSECURITY.md "
            f"max_transaction_value of ${MAX_TRANSACTION}"
        )
    print(f"[HITL REQUIRED] Charge ${amount} {currency}")
    return {"amount": amount, "status": "pending_approval"}


def query_database(table: str, query: str) -> list:
    """Query customer database. READ-ONLY with table restrictions.

    AGENTSECURITY.md:
      tools.customer_database.permission: read_only
      tools.customer_database.scope.allowed_tables
      tools.customer_database.scope.denied_tables
    """
    if table in DENIED_DB_TABLES:
        raise PermissionError(
            f"Table '{table}' is in AGENTSECURITY.md denied_tables. "
            "Access to payment and banking data is restricted."
        )
    if table not in ALLOWED_DB_TABLES:
        raise PermissionError(
            f"Table '{table}' not in AGENTSECURITY.md allowed_tables"
        )
    print(f"[AUDIT] SELECT from {table}: {query}")
    return [{"id": 1, "data": "example"}]


def main():
    """
    Skeleton showing strict-tier AGENTSECURITY.md enforcement.

    The financial processor works with any LLM:
      - OpenAI GPT-4o/5 for natural language processing
      - Anthropic Claude for structured reasoning
      - Google Gemini for multimodal invoices
      - Open-source models for on-premise deployment

    The security policy is on the TOOLS (Stripe API, database),
    not on the model. Swap models freely; boundaries stay.
    """

    # Allowed: charge under limit
    try:
        result = create_charge(99.99)
        print(f"  Result: {result}")
    except PermissionError as e:
        print(f"  BLOCKED: {e}")

    # Denied: charge over limit
    try:
        result = create_charge(750.00)
        print(f"  Result: {result}")
    except PermissionError as e:
        print(f"  BLOCKED: {e}")

    # Allowed: query customers table
    try:
        rows = query_database("customers", "SELECT * LIMIT 10")
        print(f"  Rows: {rows}")
    except PermissionError as e:
        print(f"  BLOCKED: {e}")

    # Denied: query payment_methods table
    try:
        rows = query_database("payment_methods", "SELECT *")
        print(f"  Rows: {rows}")
    except PermissionError as e:
        print(f"  BLOCKED: {e}")

    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")


if __name__ == "__main__":
    main()
