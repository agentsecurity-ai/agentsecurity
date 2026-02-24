"""
Secure RAG Pipeline — Example companion code for AGENTSECURITY.md

Demonstrates how to apply a strict security tier to a RAG pipeline,
typically an environment where indirect prompt injection is a primary threat.
"""

import os

# --- Security policy integration ---
POLICY_TIER = "strict"
ALLOWED_COLLECTIONS = ["internal_docs"]

def validate_collection(collection_name: str) -> bool:
    """Enforce tools.vector_db_search.scope from AGENTSECURITY.md."""
    return collection_name in ALLOWED_COLLECTIONS

def sanitize_retrieved_documents(docs: list) -> list:
    """
    Defense-in-depth against prompt injection from retrieved docs.
    Strips control characters or known injection trigger phrases.
    """
    safe_docs = []
    for doc in docs:
        if "<|im_start|>" not in doc and "[SYSTEM]" not in doc:
            safe_docs.append(doc)
    return safe_docs

def main():
    """
    To run this example, install your preferred RAG framework.
    pip install llama-index llama-index-vector-stores-pinecone
    """
    
    collection_to_query = "internal_docs"
    if not validate_collection(collection_to_query):
        print("Blocked: Attempted to query unauthorized vector collection.")
        return

    # from llama_index.core import VectorStoreIndex
    # Retriever retrieves nodes. We should sanitize before feeding to LLM.
    # retrieved_nodes = index.as_retriever().retrieve("User query")
    # safe_text = sanitize_retrieved_documents([n.text for n in retrieved_nodes])
    # ... generate response using safe_text
    
    print("Secure RAG Pipeline (skeleton)")
    print(f"Policy Tier: {POLICY_TIER}")
    print(f"Allowed Vector Collections: {ALLOWED_COLLECTIONS}")
    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")

if __name__ == "__main__":
    main()
