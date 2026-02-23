"""
Healthcare Regulated Agent — Example companion code for AGENTSECURITY.md

Demonstrates a fully regulated environment with dual-approval
HITL logic, PII scrubbing, and strict endpoint masking.
"""

import os
import hashlib

# --- Security policy integration ---
POLICY_TIER = "regulated"
ALLOWED_ENDPOINTS = ["https://api.internal.hospital.local/fhir/"]
HIPAA_COMPLIANT = True

def validate_external_call(url: str) -> bool:
    """Enforce tools.ehr_read.scope from AGENTSECURITY.md."""
    return any(url.startswith(ep) for ep in ALLOWED_ENDPOINTS)

def scrub_phi(text: str) -> str:
    """
    Enforces constraints.data_handling.pii_anonymization
    In production, use Microsoft Presidio or Comprehend Medical.
    """
    # Dummy mock of a scrubber
    return text.replace("John Doe", "[REDACTED_PATIENT]")

def audit_log(action: str, status: str, dual_approval_acquired: bool):
    """Enforce audit properties."""
    print(f"AUDIT LOG (tamper-evident): [{action}] -> {status}")
    if not dual_approval_acquired:
        print("  ALERT: Dual Approval missing.")

def main():
    """
    This is an abstract framework. Do not run with real PHI!
    """

    endpoint = "https://api.internal.hospital.local/fhir/Patient/123"
    if not validate_external_call(endpoint):
        print("Blocked: Non-compliant API Call.")
        return

    # 1. Retrieve data
    raw_data = "Patient John Doe shows symptoms..."
    
    # 2. Scrub PHI BEFORE calling external LLM
    safe_data = scrub_phi(raw_data)

    # 3. Request logic and dual approval HITL
    action = "ehr_write"
    dual_approval_acquired = False
    
    # if require_justification and two_signatures_received:
    #     dual_approval_acquired = True
    
    if action == "ehr_write" and not dual_approval_acquired:
        audit_log("ehr_write", "DENIED", False)
        print("Blocked: Write operation requires dual approval.")
        return

    print("Healthcare Regulated Agent (skeleton)")
    print(f"Policy Tier: {POLICY_TIER}")
    print(f"HIPAA Alignment: {HIPAA_COMPLIANT}")
    print("\nTo validate: agentsec validate .")
    print("To scan:     agentsec check .")

if __name__ == "__main__":
    main()
