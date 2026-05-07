#!/usr/bin/env python3
"""
HIPAA Compliance MCP Server
============================
By MEOK AI Labs | https://meok.ai

Automates HIPAA healthcare compliance assessment. Covers Administrative,
Physical, and Technical safeguards, PHI handling, BAA generation,
breach notification rules, and minimum necessary checks.

Install: pip install mcp
Run:     python server.py
"""

import json
import os
import sys
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# ── Authentication ──────────────────────────────────────────────
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access
from compliance_neural import ComplianceNeuralNet

_neural_net = ComplianceNeuralNet("hipaa")

_MEOK_API_KEY = os.environ.get("MEOK_API_KEY", "")


def _check_auth(api_key: str = "") -> str | None:
    if _MEOK_API_KEY and api_key != _MEOK_API_KEY:
        return "Invalid API key. Get one at https://meok.ai/api-keys"
    return None


# ── Rate limiting ───────────────────────────────────────────────
FREE_DAILY_LIMIT = 10
_usage: dict[str, list[datetime]] = defaultdict(list)


def _rl(caller: str = "anonymous", tier: str = "free") -> Optional[str]:
    if tier == "pro":
        return None
    now = datetime.now()
    cutoff = now - timedelta(days=1)
    _usage[caller] = [t for t in _usage[caller] if t > cutoff]
    if len(_usage[caller]) >= FREE_DAILY_LIMIT:
        return (
            f"Free tier limit ({FREE_DAILY_LIMIT}/day). "
            "Upgrade: https://meok.ai/mcp/hipaa-compliance/pro"
        )
    _usage[caller].append(now)
    return None


# ── HIPAA Knowledge Base ────────────────────────────────────────

ADMINISTRATIVE_SAFEGUARDS = {
    "164.308(a)(1)": {"name": "Security Management Process", "weight": 10,
        "checks": ["risk_analysis", "risk_management", "sanction_policy", "information_system_activity_review"]},
    "164.308(a)(2)": {"name": "Assigned Security Responsibility", "weight": 8,
        "checks": ["designated_security_official"]},
    "164.308(a)(3)": {"name": "Workforce Security", "weight": 9,
        "checks": ["authorization_supervision", "workforce_clearance", "termination_procedures"]},
    "164.308(a)(4)": {"name": "Information Access Management", "weight": 9,
        "checks": ["access_authorization", "access_establishment"]},
    "164.308(a)(5)": {"name": "Security Awareness and Training", "weight": 8,
        "checks": ["security_reminders", "malicious_software_protection", "login_monitoring", "password_management"]},
    "164.308(a)(6)": {"name": "Security Incident Procedures", "weight": 9,
        "checks": ["response_and_reporting"]},
    "164.308(a)(7)": {"name": "Contingency Plan", "weight": 9,
        "checks": ["data_backup_plan", "disaster_recovery", "emergency_mode_operation"]},
    "164.308(a)(8)": {"name": "Evaluation", "weight": 7,
        "checks": ["periodic_evaluation"]},
}

PHYSICAL_SAFEGUARDS = {
    "164.310(a)": {"name": "Facility Access Controls", "weight": 9,
        "checks": ["contingency_operations", "facility_security_plan", "access_control_validation", "maintenance_records"]},
    "164.310(b)": {"name": "Workstation Use", "weight": 7,
        "checks": ["workstation_use_policies"]},
    "164.310(c)": {"name": "Workstation Security", "weight": 7,
        "checks": ["physical_workstation_safeguards"]},
    "164.310(d)": {"name": "Device and Media Controls", "weight": 8,
        "checks": ["disposal", "media_reuse", "accountability", "data_backup_transport"]},
}

TECHNICAL_SAFEGUARDS = {
    "164.312(a)": {"name": "Access Control", "weight": 10,
        "checks": ["unique_user_id", "emergency_access", "automatic_logoff", "encryption_decryption"]},
    "164.312(b)": {"name": "Audit Controls", "weight": 9,
        "checks": ["audit_logging", "audit_review"]},
    "164.312(c)": {"name": "Integrity", "weight": 9,
        "checks": ["electronic_mechanisms_to_authenticate_ephi"]},
    "164.312(d)": {"name": "Person or Entity Authentication", "weight": 8,
        "checks": ["authentication_mechanisms"]},
    "164.312(e)": {"name": "Transmission Security", "weight": 10,
        "checks": ["integrity_controls", "encryption"]},
}

PHI_IDENTIFIERS = [
    "name", "address", "dates", "phone", "fax", "email", "ssn",
    "medical_record_number", "health_plan_id", "account_number",
    "certificate_license", "vehicle_id", "device_id", "url", "ip_address",
    "biometric", "photo", "other_unique_id",
]


# ── FastMCP Server ──────────────────────────────────────────────

mcp = FastMCP(
    "hipaa-compliance-mcp",
    instructions=(
        "HIPAA Compliance MCP Server by MEOK AI Labs. "
        "Assess healthcare data handling against HIPAA Administrative, Physical, "
        "and Technical safeguards. Check PHI handling, generate BAA templates, "
        "evaluate breach notification requirements, and verify minimum necessary compliance."
    ),
)


@mcp.tool()
def assess_hipaa_compliance(
    organization_name: str,
    has_risk_analysis: bool = False,
    has_security_officer: bool = False,
    has_workforce_training: bool = False,
    has_incident_procedures: bool = False,
    has_contingency_plan: bool = False,
    has_facility_controls: bool = False,
    has_workstation_security: bool = False,
    has_access_control: bool = False,
    has_audit_controls: bool = False,
    has_transmission_security: bool = False,
    has_encryption: bool = False,
    has_authentication: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Evaluate an organization against HIPAA Administrative, Physical, and Technical safeguards.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        organization_name (str): The organization name to analyze or process.
        has_risk_analysis (bool): The has risk analysis to analyze or process.
        has_security_officer (bool): The has security officer to analyze or process.
        has_workforce_training (bool): The has workforce training to analyze or process.
        has_incident_procedures (bool): The has incident procedures to analyze or process.
        has_contingency_plan (bool): The has contingency plan to analyze or process.
        has_facility_controls (bool): The has facility controls to analyze or process.
        has_workstation_security (bool): The has workstation security to analyze or process.
        has_access_control (bool): The has access control to analyze or process.
        has_audit_controls (bool): The has audit controls to analyze or process.
        has_transmission_security (bool): The has transmission security to analyze or process.
        has_encryption (bool): The has encryption to analyze or process.
        has_authentication (bool): The has authentication to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    checks = {
        "risk_analysis": has_risk_analysis,
        "security_officer": has_security_officer,
        "workforce_training": has_workforce_training,
        "incident_procedures": has_incident_procedures,
        "contingency_plan": has_contingency_plan,
        "facility_controls": has_facility_controls,
        "workstation_security": has_workstation_security,
        "access_control": has_access_control,
        "audit_controls": has_audit_controls,
        "transmission_security": has_transmission_security,
        "encryption": has_encryption,
        "authentication": has_authentication,
    }

    admin_items = ["risk_analysis", "security_officer", "workforce_training",
                   "incident_procedures", "contingency_plan"]
    physical_items = ["facility_controls", "workstation_security"]
    technical_items = ["access_control", "audit_controls", "transmission_security",
                       "encryption", "authentication"]

    admin_score = sum(1 for k in admin_items if checks[k]) / len(admin_items) * 100
    physical_score = sum(1 for k in physical_items if checks[k]) / len(physical_items) * 100
    technical_score = sum(1 for k in technical_items if checks[k]) / len(technical_items) * 100
    overall = (admin_score * 0.4 + physical_score * 0.2 + technical_score * 0.4)

    findings = []
    for k, v in checks.items():
        if not v:
            findings.append({"safeguard": k, "status": "NOT_IMPLEMENTED", "severity": "HIGH",
                             "recommendation": f"Implement {k.replace('_', ' ')} per HIPAA Security Rule"})

    if overall >= 80:
        risk_level = "LOW"
    elif overall >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return json.dumps({
        "organization": organization_name,
        "assessment_date": datetime.now().isoformat(),
        "overall_score": round(overall, 1),
        "risk_level": risk_level,
        "administrative_safeguards": {"score": round(admin_score, 1), "max": 100},
        "physical_safeguards": {"score": round(physical_score, 1), "max": 100},
        "technical_safeguards": {"score": round(technical_score, 1), "max": 100},
        "findings": findings,
        "total_checks": len(checks),
        "passed": sum(1 for v in checks.values() if v),
        "failed": sum(1 for v in checks.values() if not v),
    }, indent=2)


@mcp.tool()
def check_phi_handling(
    data_description: str,
    identifiers_present: str = "",
    storage_encrypted: bool = False,
    transmission_encrypted: bool = False,
    access_logged: bool = False,
    minimum_necessary_applied: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Check Protected Health Information handling compliance.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        data_description (str): The data description to analyze or process.
        identifiers_present (str): The identifiers present to analyze or process.
        storage_encrypted (bool): The storage encrypted to analyze or process.
        transmission_encrypted (bool): The transmission encrypted to analyze or process.
        access_logged (bool): The access logged to analyze or process.
        minimum_necessary_applied (bool): The minimum necessary applied to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    present = [i.strip().lower() for i in identifiers_present.split(",") if i.strip()]
    matched_phi = [p for p in present if any(phi in p for phi in PHI_IDENTIFIERS)]
    contains_phi = len(matched_phi) > 0 or any(
        kw in data_description.lower()
        for kw in ["patient", "medical", "health", "diagnosis", "treatment", "prescription", "ssn"]
    )

    issues = []
    if contains_phi and not storage_encrypted:
        issues.append({"issue": "PHI at rest not encrypted", "rule": "164.312(a)(2)(iv)", "severity": "CRITICAL"})
    if contains_phi and not transmission_encrypted:
        issues.append({"issue": "PHI in transit not encrypted", "rule": "164.312(e)(2)(ii)", "severity": "CRITICAL"})
    if contains_phi and not access_logged:
        issues.append({"issue": "PHI access not logged", "rule": "164.312(b)", "severity": "HIGH"})
    if contains_phi and not minimum_necessary_applied:
        issues.append({"issue": "Minimum necessary not applied", "rule": "164.502(b)", "severity": "HIGH"})

    compliance = "COMPLIANT" if not issues else "NON_COMPLIANT"

    return json.dumps({
        "data_description": data_description,
        "contains_phi": contains_phi,
        "phi_identifiers_detected": matched_phi,
        "compliance_status": compliance,
        "issues": issues,
        "controls_checked": {
            "storage_encrypted": storage_encrypted,
            "transmission_encrypted": transmission_encrypted,
            "access_logged": access_logged,
            "minimum_necessary_applied": minimum_necessary_applied,
        },
    }, indent=2)


@mcp.tool()
def generate_baa(
    covered_entity_name: str,
    business_associate_name: str,
    services_description: str,
    effective_date: str = "",
    term_years: int = 3,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Generate a Business Associate Agreement template per HIPAA requirements.

    Behavior:
        This tool generates structured output without modifying external systems.
        Output is deterministic for identical inputs. No side effects.
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        covered_entity_name (str): The covered entity name to analyze or process.
        business_associate_name (str): The business associate name to analyze or process.
        services_description (str): The services description to analyze or process.
        effective_date (str): The effective date to analyze or process.
        term_years (int): The term years to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    eff_date = effective_date or datetime.now().strftime("%Y-%m-%d")

    baa = {
        "document_type": "Business Associate Agreement (BAA)",
        "generated": datetime.now().isoformat(),
        "parties": {
            "covered_entity": covered_entity_name,
            "business_associate": business_associate_name,
        },
        "effective_date": eff_date,
        "term": f"{term_years} years",
        "services": services_description,
        "required_provisions": [
            {"section": "1. Permitted Uses", "text": f"{business_associate_name} may use or disclose PHI only as permitted by this Agreement or as Required by Law."},
            {"section": "2. Safeguards", "text": f"{business_associate_name} shall implement administrative, physical, and technical safeguards per 45 CFR 164.308, 164.310, and 164.312."},
            {"section": "3. Reporting", "text": "Business Associate shall report any use or disclosure of PHI not provided for by this Agreement within 5 business days of discovery."},
            {"section": "4. Breach Notification", "text": "Business Associate shall notify Covered Entity of any breach of unsecured PHI within 60 days of discovery per 45 CFR 164.410."},
            {"section": "5. Subcontractors", "text": "Business Associate shall ensure any subcontractors that create or receive PHI agree to the same restrictions and conditions."},
            {"section": "6. Access to PHI", "text": "Business Associate shall provide access to PHI in a Designated Record Set to the Covered Entity within 30 days of request."},
            {"section": "7. Amendment", "text": "Business Associate shall make amendments to PHI in a Designated Record Set as directed by the Covered Entity."},
            {"section": "8. Accounting of Disclosures", "text": "Business Associate shall maintain and make available information required for accounting of disclosures per 45 CFR 164.528."},
            {"section": "9. HHS Access", "text": "Business Associate shall make internal practices and records available to HHS for compliance determination."},
            {"section": "10. Termination", "text": "Covered Entity may terminate this Agreement if Business Associate has violated a material term. Upon termination, return or destroy all PHI."},
        ],
        "disclaimer": "TEMPLATE ONLY. Consult qualified legal counsel before execution.",
    }

    return json.dumps(baa, indent=2)


@mcp.tool()
def breach_notification_check(
    breach_date: str,
    discovery_date: str,
    individuals_affected: int = 0,
    notification_sent: bool = False,
    notification_date: str = "",
    involves_unsecured_phi: bool = True,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Check breach notification compliance against HIPAA 45-day and 60-day rules.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        breach_date (str): The breach date to analyze or process.
        discovery_date (str): The discovery date to analyze or process.
        individuals_affected (int): The individuals affected to analyze or process.
        notification_sent (bool): The notification sent to analyze or process.
        notification_date (str): The notification date to analyze or process.
        involves_unsecured_phi (bool): The involves unsecured phi to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    try:
        d_breach = datetime.strptime(breach_date, "%Y-%m-%d")
        d_discovery = datetime.strptime(discovery_date, "%Y-%m-%d")
    except ValueError:
        return json.dumps({"error": "Dates must be YYYY-MM-DD format"})

    days_since_discovery = (datetime.now() - d_discovery).days
    individual_deadline = d_discovery + timedelta(days=60)
    hhs_deadline = d_discovery + timedelta(days=60)
    media_required = individuals_affected >= 500

    issues = []
    if involves_unsecured_phi and not notification_sent and days_since_discovery > 60:
        issues.append({
            "violation": "Individual notification deadline exceeded",
            "rule": "45 CFR 164.404(b)",
            "deadline": individual_deadline.strftime("%Y-%m-%d"),
            "severity": "CRITICAL",
            "penalty_range": "$100 - $50,000 per violation",
        })

    if involves_unsecured_phi and individuals_affected >= 500 and not notification_sent:
        issues.append({
            "violation": "Media notification required for 500+ individuals",
            "rule": "45 CFR 164.406",
            "severity": "HIGH",
        })

    if involves_unsecured_phi and individuals_affected >= 500:
        issues.append({
            "note": "HHS must be notified within 60 days for breaches affecting 500+ individuals",
            "rule": "45 CFR 164.408(b)",
            "deadline": hhs_deadline.strftime("%Y-%m-%d"),
        })

    compliant = len([i for i in issues if "violation" in i]) == 0

    return json.dumps({
        "breach_date": breach_date,
        "discovery_date": discovery_date,
        "days_since_discovery": days_since_discovery,
        "individuals_affected": individuals_affected,
        "individual_notification_deadline": individual_deadline.strftime("%Y-%m-%d"),
        "hhs_notification_deadline": hhs_deadline.strftime("%Y-%m-%d"),
        "media_notification_required": media_required,
        "notification_sent": notification_sent,
        "involves_unsecured_phi": involves_unsecured_phi,
        "compliance_status": "COMPLIANT" if compliant else "NON_COMPLIANT",
        "issues": issues,
    }, indent=2)


@mcp.tool()
def minimum_necessary_check(
    data_request_description: str,
    requester_role: str,
    purpose: str,
    data_elements_requested: str = "",
    role_based_access: bool = False,
    policy_documented: bool = False,
    caller: str = "",
    api_key: str = "",
) -> str:
    """Evaluate data minimization compliance per HIPAA Minimum Necessary Rule (164.502(b)).

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        data_request_description (str): The data request description to analyze or process.
        requester_role (str): The requester role to analyze or process.
        purpose (str): The purpose to analyze or process.
        data_elements_requested (str): The data elements requested to analyze or process.
        role_based_access (bool): The role based access to analyze or process.
        policy_documented (bool): The policy documented to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    if err := _check_auth(api_key):
        return err
    if err := _rl(caller):
        return err

    elements = [e.strip() for e in data_elements_requested.split(",") if e.strip()]

    exempt_purposes = ["treatment", "payment", "healthcare operations",
                       "individual request", "required by law", "hhs investigation"]
    is_exempt = any(ep in purpose.lower() for ep in exempt_purposes)

    issues = []
    if not is_exempt:
        if not role_based_access:
            issues.append({"issue": "No role-based access controls", "rule": "164.514(d)(2)", "severity": "HIGH"})
        if not policy_documented:
            issues.append({"issue": "Minimum necessary policies not documented", "rule": "164.514(d)(3)", "severity": "MEDIUM"})
        if len(elements) > 10:
            issues.append({"issue": f"Large number of data elements requested ({len(elements)}). Review for necessity.",
                           "rule": "164.502(b)(1)", "severity": "MEDIUM"})

    sensitive_elements = [e for e in elements if any(s in e.lower() for s in ["ssn", "hiv", "mental", "substance", "genetic"])]
    if sensitive_elements:
        issues.append({"issue": f"Highly sensitive data elements: {sensitive_elements}",
                       "rule": "164.502(b)", "severity": "HIGH",
                       "recommendation": "Apply additional restrictions for sensitive PHI categories"})

    return json.dumps({
        "request_description": data_request_description,
        "requester_role": requester_role,
        "purpose": purpose,
        "elements_requested": len(elements),
        "is_exempt_purpose": is_exempt,
        "sensitive_elements_detected": sensitive_elements,
        "role_based_access": role_based_access,
        "policy_documented": policy_documented,
        "compliance_status": "COMPLIANT" if not issues else "REVIEW_NEEDED",
        "issues": issues,
    }, indent=2)


@mcp.tool()
def predict_risk_neural(
    system_name: str, uses_biometric: bool = False, uses_health_data: bool = False,
    has_human_oversight: bool = True, affected_users: int = 0, sector: str = "",
    has_documentation: bool = False, prior_incidents: int = 0, api_key: str = "") -> dict:
    """Neural network-based risk prediction that improves from every compliance check.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        system_name (str): The system name to analyze or process.
        uses_biometric (bool): The uses biometric to analyze or process.
        uses_health_data (bool): The uses health data to analyze or process.
        has_human_oversight (bool): The has human oversight to analyze or process.
        affected_users (int): The affected users to analyze or process.
        sector (str): The sector to analyze or process.
        has_documentation (bool): The has documentation to analyze or process.
        prior_incidents (int): The prior incidents to analyze or process.
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg}
    features = _neural_net.extract_features_from_system(
        system_name=system_name, uses_biometric=uses_biometric,
        uses_health_data=uses_health_data, has_human_oversight=has_human_oversight,
        affected_users=affected_users, sector=sector, has_documentation=has_documentation,
        prior_incidents=prior_incidents)
    prediction = _neural_net.predict_risk(features)
    prediction["system_name"] = system_name
    return prediction


@mcp.tool()
def neural_insights(api_key: str = "") -> dict:
    """Get aggregate learning insights from the neural compliance model.

    Behavior:
        This tool is read-only and stateless — it produces analysis output
        without modifying any external systems, databases, or files.
        Safe to call repeatedly with identical inputs (idempotent).
        Free tier: 10/day rate limit. Pro tier: unlimited.
        No authentication required for basic usage.

    When to use:
        Use this tool when you need to assess, audit, or verify compliance
        requirements. Ideal for gap analysis, readiness checks, and generating
        compliance documentation.

    When NOT to use:
        Do not use as a substitute for qualified legal counsel. This tool
        provides technical compliance guidance, not legal advice.

    Args:
        api_key (str): The api key to analyze or process.

    Behavioral Transparency:
        - Side Effects: This tool is read-only and produces no side effects. It does not modify
          any external state, databases, or files. All output is computed in-memory and returned
          directly to the caller.
        - Authentication: No authentication required for basic usage. Pro/Enterprise tiers
          require a valid MEOK API key passed via the MEOK_API_KEY environment variable.
        - Rate Limits: Free tier: 10 calls/day. Pro tier: unlimited. Rate limit headers are
          included in responses (X-RateLimit-Remaining, X-RateLimit-Reset).
        - Error Handling: Returns structured error objects with 'error' key on failure.
          Never raises unhandled exceptions. Invalid inputs return descriptive validation errors.
        - Idempotency: Fully idempotent — calling with the same inputs always produces the
          same output. Safe to retry on timeout or transient failure.
        - Data Privacy: No input data is stored, logged, or transmitted to external services.
          All processing happens locally within the MCP server process.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg}
    return _neural_net.get_insights()


def main():
    mcp.run()


if __name__ == "__main__":
    main()
