"""Functional tests for HIPAA Compliance MCP Server tools.

Tests tool registration, input validation, error handling, and output
correctness for all HIPAA compliance tools. No external API calls.
"""
import json
import os
import sys
from unittest.mock import MagicMock

_mock_mcp_module = MagicMock()

class _MockFastMCP:
    def __init__(self, name="", **kwargs):
        self.name = name

    def tool(self):
        def decorator(fn):
            return fn
        return decorator

_mock_mcp_module.FastMCP = _MockFastMCP
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.server.fastmcp"] = _mock_mcp_module

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("MEOK_API_KEY", None)

import server as srv  # noqa: E402
import pytest  # noqa: E402
from unittest.mock import patch  # noqa: E402


@pytest.fixture(autouse=True)
def reset_state():
    srv._usage.clear()
    os.environ.pop("MEOK_API_KEY", None)
    yield
    srv._usage.clear()


@pytest.fixture(autouse=True)
def bypass_auth_and_rate_limit():
    with patch.object(srv, "_check_auth", return_value=None), \
         patch.object(srv, "_rl", return_value=None):
        yield


class TestMcpRegistration:
    def test_mcp_object_exists(self):
        assert hasattr(srv, "mcp")

    def test_tools_are_callable(self):
        tool_names = [
            "assess_hipaa_compliance", "check_phi_handling",
            "generate_baa", "breach_notification_check",
            "minimum_necessary_check", "predict_risk_neural",
            "neural_insights",
        ]
        for name in tool_names:
            assert hasattr(srv, name), f"Missing tool: {name}"
            assert callable(getattr(srv, name)), f"Tool not callable: {name}"


class TestAssessHipaaCompliance:
    def test_fully_compliant(self):
        result = json.loads(srv.assess_hipaa_compliance(
            "Full Compliance Hospital",
            has_risk_analysis=True, has_security_officer=True,
            has_workforce_training=True, has_incident_procedures=True,
            has_contingency_plan=True, has_facility_controls=True,
            has_workstation_security=True, has_access_control=True,
            has_audit_controls=True, has_transmission_security=True,
            has_encryption=True, has_authentication=True,
        ))
        assert result["overall_score"] == 100.0
        assert result["risk_level"] == "LOW"
        assert result["passed"] == 12
        assert result["failed"] == 0

    def test_fully_non_compliant(self):
        result = json.loads(srv.assess_hipaa_compliance("Zero Compliance Clinic"))
        assert result["overall_score"] == 0.0
        assert result["risk_level"] == "HIGH"
        assert result["passed"] == 0
        assert result["failed"] == 12

    def test_partial_compliance(self):
        result = json.loads(srv.assess_hipaa_compliance(
            "Partial Hospital",
            has_risk_analysis=True, has_encryption=True, has_access_control=True,
        ))
        assert 0 < result["overall_score"] < 100
        assert len(result["findings"]) > 0

    def test_safeguard_categories(self):
        result = json.loads(srv.assess_hipaa_compliance("Test Org", has_risk_analysis=True))
        assert "administrative_safeguards" in result
        assert "physical_safeguards" in result
        assert "technical_safeguards" in result
        assert result["administrative_safeguards"]["max"] == 100
        assert result["physical_safeguards"]["max"] == 100
        assert result["technical_safeguards"]["max"] == 100

    def test_organization_name_preserved(self):
        result = json.loads(srv.assess_hipaa_compliance("St. Mary's Hospital"))
        assert result["organization"] == "St. Mary's Hospital"

    def test_findings_all_high_severity_when_missing(self):
        result = json.loads(srv.assess_hipaa_compliance("Clinic"))
        for finding in result["findings"]:
            assert finding["severity"] == "HIGH"


class TestCheckPhiHandling:
    def test_phi_detected_from_description(self):
        result = json.loads(srv.check_phi_handling("Patient medical records database"))
        assert result["contains_phi"] is True

    def test_phi_detected_from_identifiers(self):
        result = json.loads(srv.check_phi_handling(
            "Database", identifiers_present="name, ssn, email"
        ))
        assert result["contains_phi"] is True
        assert "ssn" in result["phi_identifiers_detected"]

    def test_no_phi(self):
        result = json.loads(srv.check_phi_handling("Anonymous aggregate statistics"))
        assert result["contains_phi"] is False

    def test_unencrypted_phi_critical(self):
        result = json.loads(srv.check_phi_handling(
            "Patient medical records", identifiers_present="ssn",
            storage_encrypted=False, transmission_encrypted=False,
        ))
        assert result["compliance_status"] == "NON_COMPLIANT"
        critical = [i for i in result["issues"] if i["severity"] == "CRITICAL"]
        assert len(critical) >= 2

    def test_encrypted_phi_compliant(self):
        result = json.loads(srv.check_phi_handling(
            "Patient records", storage_encrypted=True,
            transmission_encrypted=True, access_logged=True,
            minimum_necessary_applied=True,
        ))
        assert result["compliance_status"] == "COMPLIANT"

    def test_controls_checked_keys(self):
        result = json.loads(srv.check_phi_handling("Health data"))
        assert "storage_encrypted" in result["controls_checked"]
        assert "transmission_encrypted" in result["controls_checked"]
        assert "access_logged" in result["controls_checked"]
        assert "minimum_necessary_applied" in result["controls_checked"]


class TestGenerateBAA:
    def test_basic_baa(self):
        result = json.loads(srv.generate_baa(
            "Test Hospital", "Cloud Health Inc", "EHR cloud hosting"
        ))
        assert result["document_type"] == "Business Associate Agreement (BAA)"
        assert result["parties"]["covered_entity"] == "Test Hospital"
        assert result["parties"]["business_associate"] == "Cloud Health Inc"
        assert len(result["required_provisions"]) == 10

    def test_baa_custom_term(self):
        result = json.loads(srv.generate_baa(
            "Hospital", "Vendor", "Data processing",
            effective_date="2025-06-01", term_years=5,
        ))
        assert result["term"] == "5 years"
        assert result["effective_date"] == "2025-06-01"

    def test_baa_services_preserved(self):
        result = json.loads(srv.generate_baa(
            "CE", "BA", "AI-powered diagnostic analytics"
        ))
        assert result["services"] == "AI-powered diagnostic analytics"

    def test_baa_disclaimer_present(self):
        result = json.loads(srv.generate_baa("CE", "BA", "Service"))
        assert "TEMPLATE" in result["disclaimer"]


class TestBreachNotificationCheck:
    def test_recent_breach_compliant(self):
        result = json.loads(srv.breach_notification_check(
            breach_date="2025-01-01", discovery_date="2025-01-01",
            individuals_affected=100, notification_sent=True,
        ))
        assert "compliance_status" in result
        assert "individual_notification_deadline" in result

    def test_invalid_date_format(self):
        result = json.loads(srv.breach_notification_check(
            breach_date="not-a-date", discovery_date="2025-01-01",
        ))
        assert "error" in result

    def test_large_breach_requires_media(self):
        result = json.loads(srv.breach_notification_check(
            breach_date="2025-01-15", discovery_date="2025-01-15",
            individuals_affected=600, involves_unsecured_phi=True,
        ))
        assert result["media_notification_required"] is True

    def test_small_breach_no_media(self):
        result = json.loads(srv.breach_notification_check(
            breach_date="2025-01-15", discovery_date="2025-01-15",
            individuals_affected=50,
        ))
        assert result["media_notification_required"] is False

    def test_hhs_deadline_present_for_500plus(self):
        result = json.loads(srv.breach_notification_check(
            breach_date="2025-01-15", discovery_date="2025-01-15",
            individuals_affected=1000, involves_unsecured_phi=True,
        ))
        assert "hhs_notification_deadline" in result


class TestMinimumNecessaryCheck:
    def test_exempt_purpose_treatment(self):
        result = json.loads(srv.minimum_necessary_check(
            data_request_description="Patient record access",
            requester_role="Physician", purpose="treatment",
        ))
        assert result["is_exempt_purpose"] is True

    def test_exempt_purpose_payment(self):
        result = json.loads(srv.minimum_necessary_check(
            data_request_description="Billing access",
            requester_role="Billers", purpose="payment",
        ))
        assert result["is_exempt_purpose"] is True

    def test_non_exempt_with_issues(self):
        result = json.loads(srv.minimum_necessary_check(
            data_request_description="Marketing analysis",
            requester_role="Marketing analyst", purpose="marketing",
        ))
        assert result["is_exempt_purpose"] is False
        assert len(result["issues"]) > 0

    def test_sensitive_data_flagged(self):
        result = json.loads(srv.minimum_necessary_check(
            data_request_description="Research study",
            requester_role="Researcher", purpose="research",
            data_elements_requested="ssn, HIV status, genetic markers",
        ))
        assert len(result["sensitive_elements_detected"]) > 0

    def test_many_elements_flagged(self):
        elements = ", ".join([f"field_{i}" for i in range(15)])
        result = json.loads(srv.minimum_necessary_check(
            data_request_description="Bulk export",
            requester_role="Analyst", purpose="analytics",
            data_elements_requested=elements,
        ))
        medium_issues = [i for i in result["issues"] if i.get("severity") == "MEDIUM"]
        assert len(medium_issues) > 0

    def test_role_based_access_check(self):
        result = json.loads(srv.minimum_necessary_check(
            data_request_description="Data access",
            requester_role="Analyst", purpose="research",
            role_based_access=True, policy_documented=True,
        ))
        role_issues = [i for i in result["issues"] if "role-based" in i["issue"].lower()]
        assert len(role_issues) == 0


class TestPredictRiskNeural:
    def test_fallback_when_no_neural(self):
        result = srv.predict_risk_neural("Test System")
        assert "risk_level" in result
        assert result["confidence"] == "low"
        assert "note" in result

    def test_fallback_includes_factors(self):
        result = srv.predict_risk_neural(
            "AI Diagnostic", uses_biometric=True, uses_health_data=True
        )
        assert result["factors"]["uses_biometric"] is True
        assert result["factors"]["uses_health_data"] is True


class TestNeuralInsights:
    def test_fallback_status(self):
        result = srv.neural_insights()
        assert result["status"] == "fallback"
        assert "note" in result