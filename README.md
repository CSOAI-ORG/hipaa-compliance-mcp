# HIPAA Compliance MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

Automates HIPAA healthcare compliance assessment. Evaluate Administrative, Physical, and Technical safeguards, check PHI handling, generate BAA templates, verify breach notification compliance, and enforce the minimum necessary rule.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/hipaa-compliance)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Features

- Full HIPAA Security Rule compliance assessment across all three safeguard categories
- Protected Health Information (PHI) handling validation with 18 identifier types
- Business Associate Agreement (BAA) template generation with 10 required provisions
- Breach notification timeline compliance checking (60-day individual, media for 500+)
- Minimum necessary rule evaluation with exempt purpose detection
- Neural network-based risk prediction that learns from compliance checks
- Weighted scoring: Administrative (40%), Technical (40%), Physical (20%)
- Built-in rate limiting (10 free/day) and API key authentication

## Tools

| Tool | Description |
|------|-------------|
| `assess_hipaa_compliance` | Evaluate against HIPAA Administrative, Physical, and Technical safeguards with weighted scoring |
| `check_phi_handling` | Check PHI handling compliance -- encryption at rest/transit, access logging, minimum necessary |
| `generate_baa` | Generate a Business Associate Agreement template with all 10 required HIPAA provisions |
| `breach_notification_check` | Check breach notification compliance against 45 CFR 164.404-408 (60-day rules) |
| `minimum_necessary_check` | Evaluate data minimization per HIPAA Minimum Necessary Rule (164.502(b)) |
| `predict_risk_neural` | Neural network-based risk prediction that improves from every compliance check |
| `neural_insights` | Get aggregate learning insights from the neural compliance model |

## HIPAA Coverage

- **Administrative Safeguards** (164.308): Security management, workforce security, information access management, security awareness training, incident procedures, contingency planning, evaluation
- **Physical Safeguards** (164.310): Facility access controls, workstation use and security, device and media controls
- **Technical Safeguards** (164.312): Access control, audit controls, integrity, person/entity authentication, transmission security

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/hipaa-compliance-mcp.git
cd hipaa-compliance-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "hipaa-compliance": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/hipaa-compliance-mcp"
    }
  }
}
```

## Usage Examples

```python
# Assess HIPAA compliance
result = assess_hipaa_compliance(
    organization_name="Acme Health",
    has_risk_analysis=True,
    has_security_officer=True,
    has_encryption=True,
    has_access_control=True,
    has_audit_controls=True
)

# Check PHI handling
result = check_phi_handling(
    data_description="Patient treatment records",
    identifiers_present="name,ssn,medical_record_number",
    storage_encrypted=True,
    transmission_encrypted=True,
    access_logged=True
)

# Generate a BAA
result = generate_baa(
    covered_entity_name="Regional Hospital",
    business_associate_name="Cloud EHR Inc",
    services_description="Electronic health record hosting and backup"
)

# Check breach notification compliance
result = breach_notification_check(
    breach_date="2026-03-01",
    discovery_date="2026-03-15",
    individuals_affected=1200,
    involves_unsecured_phi=True
)
```

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 10 requests/day |
| Pro | $29/mo | Unlimited |

## Authentication

Set `MEOK_API_KEY` environment variable. Get your key at [meok.ai/api-keys](https://meok.ai/api-keys).

## Links

- [MEOK AI Labs](https://meok.ai)
- [All MCP Servers](https://meok.ai/mcp)
- [GitHub](https://github.com/CSOAI-ORG/hipaa-compliance-mcp)
