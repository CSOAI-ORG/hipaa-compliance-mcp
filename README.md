[![hipaa-compliance-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/hipaa-compliance-mcp/badges/score.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/hipaa-compliance-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-Published-green)](https://registry.modelcontextprotocol.io)
[![PyPI](https://img.shields.io/pypi/v/hipaa-compliance-mcp)](https://pypi.org/project/hipaa-compliance-mcp/)

[![hipaa-compliance-mcp MCP server](https://glama.ai/mcp/servers/CSOAI-ORG/hipaa-compliance-mcp/badges/card.svg)](https://glama.ai/mcp/servers/CSOAI-ORG/hipaa-compliance-mcp)

<div align="center">

[![PyPI](https://img.shields.io/pypi/v/hipaa-compliance-mcp)](https://pypi.org/project/hipaa-compliance-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/hipaa-compliance-mcp)](https://pypi.org/project/hipaa-compliance-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/hipaa-compliance-mcp)](https://github.com/CSOAI-ORG/hipaa-compliance-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# HIPAA Compliance MCP

**Automate HIPAA healthcare compliance for AI systems handling PHI.**

Administrative safeguards · Physical safeguards · Technical safeguards · BAA templates · Breach notification · Minimum necessary rule

Penalties: up to $2.1M per violation category per year.

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing)

</div>

---

## Why This Exists

Healthcare AI is the fastest-growing sector for ML deployment — and the most regulated. Every AI system touching Protected Health Information (PHI) must comply with the HIPAA Security Rule, Privacy Rule, and Breach Notification Rule. Business Associate Agreements (BAAs) are required for every vendor in the chain.

This MCP assesses your AI system against all three HIPAA safeguard categories, checks PHI handling workflows, generates BAA templates, and verifies breach notification readiness.

## Install

```bash
pip install hipaa-compliance-mcp
```

## Tools

| Tool | Safeguard | What it does |
|------|-----------|-------------|
| `assess_administrative` | Administrative | Security management, workforce training, contingency plans |
| `assess_physical` | Physical | Facility access, workstation security, device controls |
| `assess_technical` | Technical | Access controls, audit controls, transmission security |
| `check_phi_handling` | Privacy Rule | PHI use/disclosure, minimum necessary, de-identification |
| `generate_baa` | — | Business Associate Agreement template |
| `assess_breach_readiness` | Breach Rule | 60-day notification, risk assessment, documentation |
| `run_full_audit` | All | Complete HIPAA readiness assessment |
| `sign_attestation` | — | HMAC-SHA256 signed compliance certificate |

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT
<!-- mcp-name: io.github.CSOAI-ORG/hipaa-compliance-mcp -->
