# HIPAA Compliance MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

Automates HIPAA healthcare compliance assessment. Evaluate Administrative, Physical, and Technical safeguards, check PHI handling, generate BAA templates, and verify breach notification compliance.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/hipaa-compliance)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `assess_hipaa_compliance` | Evaluate against HIPAA Administrative, Physical, and Technical safeguards |
| `check_phi_handling` | Check Protected Health Information handling compliance |
| `generate_baa` | Generate a Business Associate Agreement template |
| `breach_notification_check` | Check breach notification compliance against 45/60-day rules |
| `minimum_necessary_check` | Evaluate data minimization per HIPAA Minimum Necessary Rule |

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
