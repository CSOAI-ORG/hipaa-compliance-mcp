<div align="center">

# Hipaa Compliance MCP

**MCP server for hipaa compliance mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-hipaa-compliance-mcp)](https://pypi.org/project/meok-hipaa-compliance-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Hipaa Compliance MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `assess_hipaa_compliance` | Evaluate an organization against HIPAA Administrative, Physical, and Technical s |
| `check_phi_handling` | Check Protected Health Information handling compliance. |
| `generate_baa` | Generate a Business Associate Agreement template per HIPAA requirements. |
| `breach_notification_check` | Check breach notification compliance against HIPAA 45-day and 60-day rules. |
| `minimum_necessary_check` | Evaluate data minimization compliance per HIPAA Minimum Necessary Rule (164.502( |
| `predict_risk_neural` | Neural network-based risk prediction that improves from every compliance check. |
| `neural_insights` | Get aggregate learning insights from the neural compliance model. |

## Installation

```bash
pip install meok-hipaa-compliance-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "hipaa-compliance-mcp": {
      "command": "python",
      "args": ["-m", "meok_hipaa_compliance_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 7 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
