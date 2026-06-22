# Security Scanner MCP Server

[![npm](https://img.shields.io/npm/v/%40supernova123/security-scanner-mcp-server)](https://www.npmjs.com/package/@supernova123/security-scanner-mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Multi-engine container & system vulnerability scanning for AI agents. Wraps **Trivy** and **Grype** with cross-engine validation, SBOM generation, and IaC misconfiguration scanning.

## Why This Exists

Most security MCP servers wrap a single scanner. This one wraps **two** — Trivy (Aqua Security) and Grype (Anchore) — and runs them against the same target to surface what each engine catches alone. Different vulnerability databases + different detection logic = broader coverage.

**Key differentiator:** No other MCP server offers multi-engine cross-validation.

## Features

- **15 tools** covering vulnerability scanning, SBOM generation, IaC checks, and database management
- **Cross-engine validation** — run Trivy + Grype on the same image and see what each catches alone
- **MIT licensed** — no AGPL encumbrance (unlike `@aikidosec/mcp`)
- **npm-native** — install via `npx`, works with Claude Desktop, Cursor, and any MCP client
- **No cloud account required** — runs locally against Docker daemon or filesystem

## Quick Start

### Prerequisites

Install at least one scanning engine:

```bash
# Trivy (recommended)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Grype (for cross-validation)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Claude Desktop / Cursor

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "npx",
      "args": ["-y", "@supernova123/security-scanner-mcp-server"]
    }
  }
}
```

### Standalone

```bash
npx @supernova123/security-scanner-mcp-server
```

## Tools

| # | Tool | Engine | Description |
|---|------|--------|-------------|
| 1 | `scan_image` | Trivy | Scan Docker image for vulnerabilities |
| 2 | `scan_image_grype` | Grype | Same target via Grype (cross-validation) |
| 3 | `vulnerability_report` | Trivy | Detailed report with remediation |
| 4 | `scan_filesystem` | Trivy | Local dir/file vulnerability + misconfig scan |
| 5 | `scan_filesystem_grype` | Grype | Cross-engine filesystem scan |
| 6 | `scan_repository` | Trivy | Remote git repo scan |
| 7 | `scan_remote_image` | Grype | Pull from registry directly (no Docker daemon) |
| 8 | `scan_purl` | Grype | Single Package URL vulnerability lookup |
| 9 | `scan_sbom` | Trivy | Scan SBOM file for vulnerabilities |
| 10 | `generate_sbom` | Trivy | Generate CycloneDX/SPDX SBOM |
| 11 | `scan_config` | Trivy | IaC misconfiguration scan |
| 12 | `cross_validate` | Both | Run both engines, surface divergence |
| 13 | `db_status` | Grype | Check vulnerability DB status |
| 14 | `update_db` | Grype | Update vulnerability database |
| 15 | `get_version` | Both | Engine version + availability |

## Cross-Validation Example

The `cross_validate` tool runs both Trivy and Grype on the same Docker image and compares results:

```json
{
  "combined_summary": {
    "total_unique_cves": 47,
    "critical": 2,
    "high": 8,
    "medium": 23,
    "low": 14
  },
  "divergence": {
    "only_in_trivy_count": 5,
    "only_in_grype_count": 3,
    "severity_mismatches": 2,
    "only_in_trivy": ["CVE-2023-1234", ...],
    "only_in_grype": ["CVE-2023-5678", ...]
  },
  "insight": "Cross-validation found 5 CVEs only in Trivy and 3 only in Grype. Using both engines gives broader coverage than either alone."
}
```

## Competitive Landscape

| Package | Engine | License | Weekly Downloads |
|---------|--------|---------|-----------------|
| `@aikidosec/mcp` | Cloud API | AGPL-3.0 | ~11,800 |
| `@paretools/security` | Trivy + Semgrep | MIT | ~75 |
| **`@supernova123/security-scanner-mcp-server`** | **Trivy + Grype** | **MIT** | TBD |
| `aquasecurity/trivy-mcp` | Trivy (Go plugin) | MIT | N/A (not npm) |
| `anchore/grype-mcp` | Grype (Python) | Apache-2.0 | N/A (not npm) |

## Development

```bash
git clone https://github.com/friendlygeorge/security-scanner-mcp-server.git
cd security-scanner-mcp-server
npm install
npm run build
npm test
```

## License

MIT — see [LICENSE](LICENSE)

## Links

- [npm package](https://www.npmjs.com/package/@supernova123/security-scanner-mcp-server)
- [GitHub repo](https://github.com/friendlygeorge/security-scanner-mcp-server)
- [MCP specification](https://modelcontextprotocol.io/)
