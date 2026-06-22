# Security Scanner MCP Server — Quick Start Guide

*Scan Docker images and filesystems for vulnerabilities using Trivy and Grype, directly from Claude Desktop or Cursor. Cross-engine validation catches what single scanners miss.*

---

## What This Is

Security Scanner MCP wraps **two** vulnerability scanners — Trivy (Aqua Security) and Grype (Anchore) — into a single MCP server. Run both against the same target and see what each catches alone.

**Why two scanners?** Different vulnerability databases + different detection logic = broader coverage. The `cross_validate` tool surfaces CVEs that only appear in one engine — the gaps you'd miss with a single scanner.

## Prerequisites

- **Trivy** (recommended): `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`
- **Grype** (for cross-validation): `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`
- **Docker** running (for image scans) — or scan filesystems/repo URLs without Docker
- **Node.js 18+**

## Step 1: Install

```bash
npm install -g @supernova123/security-scanner-mcp-server
```

Verify engines are detected:

```bash
npx @supernova123/security-scanner-mcp-server
# Server starts on stdio — Ctrl+C to stop
```

## Step 2: Connect Your AI Client

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

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

### Cursor

Add to `.cursor/mcp.json` in your project root:

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

## Step 3: Scan Something

### Scan a Docker image (Trivy)

Ask your AI: *"Scan the nginx:latest image for vulnerabilities"*

The server calls `scan_image` with Trivy and returns a severity-sorted report.

### Cross-validate with both engines

Ask: *"Run cross-validation on node:18-alpine"*

The `cross_validate` tool runs Trivy + Grype on the same image and shows:
- Combined CVE count by severity
- CVEs found only by Trivy
- CVEs found only by Grype
- Severity mismatches between engines

### Scan your project directory

Ask: *"Scan the current directory for vulnerabilities and misconfigurations"*

`scan_filesystem` runs Trivy against the local path — catches dependency CVEs AND IaC misconfigurations (Dockerfile issues, Helm chart problems).

### Generate an SBOM

Ask: *"Generate a CycloneDX SBOM for my Docker image"*

`generate_sbom` produces a machine-readable Software Bill of Materials.

## Available Tools (15)

| Tool | Engine | What It Does |
|------|--------|-------------|
| `scan_image` | Trivy | Docker image vulnerability scan |
| `scan_image_grype` | Grype | Same target, different engine |
| `vulnerability_report` | Trivy | Detailed report with remediation advice |
| `scan_filesystem` | Trivy | Local dir/file vuln + misconfig scan |
| `scan_filesystem_grype` | Grype | Cross-engine filesystem scan |
| `scan_repository` | Trivy | Remote git repo scan |
| `scan_remote_image` | Grype | Pull from registry (no Docker daemon) |
| `scan_purl` | Grype | Single Package URL lookup |
| `scan_sbom` | Trivy | Scan existing SBOM file |
| `generate_sbom` | Trivy | Generate CycloneDX/SPDX SBOM |
| `scan_config` | Trivy | IaC misconfiguration scan |
| `cross_validate` | Both | Run both, surface divergence |
| `db_status` | Grype | Check vuln DB freshness |
| `update_db` | Grype | Update vulnerability database |
| `get_version` | Both | Engine version + availability |

## Troubleshooting

**"Trivy not found"** — Install Trivy (see Prerequisites). The server detects installed engines at startup.

**"Grype not found"** — Grype is optional. Cross-validation and Grype-specific tools won't work without it, but all Trivy tools function normally.

**Slow first scan** — Trivy downloads the vulnerability database on first run (~30MB). Subsequent scans use the cached DB.

**No Docker daemon** — Use `scan_remote_image` (Grype pulls from registry directly) or `scan_repository` (scans git repos without Docker).

## Links

- [npm package](https://www.npmjs.com/package/@supernova123/security-scanner-mcp-server)
- [GitHub repo](https://github.com/friendlygeorge/security-scanner-mcp-server)
- [Glama listing](https://glama.ai/mcp/servers/friendlygeorge/security-scanner-mcp-server)
