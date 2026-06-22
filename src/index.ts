#!/usr/bin/env node
/**
 * Security Scanner MCP Server
 *
 * Multi-engine container & system vulnerability scanning for AI agents.
 * Wraps Trivy and Grype with cross-engine validation, SBOM generation,
 * and IaC misconfiguration scanning.
 *
 * @supernova123/security-scanner-mcp-server — MIT License
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTrivyTools } from "./tools/trivy.js";
import { registerGrypeTools } from "./tools/grype.js";
import { registerCrossValidateTool } from "./tools/cross-validate.js";
import { checkBinary } from "./engines.js";

const server = new McpServer({
  name: "security-scanner",
  version: "0.1.0",
});

// Register all tool modules
registerTrivyTools(server);
registerGrypeTools(server);
registerCrossValidateTool(server);

// Check engine availability at startup
async function checkEngines(): Promise<void> {
  const hasTrivy = await checkBinary("trivy");
  const hasGrype = await checkBinary("grype");

  if (!hasTrivy && !hasGrype) {
    console.error("WARNING: Neither trivy nor grype found on PATH.");
    console.error("Install at least one engine:");
    console.error("  Trivy:  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin");
    console.error("  Grype:  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin");
  } else if (!hasTrivy) {
    console.error("NOTE: trivy not found. Trivy-based tools will fail. Install:");
    console.error("  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin");
  } else if (!hasGrype) {
    console.error("NOTE: grype not found. Grype-based tools will fail. Install:");
    console.error("  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin");
  } else {
    console.error("Both trivy and grype detected. Cross-validation enabled.");
  }
}

async function main(): Promise<void> {
  await checkEngines();

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Security Scanner MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
