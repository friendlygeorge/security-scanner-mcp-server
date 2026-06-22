import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  ScanImageGrypeSchema,
  ScanFilesystemGrypeSchema,
  ScanRemoteImageSchema,
  ScanPurlSchema,
  DbStatusSchema,
  UpdateDbSchema,
  GetVersionSchema,
} from "../types.js";
import {
  runCommand,
  parseGrypeJson,
  checkBinary,
  formatVulnTable,
} from "../engines.js";

/**
 * Register all Grype-based tools on the MCP server.
 */
export function registerGrypeTools(server: McpServer): void {
  // 2. scan_image_grype — Scan image via Grype (cross-validation partner)
  server.tool(
    "scan_image_grype",
    "Scan a Docker image for vulnerabilities using Grype (Anchore's scanner). Provides cross-validation against Trivy results — different vulnerability database, different detection coverage.",
    ScanImageGrypeSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const severity = params.severity || "critical,high,medium";
      const args = [
        params.image,
        "-o", "json",
        "--fail-on", params.fail_on || "none",
      ];
      if (params.only_fixed) args.push("--only-fixed");

      const result = await runCommand("grype", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("matches")) {
        return {
          content: [{ type: "text", text: `Grype scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { matches, summary } = parseGrypeJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      const vulns = matches.map((m: any) => ({
        id: m.vulnerability?.id || "N/A",
        package: m.artifact?.name || "N/A",
        installed_version: m.artifact?.version || "N/A",
        fixed_version: m.vulnerability?.fix?.versions?.[0] || "N/A",
        severity: m.vulnerability?.severity || "N/A",
        title: m.vulnerability?.description?.substring(0, 100) || "",
      }));

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            image: params.image,
            engine: "grype",
            scan_summary: {
              total_vulnerabilities: totalVulns,
              critical: summary.Critical || 0,
              high: summary.High || 0,
              medium: summary.Medium || 0,
              low: summary.Low || 0,
              negligible: summary.Negligible || 0,
            },
            vulnerabilities: vulns.slice(0, 30),
          }, null, 2),
        }],
      };
    }
  );

  // 5. scan_filesystem_grype — Scan filesystem via Grype
  server.tool(
    "scan_filesystem_grype",
    "Scan a local directory or file for vulnerabilities using Grype. Cross-validates against Trivy filesystem scans.",
    ScanFilesystemGrypeSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      // Grype uses dir: or file: prefix for local paths
      const source = params.path.endsWith("/")
        ? `dir:${params.path}`
        : `file:${params.path}`;
      const args = [
        source,
        "-o", "json",
      ];
      if (params.only_fixed) args.push("--only-fixed");

      const result = await runCommand("grype", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("matches")) {
        return {
          content: [{ type: "text", text: `Grype filesystem scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { matches, summary } = parseGrypeJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            path: params.path,
            engine: "grype",
            scan_summary: {
              total_vulnerabilities: totalVulns,
              critical: summary.Critical || 0,
              high: summary.High || 0,
              medium: summary.Medium || 0,
              low: summary.Low || 0,
            },
            vulnerabilities: matches.slice(0, 30).map((m: any) => ({
              id: m.vulnerability?.id || "N/A",
              package: m.artifact?.name || "N/A",
              installed_version: m.artifact?.version || "N/A",
              fixed_version: m.vulnerability?.fix?.versions?.[0] || "N/A",
              severity: m.vulnerability?.severity || "N/A",
            })),
          }, null, 2),
        }],
      };
    }
  );

  // 7. scan_remote_image — Pull and scan image from registry (no Docker daemon)
  server.tool(
    "scan_remote_image",
    "Scan a container image directly from a remote registry using Grype. No Docker daemon required — pulls the image manifest and layers directly.",
    ScanRemoteImageSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const args = [
        `registry:${params.image}`,
        "-o", "json",
      ];
      if (params.platform) args.push("--platform", params.platform);

      const result = await runCommand("grype", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("matches")) {
        return {
          content: [{ type: "text", text: `Grype remote scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { matches, summary } = parseGrypeJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            image: params.image,
            engine: "grype",
            source: "registry (no Docker daemon)",
            scan_summary: {
              total_vulnerabilities: totalVulns,
              critical: summary.Critical || 0,
              high: summary.High || 0,
              medium: summary.Medium || 0,
              low: summary.Low || 0,
            },
            vulnerabilities: matches.slice(0, 30).map((m: any) => ({
              id: m.vulnerability?.id || "N/A",
              package: m.artifact?.name || "N/A",
              installed_version: m.artifact?.version || "N/A",
              fixed_version: m.vulnerability?.fix?.versions?.[0] || "N/A",
              severity: m.vulnerability?.severity || "N/A",
            })),
          }, null, 2),
        }],
      };
    }
  );

  // 8. scan_purl — Look up vulnerabilities by Package URL
  server.tool(
    "scan_purl",
    "Look up known vulnerabilities for a specific package using its Package URL (PURL). Useful for checking if a specific dependency version is affected by any CVEs.",
    ScanPurlSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const args = [
        `purl:${params.purl}`,
        "-o", "json",
      ];

      const result = await runCommand("grype", args, 30_000);

      if (result.exitCode !== 0 && !result.stdout.includes("matches")) {
        return {
          content: [{ type: "text", text: `Grype PURL lookup failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { matches, summary } = parseGrypeJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            purl: params.purl,
            engine: "grype",
            scan_summary: {
              total_vulnerabilities: totalVulns,
              critical: summary.Critical || 0,
              high: summary.High || 0,
              medium: summary.Medium || 0,
              low: summary.Low || 0,
            },
            vulnerabilities: matches.map((m: any) => ({
              id: m.vulnerability?.id || "N/A",
              package: m.artifact?.name || "N/A",
              installed_version: m.artifact?.version || "N/A",
              fixed_version: m.vulnerability?.fix?.versions?.[0] || "N/A",
              severity: m.vulnerability?.severity || "N/A",
              description: m.vulnerability?.description?.substring(0, 200) || "",
            })),
          }, null, 2),
        }],
      };
    }
  );

  // 13. db_status — Check Grype vulnerability database status
  server.tool(
    "db_status",
    "Check the status of Grype's vulnerability database — last update time, database schema version, and whether an update is available.",
    DbStatusSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async () => {
      const result = await runCommand("grype", ["db", "status"], 10_000);

      return {
        content: [{
          type: "text",
          text: result.stdout || `Error checking DB status: ${result.stderr}`,
        }],
      };
    }
  );

  // 14. update_db — Update Grype vulnerability database
  server.tool(
    "update_db",
    "Update Grype's vulnerability database to the latest version. Recommended before scanning if the DB hasn't been updated recently.",
    UpdateDbSchema.shape,
    { readOnlyHint: false, openWorldHint: false },
    async () => {
      const result = await runCommand("grype", ["db", "update"], 120_000);

      return {
        content: [{
          type: "text",
          text: result.stdout || `DB update result: exit code ${result.exitCode}\n${result.stderr}`,
        }],
      };
    }
  );

  // 15. get_version — Get versions of both engines
  server.tool(
    "get_version",
    "Get version information for installed security scanning engines (Trivy and/or Grype).",
    GetVersionSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async () => {
      const versions: Record<string, string> = {};

      const trivyCheck = await runCommand("trivy", ["version"], 5000);
      if (trivyCheck.exitCode === 0) {
        versions.trivy = trivyCheck.stdout;
      } else {
        versions.trivy = "not installed";
      }

      const grypeCheck = await runCommand("grype", ["version"], 5000);
      if (grypeCheck.exitCode === 0) {
        versions.grype = grypeCheck.stdout;
      } else {
        versions.grype = "not installed";
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify(versions, null, 2),
        }],
      };
    }
  );
}
