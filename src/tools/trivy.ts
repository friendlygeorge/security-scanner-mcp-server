import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { writeFile } from "fs/promises";
import {
  ScanImageSchema,
  VulnerabilityReportSchema,
  ScanFilesystemSchema,
  ScanRepositorySchema,
  ScanSbomSchema,
  GenerateSbomSchema,
  ScanConfigSchema,
} from "../types.js";
import {
  runCommand,
  parseTrivyJson,
  formatVulnTable,
} from "../engines.js";

/**
 * Register all Trivy-based tools on the MCP server.
 */
export function registerTrivyTools(server: McpServer): void {
  // 1. scan_image — Scan a Docker image for vulnerabilities
  server.tool(
    "scan_image",
    "Scan a Docker image for known vulnerabilities using Trivy. Returns a summary of critical/high/medium/low vulnerabilities with package names and fix availability.",
    ScanImageSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const imageRef = params.tag ? `${params.image}:${params.tag}` : params.image;
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM";
      const args = [
        "image", "--format", "json",
        "--severity", severity,
        "--no-progress", "--quiet",
      ];
      if (params.ignore_unfixed) args.push("--ignore-unfixed");
      args.push(imageRef);

      const result = await runCommand("trivy", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("Vulnerability")) {
        return {
          content: [{ type: "text", text: `Trivy scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { results, summary } = parseTrivyJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      const allVulns: any[] = [];
      for (const r of results) {
        for (const v of r.Vulnerabilities || []) {
          allVulns.push(v);
        }
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            image: imageRef,
            engine: "trivy",
            scan_summary: {
              total_vulnerabilities: totalVulns,
              critical: summary.CRITICAL || 0,
              high: summary.HIGH || 0,
              medium: summary.MEDIUM || 0,
              low: summary.LOW || 0,
              unknown: summary.UNKNOWN || 0,
            },
            targets: results.map((r: any) => r.Target),
            critical_vulns: allVulns.filter((v: any) => v.Severity === "CRITICAL").slice(0, 10),
            high_vulns: allVulns.filter((v: any) => v.Severity === "HIGH").slice(0, 10),
          }, null, 2),
        }],
      };
    }
  );

  // 3. vulnerability_report — Detailed vulnerability report with remediation
  server.tool(
    "vulnerability_report",
    "Generate a detailed vulnerability report for a Docker image with remediation recommendations (which packages to upgrade). More detailed than scan_image.",
    VulnerabilityReportSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const imageRef = params.tag ? `${params.image}:${params.tag}` : params.image;
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM,LOW";
      const args = [
        "image", "--format", "json",
        "--severity", severity,
        "--no-progress", "--quiet",
        imageRef,
      ];

      const result = await runCommand("trivy", args, (params.timeout || 180) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("Vulnerability")) {
        return {
          content: [{ type: "text", text: `Trivy report failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { results, summary } = parseTrivyJson(result.stdout);
      const allVulns: any[] = [];
      for (const r of results) {
        for (const v of r.Vulnerabilities || []) {
          allVulns.push(v);
        }
      }

      // Build remediation list
      const fixable = allVulns
        .filter((v: any) => v.FixedVersion && v.FixedVersion !== "N/A")
        .reduce((acc: any, v: any) => {
          const key = `${v.PkgName}@${v.InstalledVersion}`;
          if (!acc[key]) {
            acc[key] = {
              package: v.PkgName,
              current_version: v.InstalledVersion,
              fix_version: v.FixedVersion,
              vulnerabilities: [],
              highest_severity: v.Severity,
            };
          }
          acc[key].vulnerabilities.push(v.VulnerabilityID);
          const sevOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
          if ((sevOrder[v.Severity] || 0) > (sevOrder[acc[key].highest_severity] || 0)) {
            acc[key].highest_severity = v.Severity;
          }
          return acc;
        }, {});

      const remediation = Object.values(fixable)
        .sort((a: any, b: any) => {
          const sevOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
          return (sevOrder[b.highest_severity] || 0) - (sevOrder[a.highest_severity] || 0);
        });

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            image: imageRef,
            engine: "trivy",
            report_summary: {
              total_vulnerabilities: allVulns.length,
              critical: summary.CRITICAL || 0,
              high: summary.HIGH || 0,
              medium: summary.MEDIUM || 0,
              low: summary.LOW || 0,
              fixable_packages: remediation.length,
            },
            remediation: remediation.slice(0, 20),
            detailed_vulnerabilities: formatVulnTable(allVulns),
          }, null, 2),
        }],
      };
    }
  );

  // 4. scan_filesystem — Scan local directory/files for vulnerabilities and misconfigs
  server.tool(
    "scan_filesystem",
    "Scan a local directory or file for vulnerabilities, misconfigurations, and secrets using Trivy. Supports Dockerfiles, Terraform, Kubernetes manifests, and application dependencies.",
    ScanFilesystemSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM";
      const scanners = params.scanners || "vuln,misconfig,secret";
      const args = [
        "fs", "--format", "json",
        "--severity", severity,
        "--scanners", scanners,
        "--no-progress", "--quiet",
      ];
      if (params.ignore_unfixed) args.push("--ignore-unfixed");
      args.push(params.path);

      const result = await runCommand("trivy", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("Vulnerability") && !result.stdout.includes("Misconfig")) {
        return {
          content: [{ type: "text", text: `Trivy fs scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { results, summary } = parseTrivyJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            path: params.path,
            engine: "trivy",
            scan_summary: {
              total_findings: totalVulns,
              critical: summary.CRITICAL || 0,
              high: summary.HIGH || 0,
              medium: summary.MEDIUM || 0,
              low: summary.LOW || 0,
            },
            targets: results.map((r: any) => r.Target),
            findings: formatVulnTable(
              results.reduce((acc: any[], r: any) => acc.concat(r.Vulnerabilities || []), [] as any[])
            ),
          }, null, 2),
        }],
      };
    }
  );

  // 6. scan_repository — Scan a git repository
  server.tool(
    "scan_repository",
    "Scan a git repository (local or remote URL) for vulnerabilities, misconfigurations, and secrets using Trivy.",
    ScanRepositorySchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM";
      const scanners = params.scanners || "vuln,misconfig,secret";
      const args = [
        "repository", "--format", "json",
        "--severity", severity,
        "--scanners", scanners,
        "--no-progress", "--quiet",
      ];
      if (params.branch) args.push("--branch", params.branch);
      args.push(params.url);

      const result = await runCommand("trivy", args, (params.timeout || 180) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("Vulnerability")) {
        return {
          content: [{ type: "text", text: `Trivy repo scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { results, summary } = parseTrivyJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            repository: params.url,
            engine: "trivy",
            scan_summary: {
              total_findings: totalVulns,
              critical: summary.CRITICAL || 0,
              high: summary.HIGH || 0,
              medium: summary.MEDIUM || 0,
              low: summary.LOW || 0,
            },
            targets: results.map((r: any) => r.Target),
            findings: formatVulnTable(
              results.reduce((acc: any[], r: any) => acc.concat(r.Vulnerabilities || []), [] as any[])
            ),
          }, null, 2),
        }],
      };
    }
  );

  // 9. scan_sbom — Scan an SBOM file for vulnerabilities
  server.tool(
    "scan_sbom",
    "Scan a Software Bill of Materials (SBOM) file for known vulnerabilities. Accepts CycloneDX or SPDX format SBOMs.",
    ScanSbomSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM";
      const args = [
        "sbom", "--format", "json",
        "--severity", severity,
        "--no-progress", "--quiet",
        params.sbom_path,
      ];

      const result = await runCommand("trivy", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("Vulnerability")) {
        return {
          content: [{ type: "text", text: `Trivy SBOM scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { results, summary } = parseTrivyJson(result.stdout);
      const totalVulns = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            sbom: params.sbom_path,
            engine: "trivy",
            scan_summary: {
              total_vulnerabilities: totalVulns,
              critical: summary.CRITICAL || 0,
              high: summary.HIGH || 0,
              medium: summary.MEDIUM || 0,
              low: summary.LOW || 0,
            },
            targets: results.map((r: any) => r.Target),
            vulnerabilities: formatVulnTable(
              results.reduce((acc: any[], r: any) => acc.concat(r.Vulnerabilities || []), [] as any[])
            ),
          }, null, 2),
        }],
      };
    }
  );

  // 10. generate_sbom — Generate an SBOM from a Docker image
  server.tool(
    "generate_sbom",
    "Generate a Software Bill of Materials (SBOM) for a Docker image in CycloneDX or SPDX format. The SBOM lists all packages and dependencies in the image.",
    GenerateSbomSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const imageRef = params.tag ? `${params.image}:${params.tag}` : params.image;
      const format = params.format || "cyclonedx";
      const args = [
        "sbom", "--format", format,
        "--no-progress", "--quiet",
        imageRef,
      ];

      const result = await runCommand("trivy", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0) {
        return {
          content: [{ type: "text", text: `SBOM generation failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      // If output path specified, write to file
      if (params.output) {
        
        await writeFile(params.output, result.stdout);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              image: imageRef,
              format,
              output_file: params.output,
              size_bytes: result.stdout.length,
            }, null, 2),
          }],
        };
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            image: imageRef,
            format,
            sbom: JSON.parse(result.stdout),
          }, null, 2),
        }],
      };
    }
  );

  // 11. scan_config — Scan IaC for misconfigurations
  server.tool(
    "scan_config",
    "Scan Infrastructure-as-Code files for misconfigurations and security issues. Supports Terraform, Dockerfile, Kubernetes manifests, CloudFormation, Helm charts, and more.",
    ScanConfigSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM";
      const scanners = params.scanners || "misconfig,secret";
      const args = [
        "config", "--format", "json",
        "--severity", severity,
        "--scanners", scanners,
        "--no-progress", "--quiet",
        params.path,
      ];

      const result = await runCommand("trivy", args, (params.timeout || 120) * 1000);

      if (result.exitCode !== 0 && !result.stdout.includes("Misconfig")) {
        return {
          content: [{ type: "text", text: `Trivy config scan failed (exit code ${result.exitCode}):\n${result.stderr.substring(0, 2000)}` }],
          isError: true,
        };
      }

      const { results, summary } = parseTrivyJson(result.stdout);
      const totalFindings = Object.values(summary).reduce((a, b) => a + b, 0);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            path: params.path,
            engine: "trivy",
            scan_summary: {
              total_misconfigs: totalFindings,
              critical: summary.CRITICAL || 0,
              high: summary.HIGH || 0,
              medium: summary.MEDIUM || 0,
              low: summary.LOW || 0,
            },
            targets: results.map((r: any) => r.Target),
            misconfigurations: formatVulnTable(
              results.reduce((acc: any[], r: any) => acc.concat(r.Vulnerabilities || r.Misconfigurations || []), [] as any[])
            ),
          }, null, 2),
        }],
      };
    }
  );
}
