import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CrossValidateSchema } from "../types.js";
import {
  runCommand,
  parseTrivyJson,
  parseGrypeJson,
} from "../engines.js";

/**
 * Register the cross-validation tool — the key differentiator.
 * Runs both Trivy and Grype on the same target and surfaces divergence.
 */
export function registerCrossValidateTool(server: McpServer): void {
  server.tool(
    "cross_validate",
    "Scan a Docker image with BOTH Trivy and Grype, then compare results. Surfaces vulnerabilities found by only one engine (different databases = different coverage). This is the key differentiator — no other MCP server offers multi-engine cross-validation.",
    CrossValidateSchema.shape,
    { readOnlyHint: true, openWorldHint: false },
    async (params) => {
      const imageRef = params.tag ? `${params.image}:${params.tag}` : params.image;
      const timeoutMs = (params.timeout || 120) * 1000;
      const severity = params.severity || "CRITICAL,HIGH,MEDIUM";

      // Run both engines in parallel
      const trivyPromise = runCommand("trivy", [
        "image", "--format", "json",
        "--severity", severity,
        "--no-progress", "--quiet",
        imageRef,
      ], timeoutMs);

      const grypePromise = runCommand("grype", [
        imageRef,
        "-o", "json",
      ], timeoutMs);

      const [trivyResult, grypeResult] = await Promise.all([trivyPromise, grypePromise]);

      // Parse Trivy results
      const trivyParsed = parseTrivyJson(trivyResult.stdout);
      const trivyVulns: any[] = [];
      for (const r of trivyParsed.results) {
        for (const v of r.Vulnerabilities || []) {
          trivyVulns.push(v);
        }
      }
      const trivyIds = new Set(trivyVulns.map((v: any) => v.VulnerabilityID));

      // Parse Grype results
      const grypeParsed = parseGrypeJson(grypeResult.stdout);
      const grypeVulns = grypeParsed.matches.map((m: any) => ({
        id: m.vulnerability?.id || "N/A",
        package: m.artifact?.name || "N/A",
        installed_version: m.artifact?.version || "N/A",
        fixed_version: m.vulnerability?.fix?.versions?.[0] || "N/A",
        severity: m.vulnerability?.severity || "N/A",
      }));
      const grypeIds = new Set(grypeVulns.map((v: any) => v.id));

      // Find divergence
      const onlyInTrivy = trivyVulns
        .filter((v: any) => !grypeIds.has(v.VulnerabilityID))
        .map((v: any) => v.VulnerabilityID);
      const onlyInGrype = grypeVulns
        .filter((v: any) => !trivyIds.has(v.id))
        .map((v: any) => v.id);

      // Find severity mismatches (same CVE, different severity)
      const trivySeverityMap = new Map(trivyVulns.map((v: any) => [v.VulnerabilityID, v.Severity]));
      const severityMismatch = grypeVulns
        .filter((v: any) => trivySeverityMap.has(v.id) && trivySeverityMap.get(v.id) !== v.severity)
        .map((v: any) => ({
          cve: v.id,
          trivy_severity: trivySeverityMap.get(v.id),
          grype_severity: v.severity,
        }));

      // Combined summary
      const combined: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
      const allIds = new Set([...trivyIds, ...grypeIds]);
      for (const id of allIds) {
        const sev = trivySeverityMap.get(id) || "UNKNOWN";
        combined[sev] = (combined[sev] || 0) + 1;
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            image: imageRef,
            engines: { trivy: trivyResult.exitCode === 0 ? "ok" : "failed", grype: grypeResult.exitCode === 0 ? "ok" : "failed" },
            combined_summary: {
              total_unique_cves: allIds.size,
              critical: combined.CRITICAL,
              high: combined.HIGH,
              medium: combined.MEDIUM,
              low: combined.LOW,
            },
            trivy_summary: trivyParsed.summary,
            grype_summary: grypeParsed.summary,
            divergence: {
              only_in_trivy_count: onlyInTrivy.length,
              only_in_grype_count: onlyInGrype.length,
              severity_mismatches: severityMismatch.length,
              only_in_trivy: onlyInTrivy.slice(0, 20),
              only_in_grype: onlyInGrype.slice(0, 20),
              severity_mismatch_details: severityMismatch.slice(0, 10),
            },
            insight: onlyInTrivy.length > 0 && onlyInGrype.length > 0
              ? `Cross-validation found ${onlyInTrivy.length} CVEs only in Trivy and ${onlyInGrype.length} only in Grype. Using both engines gives broader coverage than either alone.`
              : onlyInTrivy.length > 0
              ? `Grype missed ${onlyInTrivy.length} CVEs that Trivy found. Trivy's database appears more comprehensive for this image.`
              : onlyInGrype.length > 0
              ? `Trivy missed ${onlyInGrype.length} CVEs that Grype found. Grype's database appears more comprehensive for this image.`
              : "Both engines agree on all findings — high confidence in coverage.",
          }, null, 2),
        }],
      };
    }
  );
}
