import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface EngineResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * Run a CLI command with timeout and return structured result.
 */
export async function runCommand(
  command: string,
  args: string[],
  timeoutMs: number = 120_000
): Promise<EngineResult> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: timeoutMs,
      maxBuffer: 50 * 1024 * 1024, // 50MB
    });
    return { exitCode: 0, stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (error: any) {
    return {
      exitCode: error.code || 1,
      stdout: error.stdout?.toString()?.trim() || "",
      stderr: error.stderr?.toString()?.trim() || error.message,
    };
  }
}

/**
 * Check if a binary is available on the system.
 */
export async function checkBinary(name: string): Promise<boolean> {
  const result = await runCommand("which", [name], 5000);
  return result.exitCode === 0;
}

/**
 * Parse Trivy JSON output into structured vulnerabilities.
 */
export function parseTrivyJson(output: string): {
  results: Array<{ Target: string; Vulnerabilities?: any[] }>;
  summary: Record<string, number>;
} {
  try {
    const data = JSON.parse(output);
    const results = data.Results || [];
    const summary: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };

    for (const result of results) {
      for (const vuln of result.Vulnerabilities || []) {
        const sev = (vuln.Severity || "UNKNOWN").toUpperCase();
        summary[sev] = (summary[sev] || 0) + 1;
      }
    }
    return { results, summary };
  } catch {
    return { results: [], summary: {} };
  }
}

/**
 * Parse Grype JSON output into structured vulnerabilities.
 */
export function parseGrypeJson(output: string): {
  matches: any[];
  summary: Record<string, number>;
} {
  try {
    const data = JSON.parse(output);
    const matches = data.matches || [];
    const summary: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };

    for (const match of matches) {
      const sev = match.vulnerability?.severity || "Unknown";
      summary[sev] = (summary[sev] || 0) + 1;
    }
    return { matches, summary };
  } catch {
    return { matches: [], summary: {} };
  }
}

/**
 * Format a table of vulnerabilities for text output.
 */
export function formatVulnTable(vulns: any[], maxRows: number = 30): string {
  if (vulns.length === 0) return "No vulnerabilities found.";

  const lines = ["ID | Package | Installed | Fixed | Severity | Title"];
  lines.push("---|---------|-----------|-------|----------|-----");

  for (const v of vulns.slice(0, maxRows)) {
    const id = v.VulnerabilityID || v.id || "N/A";
    const pkg = v.PkgName || v.package || "N/A";
    const installed = v.InstalledVersion || v.installed_version || "N/A";
    const fixed = v.FixedVersion || v.fixed_version || "N/A";
    const severity = v.Severity || v.severity || "N/A";
    const title = (v.Title || v.title || "").substring(0, 60);
    lines.push(`${id} | ${pkg} | ${installed} | ${fixed} | ${severity} | ${title}`);
  }

  if (vulns.length > maxRows) {
    lines.push(`... and ${vulns.length - maxRows} more`);
  }

  return lines.join("\n");
}
