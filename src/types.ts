import { z } from "zod";

// --- Shared schemas ---

export const SeveritySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const OutputFormatSchema = z.enum(["json", "table", "sarif", "cyclonedx", "spdx"]);
export type OutputFormat = z.infer<typeof OutputFormatSchema>;

// --- Tool schemas ---

// 1. scan_image (Trivy)
export const ScanImageSchema = z.object({
  image: z.string().describe("Docker image name (e.g. 'nginx', 'ubuntu:22.04')"),
  tag: z.string().optional().describe("Image tag (appended to image if provided)"),
  severity: z.string().optional().describe("Comma-separated severities to filter (default: CRITICAL,HIGH,MEDIUM)"),
  ignore_unfixed: z.boolean().optional().describe("Ignore vulnerabilities without a fix version"),
  timeout: z.number().optional().describe("Scan timeout in seconds (default: 120)"),
});

// 2. scan_image_grype (Grype)
export const ScanImageGrypeSchema = z.object({
  image: z.string().describe("Docker image reference (e.g. 'nginx:latest', 'docker:ubuntu')"),
  severity: z.string().optional().describe("Minimum severity to report (default: critical,high,medium)"),
  only_fixed: z.boolean().optional().describe("Only show vulnerabilities with fixes available"),
  fail_on: z.string().optional().describe("Exit with error if finding meets this severity (critical, high, medium, low, negligible)"),
  timeout: z.number().optional().describe("Scan timeout in seconds (default: 120)"),
});

// 3. vulnerability_report (Trivy)
export const VulnerabilityReportSchema = z.object({
  image: z.string().describe("Docker image name"),
  tag: z.string().optional().describe("Image tag"),
  severity: z.string().optional().describe("Severities to include (default: CRITICAL,HIGH,MEDIUM,LOW)"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 180)"),
});

// 4. scan_filesystem (Trivy)
export const ScanFilesystemSchema = z.object({
  path: z.string().describe("Local directory or file path to scan"),
  severity: z.string().optional().describe("Severities to filter (default: CRITICAL,HIGH,MEDIUM)"),
  scanners: z.string().optional().describe("Scanner types: vuln,misconfig,secret,license (default: vuln,misconfig,secret)"),
  ignore_unfixed: z.boolean().optional().describe("Ignore vulnerabilities without fixes"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 120)"),
});

// 5. scan_filesystem_grype (Grype)
export const ScanFilesystemGrypeSchema = z.object({
  path: z.string().describe("Directory or file path to scan (uses dir: or file: source)"),
  severity: z.string().optional().describe("Minimum severity (default: critical,high,medium)"),
  only_fixed: z.boolean().optional().describe("Only show fixable vulnerabilities"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 120)"),
});

// 6. scan_repository (Trivy)
export const ScanRepositorySchema = z.object({
  url: z.string().describe("Git repository URL or local path"),
  branch: z.string().optional().describe("Branch to scan (default: HEAD)"),
  severity: z.string().optional().describe("Severities to filter"),
  scanners: z.string().optional().describe("Scanner types: vuln,misconfig,secret,license"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 180)"),
});

// 7. scan_remote_image (Grype)
export const ScanRemoteImageSchema = z.object({
  image: z.string().describe("Full image reference including registry (e.g. 'registry.io/org/image:tag')"),
  platform: z.string().optional().describe("Platform to scan (e.g. 'linux/amd64')"),
  severity: z.string().optional().describe("Minimum severity"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 120)"),
});

// 8. scan_purl (Grype)
export const ScanPurlSchema = z.object({
  purl: z.string().describe("Package URL to look up (e.g. 'pkg:npm/lodash@4.17.21')"),
  severity: z.string().optional().describe("Minimum severity"),
});

// 9. scan_sbom (Trivy)
export const ScanSbomSchema = z.object({
  sbom_path: z.string().describe("Path to SBOM file (CycloneDX or SPDX format)"),
  severity: z.string().optional().describe("Severities to filter"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 120)"),
});

// 10. generate_sbom (Trivy)
export const GenerateSbomSchema = z.object({
  image: z.string().describe("Docker image to generate SBOM for"),
  tag: z.string().optional().describe("Image tag"),
  format: z.enum(["cyclonedx", "spdx", "spdx-json"]).optional().describe("SBOM output format (default: cyclonedx)"),
  output: z.string().optional().describe("File path to write SBOM (if omitted, returns in response)"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 120)"),
});

// 11. scan_config (Trivy)
export const ScanConfigSchema = z.object({
  path: z.string().describe("Path to IaC files (Terraform, Dockerfile, Kubernetes manifests, CloudFormation)"),
  severity: z.string().optional().describe("Severities to filter"),
  scanners: z.string().optional().describe("Scanner types: misconfig,secret (default: misconfig,secret)"),
  timeout: z.number().optional().describe("Timeout in seconds (default: 120)"),
});

// 12. cross_validate (Trivy + Grype)
export const CrossValidateSchema = z.object({
  image: z.string().describe("Docker image to scan with both engines"),
  tag: z.string().optional().describe("Image tag"),
  severity: z.string().optional().describe("Severities to compare (default: CRITICAL,HIGH,MEDIUM)"),
  timeout: z.number().optional().describe("Timeout per engine in seconds (default: 120)"),
});

// 13. db_status (Grype)
export const DbStatusSchema = z.object({});

// 14. update_db (Grype)
export const UpdateDbSchema = z.object({});

// 15. get_version (Both)
export const GetVersionSchema = z.object({});

// --- Response types ---

export interface Vulnerability {
  id: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  severity: string;
  title: string;
  description?: string;
}

export interface ScanResult {
  engine: "trivy" | "grype";
  target: string;
  summary: Record<string, number>;
  vulnerabilities: Vulnerability[];
  fixable_count: number;
}

export interface CrossValidationResult {
  image: string;
  trivy: ScanResult;
  grype: ScanResult;
  divergence: {
    only_in_trivy: string[];
    only_in_grype: string[];
    severity_mismatch: Array<{ cve: string; trivy_severity: string; grype_severity: string }>;
  };
  combined_summary: Record<string, number>;
}
