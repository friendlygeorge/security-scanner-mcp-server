import { describe, it, expect } from "vitest";
import { parseTrivyJson, parseGrypeJson, formatVulnTable } from "../src/engines.js";

describe("parseTrivyJson", () => {
  it("parses valid Trivy JSON output", () => {
    const output = JSON.stringify({
      Results: [
        {
          Target: "alpine:3.18",
          Vulnerabilities: [
            { VulnerabilityID: "CVE-2023-1234", PkgName: "musl", InstalledVersion: "1.2.3", FixedVersion: "1.2.4", Severity: "HIGH", Title: "Test vuln" },
            { VulnerabilityID: "CVE-2023-5678", PkgName: "busybox", InstalledVersion: "1.36", FixedVersion: "", Severity: "MEDIUM", Title: "Another vuln" },
          ],
        },
      ],
    });

    const { results, summary } = parseTrivyJson(output);
    expect(results).toHaveLength(1);
    expect(results[0].Target).toBe("alpine:3.18");
    expect(summary.HIGH).toBe(1);
    expect(summary.MEDIUM).toBe(1);
    expect(summary.CRITICAL).toBe(0);
  });

  it("handles empty/invalid JSON", () => {
    const { results, summary } = parseTrivyJson("not json");
    expect(results).toHaveLength(0);
    expect(summary).toEqual({});
  });

  it("handles missing Vulnerabilities array", () => {
    const output = JSON.stringify({ Results: [{ Target: "test" }] });
    const { results, summary } = parseTrivyJson(output);
    expect(results).toHaveLength(1);
    expect(summary.CRITICAL).toBe(0);
  });
});

describe("parseGrypeJson", () => {
  it("parses valid Grype JSON output", () => {
    const output = JSON.stringify({
      matches: [
        {
          vulnerability: { id: "CVE-2023-1234", severity: "High", fix: { versions: ["1.2.4"] } },
          artifact: { name: "musl", version: "1.2.3" },
        },
        {
          vulnerability: { id: "CVE-2023-5678", severity: "Critical", fix: { versions: [] } },
          artifact: { name: "openssl", version: "3.0.0" },
        },
      ],
    });

    const { matches, summary } = parseGrypeJson(output);
    expect(matches).toHaveLength(2);
    expect(summary.High).toBe(1);
    expect(summary.Critical).toBe(1);
  });

  it("handles empty matches", () => {
    const { matches, summary } = parseGrypeJson("{}");
    expect(matches).toHaveLength(0);
  });
});

describe("formatVulnTable", () => {
  it("returns 'No vulnerabilities found' for empty array", () => {
    expect(formatVulnTable([])).toBe("No vulnerabilities found.");
  });

  it("truncates at maxRows", () => {
    const vulns = Array.from({ length: 50 }, (_, i) => ({
      VulnerabilityID: `CVE-2023-${i}`,
      PkgName: `pkg-${i}`,
      InstalledVersion: "1.0",
      FixedVersion: "1.1",
      Severity: "HIGH",
      Title: `Vuln ${i}`,
    }));

    const table = formatVulnTable(vulns, 10);
    expect(table).toContain("... and 40 more");
    expect(table.split("\n")).toHaveLength(13); // header + separator + 10 rows + truncation
  });
});
