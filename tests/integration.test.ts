import { describe, it, expect } from "vitest";
import { runCommand, checkBinary, parseTrivyJson, parseGrypeJson } from "../src/engines.js";
import { execSync } from "child_process";

const TRIVY_AVAILABLE = (() => {
  try {
    execSync("which trivy", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

const GRYPE_AVAILABLE = (() => {
  try {
    execSync("which grype", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

describe("runCommand", () => {
  it("runs a simple command successfully", async () => {
    const result = await runCommand("echo", ["hello world"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("hello world");
  });

  it("returns non-zero exit code on failure", async () => {
    const result = await runCommand("false", []);
    expect(result.exitCode).not.toBe(0);
  });

  it("captures stderr", async () => {
    const result = await runCommand("sh", ["-c", "echo errormsg >&2"]);
    expect(result.stderr).toContain("errormsg");
  });

  it("handles timeout gracefully", async () => {
    const result = await runCommand("sleep", ["10"], 100);
    expect(result.exitCode).not.toBe(0);
  }, 500);

  it("returns empty stdout for commands with no output", async () => {
    const result = await runCommand("true", []);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("");
  });
});

describe("checkBinary", () => {
  it("returns true for an existing binary", async () => {
    expect(await checkBinary("sh")).toBe(true);
  });

  it("returns false for a nonexistent binary", async () => {
    expect(await checkBinary("nonexistent-binary-xyz-12345")).toBe(false);
  });
});

describe("Trivy integration (real engine)", () => {
  it("detects trivy binary", async () => {
    const available = await checkBinary("trivy");
    expect(available).toBe(TRIVY_AVAILABLE);
  });

  it.runIf(TRIVY_AVAILABLE)("trivy version returns valid output", async () => {
    const result = await runCommand("trivy", ["--version"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/Version:|v\d+\.\d+/);
  });

  it.runIf(TRIVY_AVAILABLE)(
    "trivy scans alpine:3.16 and finds vulnerabilities at CRITICAL,HIGH,MEDIUM",
    async () => {
      const result = await runCommand(
        "trivy",
        ["image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", "--no-progress", "--quiet", "alpine:3.16"],
        120_000
      );
      expect(result.exitCode).toBe(0);

      const { results, summary } = parseTrivyJson(result.stdout);
      expect(results.length).toBeGreaterThan(0);

      const totalVulns = summary.CRITICAL + summary.HIGH + summary.MEDIUM;
      expect(totalVulns).toBeGreaterThan(0);

      // Each result should have a Target
      for (const r of results) {
        expect(r.Target).toBeTruthy();
      }
    },
    180_000
  );

  it.runIf(TRIVY_AVAILABLE)(
    "trivy filesystem scan on package.json returns valid output",
    async () => {
      const result = await runCommand(
        "trivy",
        ["fs", "--format", "json", "--severity", "CRITICAL,HIGH", "--no-progress", "--quiet", "."],
        60_000
      );
      expect(result.exitCode).toBe(0);

      const parsed = JSON.parse(result.stdout);
      expect(parsed).toHaveProperty("Results");
      expect(Array.isArray(parsed.Results)).toBe(true);
    },
    90_000
  );
});

describe("Grype integration (real engine)", () => {
  it("detects grype binary", async () => {
    const available = await checkBinary("grype");
    expect(available).toBe(GRYPE_AVAILABLE);
  });

  it.runIf(GRYPE_AVAILABLE)("grype version returns valid output", async () => {
    const result = await runCommand("grype", ["version"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/v\d+\.\d+/);
  });

  it.runIf(GRYPE_AVAILABLE)(
    "grype scans alpine:3.16 and returns matches",
    async () => {
      const result = await runCommand(
        "grype",
        ["alpine:3.16", "-o", "json"],
        120_000
      );
      expect(result.exitCode).toBe(0);

      const { matches, summary } = parseGrypeJson(result.stdout);
      expect(matches.length).toBeGreaterThan(0);

      const totalVulns = (summary.Critical || 0) + (summary.High || 0) + (summary.Medium || 0);
      expect(totalVulns).toBeGreaterThan(0);

      // Each match should have a vulnerability ID
      for (const m of matches) {
        expect(m.vulnerability?.id).toBeTruthy();
        expect(m.artifact?.name).toBeTruthy();
      }
    },
    180_000
  );
});

describe("Cross-engine validation", () => {
  it.runIf(TRIVY_AVAILABLE && GRYPE_AVAILABLE)(
    "both engines find vulnerabilities in alpine:3.16",
    async () => {
      const [trivyResult, grypeResult] = await Promise.all([
        runCommand(
          "trivy",
          ["image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM", "--no-progress", "--quiet", "alpine:3.16"],
          120_000
        ),
        runCommand(
          "grype",
          ["alpine:3.16", "-o", "json"],
          120_000
        ),
      ]);

      const trivyParsed = parseTrivyJson(trivyResult.stdout);
      const grypeParsed = parseGrypeJson(grypeResult.stdout);

      // Both should find vulns
      expect(trivyParsed.results.length).toBeGreaterThan(0);
      expect(grypeParsed.matches.length).toBeGreaterThan(0);

      // Both should find the same CVE IDs (at least some overlap)
      const trivyCVEs = new Set<string>();
      for (const r of trivyParsed.results) {
        for (const v of r.Vulnerabilities || []) {
          if (v.VulnerabilityID) trivyCVEs.add(v.VulnerabilityID);
        }
      }
      const grypeCVEs = new Set(
        grypeParsed.matches.map((m: any) => m.vulnerability?.id).filter(Boolean)
      );

      const overlap = Array.from(trivyCVEs).filter((cve) => grypeCVEs.has(cve));
      // Should share at least 1 CVE (both scan the same image)
      expect(overlap.length).toBeGreaterThan(0);
    },
    300_000
  );
});
