import pc from "picocolors";
import type { ScanReport, Severity } from "./types";

function colorSeverity(sev: Severity): string {
  switch (sev) {
    case "CRITICAL":
      return pc.bgRed(pc.white(pc.bold(` ${sev} `)));
    case "HIGH":
      return pc.red(pc.bold(sev));
    case "MEDIUM":
      return pc.yellow(pc.bold(sev));
    case "LOW":
      return pc.green(pc.bold(sev));
  }
}

export function formatTerminalReport(report: ScanReport, showSuppressed = false): string {
  const lines: string[] = [];
  const rec = report.risk_assessment.recommendation;
  const recBadge =
    rec === "SAFE"
      ? pc.bgGreen(pc.black(pc.bold(" SAFE TO INSTALL ")))
      : rec === "CAUTION"
        ? pc.bgYellow(pc.black(pc.bold(" CAUTION — REVIEW REQUIRED ")))
        : pc.bgRed(pc.white(pc.bold(" DO NOT INSTALL ")));

  lines.push("");
  lines.push(pc.bold(pc.cyan("╭──────────────────────────────────────────────────────────────────────────────╮")));
  lines.push(
    pc.bold(pc.cyan("│")) +
      ` ${pc.bold("SkillSpectator Security Report")}                              ${pc.dim(`v${report.metadata.skillspectator_version} (Bun)`)} ` +
      pc.bold(pc.cyan("│")),
  );
  lines.push(pc.bold(pc.cyan("╰──────────────────────────────────────────────────────────────────────────────╯")));
  lines.push("");
  lines.push(`${pc.dim("Skill:")}     ${pc.bold(report.skill.name)}`);
  lines.push(`${pc.dim("Source:")}    ${report.skill.source}`);
  lines.push(`${pc.dim("Scanned:")}   ${report.skill.scanned_at} ${pc.dim(`(${report.skill.duration_ms} ms · ${report.metadata.scan_mode})`)}`);
  lines.push("");
  lines.push(`${pc.bold("Risk Score:")}     ${pc.bold(`${report.risk_assessment.score}/100`)}  (${colorSeverity(report.risk_assessment.severity)})`);
  lines.push(`${pc.bold("Verdict:")}        ${recBadge}`);
  lines.push(
    `${pc.bold("Coverage:")}       ${report.inspection_completeness.coverage_percent}% (${report.inspection_completeness.scanned_components}/${report.inspection_completeness.total_components} files · status: ${report.inspection_completeness.status})`,
  );
  lines.push("");

  lines.push(pc.bold(`Components (${report.components.length})`));
  for (const c of report.components) {
    const execTag = c.executable ? pc.yellow(" [exec]") : "";
    lines.push(`  • ${c.path} ${pc.dim(`(${c.type}, ${c.lines} lines, ${c.size_bytes} B)`)}${execTag}`);
  }
  lines.push("");

  if (report.issues.length === 0) {
    lines.push(pc.green("✔ No active security issues detected."));
  } else {
    lines.push(pc.bold(`Active Issues (${report.issues.length})`));
    lines.push("");
    for (const issue of report.issues) {
      lines.push(`  ${colorSeverity(issue.severity)}  ${pc.bold(`${issue.id} — ${issue.pattern}`)} ${pc.dim(`[${issue.category}]`)}`);
      lines.push(`    ${pc.dim("Location:")}    ${issue.location.file}:${issue.location.start_line} ${pc.dim(`(confidence ${Math.round(issue.confidence * 100)}%)`)}`);
      lines.push(`    ${pc.dim("Evidence:")}    ${issue.finding}`);
      lines.push(`    ${pc.dim("Explanation:")} ${issue.explanation}`);
      lines.push(`    ${pc.dim("Remediation:")} ${pc.cyan(issue.remediation)}`);
      lines.push("");
    }
  }

  if (report.suppressed.length > 0) {
    lines.push(pc.dim(`Suppressed by baseline: ${report.suppressed.length} (excluded from risk score)`));
    if (showSuppressed) {
      for (const s of report.suppressed) {
        lines.push(pc.dim(`  - ${s.id} ${s.location.file}:${s.location.start_line} (reason: ${s.suppression_reason})`));
      }
    }
    lines.push("");
  }

  return lines.join("\n");
}

export function formatMarkdownReport(report: ScanReport): string {
  const md: string[] = [];
  md.push(`# SkillSpectator Security Report: \`${report.skill.name}\``);
  md.push("");
  md.push(`- **Source:** \`${report.skill.source}\``);
  md.push(`- **Scanned At:** ${report.skill.scanned_at} (${report.skill.duration_ms} ms)`);
  md.push(`- **Risk Score:** **${report.risk_assessment.score}/100** (${report.risk_assessment.severity})`);
  md.push(`- **Recommendation:** **${report.risk_assessment.recommendation}**`);
  md.push(`- **Safe to Install:** \`${report.risk_assessment.safe_to_install}\``);
  md.push(`- **Coverage:** ${report.inspection_completeness.coverage_percent}% (${report.inspection_completeness.status})`);
  md.push("");
  md.push(`## Components (${report.components.length})`);
  md.push("");
  md.push("| File | Type | Lines | Executable | Size (B) |");
  md.push("| :--- | :--- | ---: | :---: | ---: |");
  for (const c of report.components) {
    md.push(`| \`${c.path}\` | ${c.type} | ${c.lines} | ${c.executable ? "Yes" : "No"} | ${c.size_bytes} |`);
  }
  md.push("");

  if (report.issues.length === 0) {
    md.push("## Issues\n\nNo active security issues detected.");
  } else {
    md.push(`## Active Issues (${report.issues.length})`);
    md.push("");
    for (const issue of report.issues) {
      md.push(`### [${issue.severity}] ${issue.id} — ${issue.pattern}`);
      md.push(`- **Category:** ${issue.category}`);
      md.push(`- **Location:** \`${issue.location.file}:${issue.location.start_line}\``);
      md.push(`- **Confidence:** ${Math.round(issue.confidence * 100)}%`);
      md.push(`- **Finding:** \`${issue.finding.replace(/`/g, "'")}\``);
      md.push(`- **Explanation:** ${issue.explanation}`);
      md.push(`- **Remediation:** ${issue.remediation}`);
      md.push("");
    }
  }
  return md.join("\n");
}

export function formatSarifReport(report: ScanReport): string {
  const uniqueRules = new Map<string, { id: string; name: string; shortDescription: { text: string } }>();
  for (const issue of report.issues) {
    if (!uniqueRules.has(issue.id)) {
      uniqueRules.set(issue.id, {
        id: issue.id,
        name: issue.pattern,
        shortDescription: { text: `${issue.category}: ${issue.pattern}` },
      });
    }
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SkillSpectator",
            version: report.metadata.skillspectator_version,
            informationUri: "https://github.com/aswin402/skill-view",
            rules: Array.from(uniqueRules.values()),
          },
        },
        results: report.issues.map((issue) => ({
          ruleId: issue.id,
          level: issue.severity === "CRITICAL" || issue.severity === "HIGH" ? "error" : issue.severity === "MEDIUM" ? "warning" : "note",
          message: { text: `${issue.explanation} Remediation: ${issue.remediation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: issue.location.file },
                region: {
                  startLine: issue.location.start_line,
                  endLine: issue.location.end_line,
                  ...(issue.location.start_column ? { startColumn: issue.location.start_column } : {}),
                },
              },
            },
          ],
          fingerprints: { matchFingerprint: issue.match_fingerprint },
          properties: {
            severity: issue.severity,
            confidence: issue.confidence,
            category: issue.category,
            surface: issue.surface,
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

export function renderReport(report: ScanReport, format: "terminal" | "json" | "markdown" | "sarif" = "json", showSuppressed = false): string {
  switch (format) {
    case "terminal":
      return formatTerminalReport(report, showSuppressed);
    case "markdown":
      return formatMarkdownReport(report);
    case "sarif":
      return formatSarifReport(report);
    case "json":
    default:
      return JSON.stringify(report, null, 2);
  }
}
