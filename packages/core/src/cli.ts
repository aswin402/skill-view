#!/usr/bin/env bun
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import pc from "picocolors";
import { buildBaselineFromFindings, SKILLSPECTATOR_VERSION, serializeBaselineYaml } from "./baseline";
import { renderReport } from "./formatters";
import { scanCollectionRecursive, scanTarget } from "./scanner";

function printHelp(): void {
  console.log(`
${pc.bold(pc.cyan("SkillSpectator"))} ${pc.dim(`v${SKILLSPECTATOR_VERSION}`)} — High-speed TS + Bun security scanner for AI agent skills

${pc.bold("Usage:")}
  skillspectator <command> [options]

${pc.bold("Commands:")}
  scan <target>        Scan a directory, SKILL.md, .zip archive, or https:// Git URL
  baseline <target>    Generate a SHA-256 YAML baseline file for reviewed findings
  ui                   Launch the SkillSpectator Website & API server

${pc.bold("Scan Options:")}
  -f, --format <fmt>         Output format: terminal | json | markdown | sarif (default: terminal)
  -o, --output <path>        Write report to file instead of stdout
  --no-llm                   Run deterministic static/AST/taint/YARA/OSV scan only (default)
  --llm                      Enable Stage-2 LLM semantic analysis
  --provider <name>          LLM provider: openai | anthropic | nv_build | ollama | gemini_cli | claude_cli
  --model <id>               Override active LLM model ID
  -b, --baseline <path>      Suppress findings matching a YAML baseline
  --show-suppressed          Display baseline-suppressed findings in terminal report
  --exclude <glob>           Exclude matching relative paths (repeatable; marks coverage partial)
  --yara-rules-dir <dir>     Load additional custom .yar/.yara rules
  --recursive                Scan immediate skill subdirectories inside <target>
  --max-skills <n>           Maximum skills in recursive mode (default: 32)
  --fail-on-findings         Exit 1 if one or more active findings exist
  --fail-on-incomplete       Exit 1 if inspection coverage is partial/incomplete
  --min-coverage <pct>       Exit 1 if coverage percentage is below threshold (0-100)
  --offline                  Skip live OSV.dev network queries and use offline advisory DB
`);
}

export async function runCli(argv = process.argv.slice(2)): Promise<number> {
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
    printHelp();
    return 0;
  }
  if (argv[0] === "-v" || argv[0] === "--version") {
    console.log(`SkillSpectator v${SKILLSPECTATOR_VERSION}`);
    return 0;
  }

  const command = argv[0];
  const rest = argv.slice(1);

  if (command === "ui") {
    const devScript = resolve(import.meta.dir, "../../../scripts/dev.ts");
    const proc = Bun.spawn(["bun", "run", devScript], {
      stdio: ["inherit", "inherit", "inherit"],
    });
    return await proc.exited;
  }

  if (command === "baseline") {
    let target = "";
    let output = ".skillspectator-baseline.yaml";
    let reason = "Accepted finding (auto-generated baseline)";
    let useLlm = false;

    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i]!;
      if ((arg === "-o" || arg === "--output") && rest[i + 1]) {
        output = rest[++i]!;
      } else if (arg === "--reason" && rest[i + 1]) {
        reason = rest[++i]!;
      } else if (arg === "--llm") {
        useLlm = true;
      } else if (arg === "--no-llm") {
        useLlm = false;
      } else if (!arg.startsWith("-")) {
        target = arg;
      }
    }

    if (!target) {
      console.error(pc.red("Error: Missing <target> path for baseline generation."));
      return 2;
    }

    const report = await scanTarget(target, { useLlm });
    const doc = buildBaselineFromFindings(report.issues, reason);
    const yamlText = serializeBaselineYaml(doc);
    if (output === "-") {
      process.stdout.write(yamlText);
    } else {
      await writeFile(output, yamlText, { mode: 0o600 });
      console.log(pc.green(`✔ Wrote baseline with ${doc.fingerprints.length} suppressed finding(s) to ${output}`));
    }
    return 0;
  }

  if (command === "scan") {
    let target = "";
    let format: "terminal" | "json" | "markdown" | "sarif" = "terminal";
    let outputPath: string | undefined;
    let useLlm = false;
    let llmProvider: string | undefined;
    let llmModel: string | undefined;
    let baselinePath: string | undefined;
    let showSuppressed = false;
    let yaraRulesDir: string | undefined;
    let recursive = false;
    let maxSkills = 32;
    let failOnFindings = false;
    let failOnIncomplete = false;
    let minCoverage: number | undefined;
    let offlineOsv = false;
    const exclude: string[] = [];

    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i]!;
      if (arg === "-h" || arg === "--help") {
        printHelp();
        return 0;
      } else if ((arg === "-f" || arg === "--format") && rest[i + 1]) {
        const val = rest[++i]! as "terminal" | "json" | "markdown" | "sarif";
        if (!["terminal", "json", "markdown", "sarif"].includes(val)) {
          console.error(pc.red(`Invalid format '${val}'. Expected terminal|json|markdown|sarif.`));
          return 2;
        }
        format = val;
      } else if ((arg === "-o" || arg === "--output") && rest[i + 1]) {
        outputPath = rest[++i]!;
      } else if (arg === "--no-llm") {
        useLlm = false;
      } else if (arg === "--llm") {
        useLlm = true;
      } else if (arg === "--provider" && rest[i + 1]) {
        llmProvider = rest[++i]!;
        useLlm = true;
      } else if (arg === "--model" && rest[i + 1]) {
        llmModel = rest[++i]!;
      } else if ((arg === "-b" || arg === "--baseline") && rest[i + 1]) {
        baselinePath = rest[++i]!;
      } else if (arg === "--show-suppressed") {
        showSuppressed = true;
      } else if (arg === "--exclude" && rest[i + 1]) {
        exclude.push(rest[++i]!);
      } else if (arg === "--yara-rules-dir" && rest[i + 1]) {
        yaraRulesDir = rest[++i]!;
      } else if (arg === "--recursive") {
        recursive = true;
      } else if (arg === "--max-skills" && rest[i + 1]) {
        maxSkills = Number(rest[++i]!);
        if (!Number.isInteger(maxSkills) || maxSkills <= 0) {
          console.error(pc.red("Error: --max-skills requires a positive integer."));
          return 2;
        }
      } else if (arg === "--fail-on-findings") {
        failOnFindings = true;
      } else if (arg === "--fail-on-incomplete") {
        failOnIncomplete = true;
      } else if (arg === "--min-coverage" && rest[i + 1]) {
        minCoverage = Number(rest[++i]!);
      } else if (arg === "--offline") {
        offlineOsv = true;
      } else if (!arg.startsWith("-")) {
        target = arg;
      }
    }

    if (!target) {
      console.error(pc.red("Error: Missing <target> path or URL to scan."));
      return 2;
    }

    try {
      if (recursive) {
        const { reports, omitted } = await scanCollectionRecursive(target, maxSkills, {
          useLlm,
          llmProvider,
          llmModel,
          yaraRulesDir,
          offlineOsv,
        });
        const payload = format === "json"
          ? JSON.stringify({ skills_scanned: reports.length, omitted_skills: omitted, reports }, null, 2)
          : reports.map((r) => renderReport(r, format, showSuppressed)).join("\n---\n");

        if (outputPath) {
          await writeFile(outputPath, payload, { mode: 0o600 });
          console.log(pc.green(`Report saved to: ${outputPath}`));
        } else {
          console.log(payload);
        }

        const anyHighRisk = reports.some((r) => r.risk_assessment.score > 50);
        const anyFinding = failOnFindings && reports.some((r) => r.issues.length > 0);
        const incomplete = failOnIncomplete && (omitted.length > 0 || reports.some((r) => !r.inspection_completeness.is_complete));
        return anyHighRisk || anyFinding || incomplete ? 1 : 0;
      }

      const report = await scanTarget(target, {
        useLlm,
        llmProvider,
        llmModel,
        outputFormat: format,
        baselinePath,
        showSuppressed,
        exclude,
        yaraRulesDir,
        offlineOsv,
      });

      const rendered = renderReport(report, format, showSuppressed);
      if (outputPath) {
        await writeFile(outputPath, rendered, { mode: 0o600 });
        console.log(pc.green(`Report saved to: ${outputPath}`));
      } else {
        console.log(rendered);
      }

      const gateFailed =
        report.risk_assessment.score > 50 ||
        report.risk_assessment.recommendation === "DO_NOT_INSTALL" ||
        (failOnFindings && report.issues.length > 0) ||
        (failOnIncomplete && report.inspection_completeness.status !== "complete") ||
        (minCoverage !== undefined && report.inspection_completeness.coverage_percent < minCoverage);

      return gateFailed ? 1 : 0;
    } catch (err) {
      console.error(pc.red(`Scan error: ${err instanceof Error ? err.message : String(err)}`));
      return 2;
    }
  }

  console.error(pc.red(`Unknown command '${command}'. Run 'skillspectator --help'.`));
  return 2;
}

if (import.meta.main) {
  const code = await runCli();
  process.exit(code);
}
