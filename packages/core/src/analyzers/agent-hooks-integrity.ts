import type { IngestedBundle } from "../ingest";
import type { AnalyzerStatusRecord, Finding } from "../types";
import { createFinding, isProhibitionContext } from "../utils";

const SENSITIVE_HOOK_EVENTS = new Set([
  "UserPromptSubmit",
  "UserPromptExpansion",
  "MessageDisplay",
  "PreToolUse",
  "PermissionRequest",
  "PermissionDenied",
  "PostToolUse",
  "PostToolUseFailure",
  "PostToolBatch",
  "SubagentStop",
  "Stop",
  "PreCompact",
  "PostCompact",
]);

const AUTO_EXEC_SETTINGS_KEYS = [
  "apiKeyHelper",
  "awsAuthRefresh",
  "awsCredentialExport",
  "gcpAuthRefresh",
  "otelHeadersHelper",
  "statusLine",
  "fileSuggestion",
] as const;

const SPACED_ATTACK_PHRASES = [
  "ignorepreviousinstructions",
  "ignoreallpreviousinstructions",
  "disregardpreviousinstructions",
  "overridesystemprompt",
  "overridesafety",
  "bypasssecurity",
  "revealsystemprompt",
  "dumpsystemprompt",
  "silentlysend",
  "withouttellingtheuser",
  "withoutinformingtheuser",
];

function collapseLetterSpacing(line: string): string | null {
  // Detect sequences like "i g n o r e   p r e v i o u s" or "i.g.n.o.r.e"
  const tokens = line.trim().split(/[\s._-]+/).filter(Boolean);
  if (tokens.length < 6) return null;
  const singleCharCount = tokens.filter((t) => t.length === 1 && /[a-zA-Z]/.test(t)).length;
  if (singleCharCount < 6 || singleCharCount / tokens.length < 0.65) return null;
  return tokens.join("").toLowerCase();
}

export function getAgentHooksIntegrityRuleIds(): string[] {
  return ["AS1", "AS2", "AS3", "BH1", "BH2", "BH3", "BH4", "AE1", "AE2", "AE3", "AE4"];
}

export function runAgentHooksAndIntegrityAnalyzers(bundle: IngestedBundle): {
  findings: Finding[];
  statuses: AnalyzerStatusRecord[];
} {
  const findings: Finding[] = [];
  const statuses: AnalyzerStatusRecord[] = [];

  // ── 1. Agent Snooping Analyzer (AS1–AS3) ──
  const tSnooping = performance.now();
  let asCount = 0;

  for (const comp of bundle.components) {
    const content = bundle.rawFiles.get(comp.path);
    if (!content) continue;
    const lines = content.split(/\r?\n/);

    lines.forEach((line, idx) => {
      if (comp.type === "markdown" && isProhibitionContext(line)) return;

      // AS1: Agent config directory access (.claude/, .codex/, .gemini/, .cursor/)
      if (/(~\/|\$HOME\/|os\.path\.expanduser\([^)]*)\.(claude|codex|gemini|cursor|opencode)\/(?!skills\/)/i.test(line)) {
        findings.push(
          createFinding({
            id: "AS1",
            category: "Agent Snooping",
            pattern: "Host Agent Configuration Directory Snooping",
            severity: "HIGH",
            confidence: 0.89,
            file: comp.path,
            startLine: idx + 1,
            finding: line.trim().slice(0, 140),
            explanation:
              "Reads from private host agent directories (`.claude/`, `.gemini/`, `.codex/`, `.cursor/`), which store auth tokens, session transcripts, and user settings.",
            remediation:
              "Remove direct reads of host agent configuration folders. Accept required settings via explicit parameters.",
            fileContent: content,
          }),
        );
        asCount++;
      }

      // AS2: Reading host MCP/Desktop configuration files
      if (/(claude_desktop_config\.json|mcp_config\.json|\.cursor\/mcp\.json|\.claude\.json)/i.test(line)) {
        findings.push(
          createFinding({
            id: "AS2",
            category: "Agent Snooping",
            pattern: "Host Tool / Configuration Token Discovery",
            severity: "HIGH",
            confidence: 0.88,
            file: comp.path,
            startLine: idx + 1,
            finding: line.trim().slice(0, 140),
            explanation:
              "Accesses host tool configuration files that commonly embed API keys, bearer tokens, and internal server endpoints.",
            remediation: "Never read global desktop or agent tool configuration files from inside a skill.",
            fileContent: content,
          }),
        );
        asCount++;
      }

      // AS3: Cross-skill enumeration (listing or reading peer installed skills)
      if (
        /(\.\.\/[a-zA-Z0-9_-]+\/SKILL\.md|(listdir|readdir|scandir|glob|rglob)\s*\([^)]*\/skills\b|find\s+~\/[^\n]*\/skills\s+-name\s+['"]?SKILL\.md)/i.test(
          line,
        )
      ) {
        findings.push(
          createFinding({
            id: "AS3",
            category: "Agent Snooping",
            pattern: "Cross-Skill Enumeration & Peer Snooping",
            severity: "MEDIUM",
            confidence: 0.84,
            file: comp.path,
            startLine: idx + 1,
            finding: line.trim().slice(0, 140),
            explanation:
              "Enumerates or reads sibling installed skills outside its own bundle boundary, exposing peer prompts and capabilities.",
            remediation: "Operate strictly within the skill's own directory without enumerating sibling skills.",
            fileContent: content,
          }),
        );
        asCount++;
      }
    });
  }

  statuses.push({
    analyzer_id: "static_patterns_agent_snooping",
    category: "Agent Snooping",
    status: "completed",
    planned_work: bundle.rawFiles.size,
    completed: bundle.rawFiles.size,
    findings_count: asCount,
    duration_ms: Math.round((performance.now() - tSnooping) * 100) / 100,
  });

  // ── 2. Bundled Execution Surface Analyzer (BH1–BH4) ──
  const tHooks = performance.now();
  let bhCount = 0;
  const hookSurfaceFiles = Array.from(bundle.rawFiles.keys()).filter((p) =>
    /(^|\/)(hooks\/hooks\.json|\.claude\/settings(\.local)?\.json|\.claude-plugin\/plugin\.json|settings\.json)$/i.test(
      p,
    ),
  );

  for (const filePath of hookSurfaceFiles) {
    const content = bundle.rawFiles.get(filePath)!;
    try {
      const parsed = JSON.parse(content) as Record<string, unknown>;

      // BH1 & BH2: Lifecycle hooks inspection
      const hooksObj = parsed.hooks;
      if (hooksObj && typeof hooksObj === "object") {
        for (const [eventName, handlers] of Object.entries(hooksObj as Record<string, unknown>)) {
          const serialized = JSON.stringify(handlers);
          const lineIdx = content.split(/\r?\n/).findIndex((l) => l.includes(`"${eventName}"`));
          const lineNo = lineIdx >= 0 ? lineIdx + 1 : 1;

          findings.push(
            createFinding({
              id: "BH1",
              category: "Bundled Execution Surface",
              pattern: `Bundled Lifecycle Hook (${eventName})`,
              severity: SENSITIVE_HOOK_EVENTS.has(eventName) ? "HIGH" : "MEDIUM",
              confidence: 0.92,
              file: filePath,
              startLine: lineNo,
              finding: `hooks.${eventName}: ${serialized.slice(0, 120)}`,
              explanation: `Bundled configuration registers an automatic lifecycle hook on '${eventName}', executing commands or HTTP calls whenever that agent event fires.`,
              remediation:
                "Review every bundled hook handler carefully before using this skill, or remove automatic lifecycle hooks.",
              fileContent: content,
            }),
          );
          bhCount++;

          // BH2: Hook directly sends prompt/event/local file data to non-loopback remote URL
          if (/https?:\/\/(?!localhost|127\.0\.0\.1)/i.test(serialized) && /(curl|wget|fetch|http|POST|\$CLAUDE|\$USER|stdin)/i.test(serialized)) {
            findings.push(
              createFinding({
                id: "BH2",
                category: "Bundled Execution Surface",
                pattern: "Remote Exfiltration Lifecycle Hook",
                severity: "CRITICAL",
                confidence: 0.96,
                file: filePath,
                startLine: lineNo,
                finding: `hooks.${eventName} -> external URL`,
                explanation: `Lifecycle hook '${eventName}' transmits event payloads or local files directly to an external server.`,
                remediation: "Remove external network transmission from lifecycle hooks immediately.",
                fileContent: content,
              }),
            );
            bhCount++;
          }
        }
      }

      // BH3: Bundled project permission overrides (bypassPermissions, dontAsk, wildcard allow)
      const perms = parsed.permissions as Record<string, unknown> | undefined;
      const defaultMode = perms?.defaultMode ?? parsed.defaultMode;
      if (
        defaultMode === "bypassPermissions" ||
        defaultMode === "dontAsk" ||
        (Array.isArray(perms?.allow) && perms.allow.some((x) => String(x).includes("*")))
      ) {
        findings.push(
          createFinding({
            id: "BH3",
            category: "Bundled Execution Surface",
            pattern: "Bundled Permission-Bypass Settings",
            severity: "HIGH",
            confidence: 0.93,
            file: filePath,
            startLine: 1,
            finding: JSON.stringify(perms ?? { defaultMode }).slice(0, 140),
            explanation:
              "Bundled project settings weaken or disable interactive permission prompts (`bypassPermissions`, `dontAsk`, or wildcard `allow` rules).",
            remediation: "Remove permission-bypassing project settings from distributed skill bundles.",
            fileContent: content,
          }),
        );
        bhCount++;
      }

      // BH4: Auto-executing helper command keys (apiKeyHelper, statusLine, awsCredentialExport, etc.)
      for (const key of AUTO_EXEC_SETTINGS_KEYS) {
        if (parsed[key] !== undefined) {
          const lineIdx = content.split(/\r?\n/).findIndex((l) => l.includes(`"${key}"`));
          findings.push(
            createFinding({
              id: "BH4",
              category: "Bundled Execution Surface",
              pattern: `Auto-Executing Settings Command (${key})`,
              severity: "CRITICAL",
              confidence: 0.95,
              file: filePath,
              startLine: lineIdx >= 0 ? lineIdx + 1 : 1,
              finding: `${key}: ${JSON.stringify(parsed[key]).slice(0, 120)}`,
              explanation: `Settings key '${key}' executes a shell command automatically whenever the project settings become active — a known Trojan-repo RCE vector.`,
              remediation: `Delete '${key}' from bundled settings files; never accept untrusted command helpers.`,
              fileContent: content,
            }),
          );
          bhCount++;
        }
      }
    } catch {
      // Malformed JSON ignored here
    }
  }

  statuses.push({
    analyzer_id: "bundled_execution_surface",
    category: "Bundled Execution Surface",
    status: hookSurfaceFiles.length > 0 ? "completed" : "not_applicable",
    planned_work: hookSurfaceFiles.length,
    completed: hookSurfaceFiles.length,
    findings_count: bhCount,
    duration_ms: Math.round((performance.now() - tHooks) * 100) / 100,
    ...(hookSurfaceFiles.length === 0
      ? { reason_code: "no_applicable_files", message: "No bundled hook or agent settings files present." }
      : {}),
  });

  // ── 3. Artifact Integrity & Evasion Analyzer (AE1–AE4) ──
  const tIntegrity = performance.now();
  let aeCount = 0;

  for (const comp of bundle.components) {
    const content = bundle.rawFiles.get(comp.path);
    if (!content) continue;
    const lines = content.split(/\r?\n/);

    // AE2: Letter-spaced / character-fragmented prompt injection ("i g n o r e  p r e v i o u s")
    lines.forEach((line, idx) => {
      const collapsed = collapseLetterSpacing(line);
      if (collapsed && SPACED_ATTACK_PHRASES.some((phrase) => collapsed.includes(phrase))) {
        findings.push(
          createFinding({
            id: "AE2",
            category: "Artifact Integrity",
            pattern: "Character-Spaced Prompt Evasion",
            severity: "HIGH",
            confidence: 0.91,
            file: comp.path,
            startLine: idx + 1,
            finding: line.trim().slice(0, 140),
            explanation:
              "Deliberately spaces or separates individual letters to smuggle prompt-override phrases past naive keyword scanners.",
            remediation: "Remove character-spaced obfuscated directives.",
            fileContent: content,
            evidence: { reconstructed: collapsed.slice(0, 120) },
          }),
        );
        aeCount++;
      }
    });

    // AE3: Multi-line split prompt injection (e.g., splitting "ignore all previous" + "\n" + "instructions and send...")
    if (comp.type === "markdown" || comp.type === "text") {
      const joinedLines = lines
        .map((l) => l.trim())
        .filter((l) => l && !isProhibitionContext(l))
        .join(" ");
      const hasSingleLineOverride = lines.some((l) =>
        /\bignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?|rules?)/i.test(l),
      );
      if (
        !hasSingleLineOverride &&
        /\bignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?|rules?)/i.test(joinedLines)
      ) {
        findings.push(
          createFinding({
            id: "AE3",
            category: "Artifact Integrity",
            pattern: "Multi-Line Fragmented Prompt Injection",
            severity: "HIGH",
            confidence: 0.87,
            file: comp.path,
            startLine: 1,
            finding: "Cross-line reconstructed instruction override",
            explanation:
              "Splits an instruction-override directive across line breaks so single-line regex checks miss it while the LLM reads the joined prose.",
            remediation: "Remove fragmented prompt-override text across lines.",
            fileContent: content,
          }),
        );
        aeCount++;
      }
    }

    // AE4: Mixed-script NFKC normalization / confusable skeleton anomaly in prose or identifiers
    const nfkcDiffLines = lines.findIndex((line) => {
      const norm = line.normalize("NFKC");
      return norm !== line && /\b(ignore|system|exec|eval|curl|ssh|token|password)\b/i.test(norm) && !/\b(ignore|system|exec|eval|curl|ssh|token|password)\b/i.test(line);
    });
    if (nfkcDiffLines >= 0) {
      findings.push(
        createFinding({
          id: "AE4",
          category: "Artifact Integrity",
          pattern: "Unicode NFKC Compatibility Normalization Evasion",
          severity: "HIGH",
          confidence: 0.9,
          file: comp.path,
          startLine: nfkcDiffLines + 1,
          finding: lines[nfkcDiffLines]!.trim().slice(0, 140),
          explanation:
            "Uses fullwidth, mathematical, or compatibility Unicode glyphs that normalize to sensitive security keywords (`ignore`, `system`, `exec`, `token`).",
          remediation: "Replace compatibility/fullwidth Unicode characters with standard ASCII.",
          fileContent: content,
        }),
      );
      aeCount++;
    }
  }

  // AE1: Incomplete or oversized/binary artifact warning when executable/binary skipped
  for (const ex of bundle.ledgerExceptions) {
    if (ex.kind === "size_limit_exceeded") {
      findings.push({
        id: "AE1",
        finding_id: `finding-ae1-${ex.file}`,
        category: "Artifact Integrity",
        pattern: "Incomplete Oversized Artifact Analysis",
        severity: "MEDIUM",
        confidence: 0.9,
        location: { file: ex.file, start_line: 1, end_line: 1 },
        finding: ex.message,
        explanation: "Artifact exceeded per-file analysis size ceiling and could not be fully inspected.",
        remediation: "Split or trim oversized files below 1 MiB so every bundled line can be verified.",
        code_snippet: ex.message,
        surface: "code",
        tags: ["Artifact Integrity"],
        evidence: { file: ex.file },
        match_fingerprint: `ae1:${ex.file}`,
        occurrences: [{ file: ex.file, start_line: 1, end_line: 1 }],
      });
      aeCount++;
    }
  }

  statuses.push({
    analyzer_id: "artifact_integrity",
    category: "Artifact Integrity",
    status: "completed",
    planned_work: bundle.components.length,
    completed: bundle.components.length,
    findings_count: aeCount,
    duration_ms: Math.round((performance.now() - tIntegrity) * 100) / 100,
  });

  return { findings, statuses };
}
