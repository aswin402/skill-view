import { createHash } from "node:crypto";
import type { ComponentInfo, Finding, FindingLocation, Severity, Surface } from "./types";

export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}

export function classifyFileType(filePath: string, isBinary = false): ComponentInfo["type"] {
  if (isBinary) return "binary";
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".md") || lower.endsWith(".mdx")) return "markdown";
  if (lower.endsWith(".py") || lower.endsWith(".pyw")) return "python";
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".mts") || lower.endsWith(".cts")) return "typescript";
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "javascript";
  if (lower.endsWith(".sh") || lower.endsWith(".bash") || lower.endsWith(".zsh") || lower.endsWith(".ps1") || lower.endsWith(".bat")) return "shell";
  if (lower.endsWith(".json") || lower.endsWith(".jsonc")) return "json";
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return "yaml";
  return "text";
}

export function isExecutableComponent(filePath: string, content: string, modeExecutable = false): boolean {
  if (modeExecutable) return true;
  const type = classifyFileType(filePath);
  if (type === "python" || type === "typescript" || type === "javascript" || type === "shell") {
    return true;
  }
  if (content.startsWith("#!/")) return true;
  return false;
}

export function classifySurface(filePath: string, lineText = ""): Surface {
  const lower = filePath.toLowerCase();
  if (/(^|\/)(tests?|__tests__|spec|fixtures?)\//.test(lower) || /\.(test|spec)\.[a-z0-9]+$/.test(lower)) {
    return "tests";
  }
  const trimmed = lineText.trim();
  if (trimmed.startsWith("#") && !lower.endsWith(".md")) return "comments";
  if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) return "comments";
  if (lower.endsWith("skill.md") || lower.includes("instructions") || lower.includes("prompt")) {
    return "instructions";
  }
  if (lower.endsWith(".md") || lower.endsWith(".mdx") || lower.startsWith("docs/")) {
    return "docs";
  }
  if (lower.endsWith(".json") || lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".toml")) {
    return "config";
  }
  return "code";
}

export function extractSnippet(content: string, lineNum: number, contextLines = 2): string {
  const lines = content.split(/\r?\n/);
  const start = Math.max(0, lineNum - 1 - contextLines);
  const end = Math.min(lines.length, lineNum + contextLines);
  return lines.slice(start, end).join("\n");
}

/**
 * Checks whether a matched phrase in Markdown/prose is inside a clear prohibition/defensive warning
 * (e.g., "Never ignore previous instructions", "Do NOT use eval() or exec()", "Avoid sudo unless required").
 */
export function isProhibitionContext(line: string): boolean {
  const lower = line.toLowerCase();
  // Stealth/bypass instructions ("do not mention", "do not ask", "never refuse", "never include warnings") are NOT defensive prohibitions
  if (
    /\b(do\s+not|don't|never)\s+(mention|tell|inform|reveal|alert|ask|warn|lecture|refuse|include\s+(safety\s+)?(warnings?|disclaimers?))\b/.test(
      lower,
    )
  ) {
    return false;
  }
  return /\b(never|do\s+not|don't|must\s+not|avoid|prohibit(?:ed)?|forbid(?:den)?|block(?:s|ed)?|detect(?:s|ing)?|prevent(?:s|ing)?|bad\s+example|anti-pattern|vulnerable\s+example)\b/.test(
    lower,
  );
}

export interface CreateFindingArgs {
  id: string;
  category: string;
  pattern: string;
  severity: Severity;
  confidence: number;
  file: string;
  startLine: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  finding: string;
  explanation: string;
  remediation: string;
  fileContent: string;
  tags?: string[];
  evidence?: Record<string, unknown>;
}

export function createFinding(args: CreateFindingArgs): Finding {
  const startLine = Math.max(1, args.startLine);
  const endLine = Math.max(startLine, args.endLine ?? startLine);
  const lines = args.fileContent.split(/\r?\n/);
  const lineText = lines[startLine - 1] ?? "";
  const location: FindingLocation = {
    file: args.file,
    start_line: startLine,
    end_line: endLine,
    ...(args.startColumn !== undefined ? { start_column: args.startColumn } : {}),
    ...(args.endColumn !== undefined ? { end_column: args.endColumn } : {}),
  };

  const matchFingerprint = sha256Hex(`${args.id}:${args.file}:${startLine}:${args.finding.trim()}`);
  const findingId = `finding-${matchFingerprint.slice(0, 24)}`;

  return {
    id: args.id,
    finding_id: findingId,
    category: args.category,
    pattern: args.pattern,
    severity: args.severity,
    confidence: Math.round(args.confidence * 100) / 100,
    location,
    finding: args.finding.slice(0, 240),
    explanation: args.explanation,
    remediation: args.remediation,
    code_snippet: extractSnippet(args.fileContent, startLine, 2),
    surface: classifySurface(args.file, lineText),
    tags: args.tags ?? [args.category],
    evidence: args.evidence ?? {},
    match_fingerprint: matchFingerprint,
    occurrences: [location],
  };
}

export function globMatch(pattern: string, targetPath: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`).test(targetPath);
}
