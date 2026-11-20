import { readdir, stat } from "node:fs/promises";
import { basename, join } from "node:path";
import { getAgentHooksIntegrityRuleIds, runAgentHooksAndIntegrityAnalyzers } from "./analyzers/agent-hooks-integrity";
import { getAstTaintRuleIds, runBehavioralAstAndTaint } from "./analyzers/ast-taint";
import { getStaticRuleIds, runStaticRulesAnalyzer } from "./analyzers/static-rules";
import { getManifestYaraOsvRuleIds, runManifestYaraAndOsvAnalyzers } from "./analyzers/yara-osv-manifest";
import { applyBaselineSuppression, loadBaselineFile, SKILLSPECTATOR_VERSION } from "./baseline";
import { analyzeFileObfuscation, type FileDeobfuscationResult } from "./deobfuscate";
import { INGEST_MAX_BYTES, type IngestedBundle, ingestInlineSkill, ingestTarget, ingestZipBytes, MAX_FILE_BYTES } from "./ingest";
import { getSemanticRuleIds, runSemanticLlmPass, SUPPORTED_LLM_PROVIDERS } from "./llm";
import type {
  DeobfuscationEvent,
  EngineCapabilities,
  ExecutiveSummary,
  Finding,
  InlineSkillInput,
  Recommendation,
  RiskAssessment,
  ScanOptions,
  ScanReport,
  Severity,
  ThreatCategoryCheck,
} from "./types";
import { classifyFileType, sha256Hex } from "./utils";

const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const SEVERITY_POINTS: Record<Severity, number> = {
  CRITICAL: 50,
  HIGH: 25,
  MEDIUM: 10,
  LOW: 5,
};

const ALL_THREAT_VECTORS = [
  "Prompt Injection",
  "System Prompt Leakage",
  "Anti-Refusal",
  "Data Exfiltration",
  "Taint Tracking",
  "Behavioral AST",
  "Bundled Execution Surface",
  "Agent Snooping",
  "Privilege Escalation",
  "Manifest & Tool Poisoning",
  "Permission Least Privilege",
  "Supply Chain",
  "Supply Chain Rug-Pull",
  "YARA Signatures",
  "Artifact Integrity",
  "Memory Poisoning",
  "Tool Misuse",
  "Rogue Agent",
  "Insecure Deserialization",
  "Server-Side Request Forgery",
  "Excessive Agency",
  "Output Handling",
  "Trigger Abuse",
] as const;

function deduplicateFindings(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.id}:${f.location.file}:${f.location.start_line}`;
    const existing = byKey.get(key);
    if (!existing || f.confidence > existing.confidence) {
      byKey.set(key, f);
    }
  }
  return Array.from(byKey.values()).sort((a, b) => {
    const diff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (diff !== 0) return diff;
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    return a.location.file.localeCompare(b.location.file) || a.location.start_line - b.location.start_line;
  });
}

function detectActualCapabilities(bundle: IngestedBundle): string[] {
  const caps: string[] = [];
  const allText = Array.from(bundle.rawFiles.values()).join("\n");
  const codeFiles = bundle.components.filter((c) => c.executable);
  const codeText = codeFiles.map((c) => bundle.rawFiles.get(c.path) ?? "").join("\n");

  if (codeFiles.length > 0) caps.push(`Executable Scripts (${codeFiles.length})`);
  if (/\b(fetch|requests\.|httpx\.|urllib\.request|axios|WebSocket|curl\s+|wget\s+)\b/.test(codeText)) {
    caps.push("Outbound Network I/O");
  }
  if (/\b(subprocess\.|os\.system|child_process|Bun\.spawn)\b/.test(codeText)) {
    caps.push("OS Process / Shell Spawn");
  }
  if (/\b(os\.environ|os\.getenv|process\.env|Bun\.env)\b/.test(codeText)) {
    caps.push("Environment Variable Read");
  }
  if (/\b(open\s*\(|readFile|writeFile|fs\.)/.test(codeText)) {
    caps.push("Local Filesystem Access");
  }
  if (Array.from(bundle.rawFiles.keys()).some((k) => /(hooks\.json|settings\.json|plugin\.json)$/.test(k))) {
    caps.push("Lifecycle Hooks / Agent Settings");
  }
  if (Array.from(bundle.rawFiles.keys()).some((k) => /(requirements\.txt|package\.json|pyproject\.toml)$/.test(k))) {
    caps.push("Third-Party Dependencies");
  }
  if (caps.length === 0 && allText.length > 0) {
    caps.push("Pure Markdown Instructions Only");
  }
  return caps;
}

function buildExecutiveSummary(
  bundle: IngestedBundle,
  risk: RiskAssessment,
  activeFindings: Finding[],
  transitiveUrls: string[],
): ExecutiveSummary {
  const categoryChecks: ThreatCategoryCheck[] = ALL_THREAT_VECTORS.map((cat) => {
    const matching = activeFindings.filter((f) => f.category === cat);
    const hasHighOrCrit = matching.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    return {
      category: cat,
      status: matching.length === 0 ? "pass" : hasHighOrCrit ? "fail" : "warn",
      issues_count: matching.length,
    };
  });

  const capabilities = detectActualCapabilities(bundle);
  let headline = "Safe to Use — No Threats Detected";
  let plainVerdict =
    "This skill passed all 23 security vector checks with no high-risk instructions, hidden payloads, credential access, or malicious code patterns.";

  if (risk.recommendation === "DO_NOT_INSTALL") {
    const topCategories = Array.from(new Set(activeFindings.slice(0, 3).map((f) => f.category))).join(", ");
    headline = "Unsafe — Do Not Use This Skill";
    plainVerdict = `Blocked with a ${risk.score}/100 risk score. Detected ${activeFindings.length} security issue(s) across ${topCategories}. Review the highlighted lines below — do not grant this skill access to your agent or workstation.`;
  } else if (risk.recommendation === "CAUTION") {
    headline = "Use With Caution — Manual Review Needed";
    plainVerdict = `Scored ${risk.score}/100 (Moderate Risk). No confirmed malware or critical exfiltration chains were found, but ${activeFindings.length} item(s) involve elevated permissions, external commands, or unverified coverage that you should verify first.`;
  }

  return {
    headline,
    plain_verdict: plainVerdict,
    detected_capabilities: capabilities,
    category_checks: categoryChecks,
    transitive_urls_scanned: transitiveUrls,
  };
}

async function expandTransitiveExternalReferences(
  bundle: IngestedBundle,
  includeSourceContents = false,
): Promise<string[]> {
  const scannedUrls: string[] = [];
  if (!bundle.manifestPath) return scannedUrls;
  const manifest = bundle.rawFiles.get(bundle.manifestPath) ?? "";
  const urlMatches = Array.from(
    manifest.matchAll(/https:\/\/[a-zA-Z0-9_./-]+\.(?:md|py|sh|ts|js|yaml|yml|json)\b/g),
  ).map((m) => m[0]);

  const uniqueUrls = Array.from(new Set(urlMatches)).slice(0, 5);
  for (const url of uniqueUrls) {
    try {
      const parsed = new URL(url);
      if (parsed.hostname === "localhost" || parsed.hostname.startsWith("127.") || parsed.hostname === "169.254.169.254") {
        continue;
      }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) continue;
      const text = (await res.text()).slice(0, 250_000);
      const virtualPath = `transitive/${parsed.hostname}/${basename(parsed.pathname)}`;
      if (bundle.rawFiles.has(virtualPath)) continue;

      const bytes = new TextEncoder().encode(text);
      bundle.rawFiles.set(virtualPath, text);
      bundle.components.push({
        path: virtualPath,
        type: classifyFileType(virtualPath, false),
        lines: text.split(/\r?\n/).length,
        executable: /\.(py|sh|ts|js)$/.test(virtualPath),
        size_bytes: bytes.byteLength,
        sha256: sha256Hex(bytes),
        ...(includeSourceContents ? { content: text } : {}),
      });
      scannedUrls.push(url);
    } catch {
      // Ignore unreachable transitive URLs
    }
  }
  return scannedUrls;
}

function computeRiskAssessment(
  activeFindings: Finding[],
  hasExecutableScripts: boolean,
  isCoverageClean: boolean,
  llmRequirementMet: boolean,
): RiskAssessment {
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let maxSev: Severity | "NONE" = "NONE";

  for (const f of activeFindings) {
    if (f.severity === "CRITICAL") criticalCount++;
    else if (f.severity === "HIGH") highCount++;
    else if (f.severity === "MEDIUM") mediumCount++;
    else lowCount++;

    if (maxSev === "NONE" || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[maxSev]) {
      maxSev = f.severity;
    }
  }

  const rawPoints =
    criticalCount * SEVERITY_POINTS.CRITICAL +
    highCount * SEVERITY_POINTS.HIGH +
    mediumCount * SEVERITY_POINTS.MEDIUM +
    lowCount * SEVERITY_POINTS.LOW;

  const multiplierApplied = hasExecutableScripts && rawPoints > 0;
  const scaled = multiplierApplied ? Math.round(rawPoints * 1.3) : rawPoints;
  const score = Math.min(100, scaled);

  let severity: Severity = "LOW";
  let recommendation: Recommendation = "SAFE";

  if (score >= 81 || criticalCount > 0) {
    severity = "CRITICAL";
    recommendation = "DO_NOT_INSTALL";
  } else if (score >= 51) {
    severity = "HIGH";
    recommendation = "DO_NOT_INSTALL";
  } else if (score >= 21) {
    severity = "MEDIUM";
    recommendation = "CAUTION";
  } else {
    severity = "LOW";
    recommendation = "SAFE";
  }

  if ((!isCoverageClean || !llmRequirementMet) && recommendation === "SAFE") {
    recommendation = "CAUTION";
  }

  const safeToInstall =
    score <= 20 &&
    recommendation === "SAFE" &&
    isCoverageClean &&
    llmRequirementMet;

  return {
    score,
    severity,
    recommendation,
    safe_to_install: safeToInstall,
    max_issue_severity: maxSev,
    score_breakdown: {
      raw_points: rawPoints,
      executable_multiplier_applied: multiplierApplied,
      critical_count: criticalCount,
      high_count: highCount,
      medium_count: mediumCount,
      low_count: lowCount,
    },
  };
}

export async function analyzeIngestedBundle(bundle: IngestedBundle, options: ScanOptions = {}): Promise<ScanReport> {
  const t0 = performance.now();

  // Optional Transitive Link Fetching (referenced external scripts/docs inside SKILL.md)
  const transitiveUrls = options.followTransitiveLinks
    ? await expandTransitiveExternalReferences(bundle, Boolean(options.includeSourceContents))
    : [];

  // Stage 0: De-obfuscation & hidden payload pre-pass
  const deobfByFile = new Map<string, FileDeobfuscationResult>();
  const allDeobfEvents: DeobfuscationEvent[] = [];

  for (const [path, content] of bundle.rawFiles.entries()) {
    const res = analyzeFileObfuscation(path, content);
    deobfByFile.set(path, res);
    allDeobfEvents.push(...res.events);
  }

  // Stage 1: Full Deterministic Analyzer Suite (Static + Hooks/Snooping/Integrity + AST/Taint + Manifest/YARA/OSV)
  const staticRes = runStaticRulesAnalyzer(bundle, deobfByFile);
  const hooksIntegrityRes = runAgentHooksAndIntegrityAnalyzers(bundle);
  const astTaintRes = runBehavioralAstAndTaint(bundle);
  const manifestYaraOsvRes = await runManifestYaraAndOsvAnalyzers(bundle, {
    yaraRulesDir: options.yaraRulesDir,
    offlineOsv: options.offlineOsv,
  });

  const combinedStatic = deduplicateFindings([
    ...staticRes.findings,
    ...hooksIntegrityRes.findings,
    ...astTaintRes.findings,
    ...manifestYaraOsvRes.findings,
  ]);

  // Stage 2: Optional 4-Angle AI Semantic Pass (SSD, SDI, SQP, Meta)
  const useLlm = Boolean(options.useLlm);
  const llmRes = await runSemanticLlmPass(bundle, combinedStatic, {
    useLlm,
    provider: options.llmProvider,
    model: options.llmModel,
    apiKey: options.llmApiKey,
    baseUrl: options.llmBaseUrl,
  });

  const allFindings = deduplicateFindings([...llmRes.reviewedFindings, ...llmRes.newFindings]);

  // Baseline suppression
  const baselineDoc = options.baselineData ?? (options.baselinePath ? await loadBaselineFile(options.baselinePath) : undefined);
  const { active, suppressed } = applyBaselineSuppression(allFindings, baselineDoc);

  // Inspection Completeness Ledger
  const totalComponents = bundle.components.length + bundle.scopeExclusions.length;
  const scannedComponents = bundle.rawFiles.size;
  const uninspected = bundle.scopeExclusions.length + bundle.components.filter((c) => !bundle.rawFiles.has(c.path)).length;
  const coveragePercent =
    totalComponents === 0 ? 100 : Math.round((scannedComponents / totalComponents) * 1000) / 10;

  const onlyMissingRefExceptions = bundle.ledgerExceptions.every((e) => e.kind === "reference_missing");
  const isCoverageClean = bundle.scopeExclusions.length === 0 && uninspected === 0;
  const llmRequirementMet = !useLlm || llmRes.used;

  const completenessStatus = !isCoverageClean
    ? "partial"
    : bundle.ledgerExceptions.length > 0
      ? "complete_with_caveats"
      : "complete";

  const hasExecutableScripts = bundle.components.some((c) => c.executable);
  const riskAssessment = computeRiskAssessment(
    active,
    hasExecutableScripts,
    isCoverageClean && (bundle.ledgerExceptions.length === 0 || onlyMissingRefExceptions),
    llmRequirementMet,
  );

  const executiveSummary = buildExecutiveSummary(bundle, riskAssessment, active, transitiveUrls);
  const durationMs = Math.round((performance.now() - t0) * 100) / 100;

  return {
    skill: {
      name: bundle.skillName,
      ...(bundle.skillDescription ? { description: bundle.skillDescription } : {}),
      source: bundle.source,
      source_kind: bundle.sourceKind,
      scanned_at: new Date().toISOString(),
      duration_ms: durationMs,
    },
    risk_assessment: riskAssessment,
    executive_summary: executiveSummary,
    components: bundle.components,
    issues: active,
    suppressed,
    deobfuscation_events: allDeobfEvents,
    inspection_completeness: {
      total_components: totalComponents,
      scanned_components: scannedComponents,
      coverage_percent: coveragePercent,
      is_complete: isCoverageClean && bundle.ledgerExceptions.length === 0,
      status: completenessStatus,
      execution_successful: true,
      fully_inspected_files: scannedComponents,
      partially_inspected_files: 0,
      entirely_uninspected_files: uninspected,
      ledger_exceptions: bundle.ledgerExceptions,
      scope_exclusions: bundle.scopeExclusions,
      analyzer_statuses: [
        ...staticRes.statuses,
        ...hooksIntegrityRes.statuses,
        ...astTaintRes.statuses,
        ...manifestYaraOsvRes.statuses,
        ...llmRes.statuses,
      ],
    },
    metadata: {
      has_executable_scripts: hasExecutableScripts,
      skillspectator_version: SKILLSPECTATOR_VERSION,
      llm_requested: useLlm,
      llm_available: llmRes.available,
      llm_used: llmRes.used,
      scan_mode: llmRes.used ? "static+llm" : "static-only",
      ...(llmRes.provider ? { llm_provider: llmRes.provider } : {}),
      ...(llmRes.model ? { llm_model: llmRes.model } : {}),
      ...(llmRes.error ? { llm_error: llmRes.error } : {}),
      osv_mode: manifestYaraOsvRes.osvMode,
    },
  };
}

export function getEngineCapabilities(): EngineCapabilities {
  const activeRuleIds = Array.from(
    new Set([
      ...getStaticRuleIds(),
      ...getAgentHooksIntegrityRuleIds(),
      ...getAstTaintRuleIds(),
      ...getManifestYaraOsvRuleIds(),
      ...getSemanticRuleIds(),
    ]),
  ).sort();

  return {
    version: SKILLSPECTATOR_VERSION,
    active_rule_ids: activeRuleIds,
    active_rule_count: activeRuleIds.length,
    threat_vectors: [...ALL_THREAT_VECTORS],
    threat_vector_count: ALL_THREAT_VECTORS.length,
    max_ingest_bytes: INGEST_MAX_BYTES,
    max_file_bytes: MAX_FILE_BYTES,
    supported_llm_providers: SUPPORTED_LLM_PROVIDERS,
  };
}

export async function scanTarget(target: string, options: ScanOptions = {}): Promise<ScanReport> {
  const bundle = await ingestTarget(target, options.exclude ?? [], Boolean(options.includeSourceContents));
  return analyzeIngestedBundle(bundle, options);
}

export async function scanInline(inline: InlineSkillInput, options: ScanOptions = {}): Promise<ScanReport> {
  const bundle = ingestInlineSkill(inline, options.exclude ?? [], options.includeSourceContents ?? true);
  return analyzeIngestedBundle(bundle, options);
}

export async function scanZipBuffer(
  zipBytes: Uint8Array,
  label = "uploaded.zip",
  options: ScanOptions = {},
): Promise<ScanReport> {
  const bundle = ingestZipBytes(zipBytes, label, options.exclude ?? [], options.includeSourceContents ?? true);
  return analyzeIngestedBundle(bundle, options);
}

export async function scanCollectionRecursive(
  parentDir: string,
  maxSkills = 32,
  options: ScanOptions = {},
): Promise<{ reports: ScanReport[]; omitted: string[] }> {
  const entries = await readdir(parentDir, { withFileTypes: true });
  const skillDirs: string[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
    const candidate = join(parentDir, entry.name);
    try {
      const st = await stat(join(candidate, "SKILL.md")).catch(() => stat(join(candidate, "skill.md")));
      if (st.isFile()) {
        skillDirs.push(candidate);
      }
    } catch {
      // Not a skill folder
    }
  }

  skillDirs.sort();
  const selected = skillDirs.slice(0, maxSkills);
  const omitted = skillDirs.slice(maxSkills);
  const reports = await Promise.all(selected.map((dir) => scanTarget(dir, options)));
  return { reports, omitted };
}
