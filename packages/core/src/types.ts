export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Recommendation = "SAFE" | "CAUTION" | "DO_NOT_INSTALL";
export type Surface = "code" | "instructions" | "docs" | "tests" | "comments" | "config";

export interface ComponentInfo {
  path: string;
  type: "markdown" | "python" | "typescript" | "javascript" | "shell" | "json" | "yaml" | "binary" | "text";
  lines: number;
  executable: boolean;
  size_bytes: number;
  sha256: string;
  content?: string;
}

export interface FindingLocation {
  file: string;
  start_line: number;
  end_line: number;
  start_column?: number;
  end_column?: number;
}

export interface Finding {
  id: string;
  finding_id: string;
  category: string;
  pattern: string;
  severity: Severity;
  confidence: number;
  location: FindingLocation;
  finding: string;
  explanation: string;
  remediation: string;
  code_snippet: string;
  surface: Surface;
  tags: string[];
  evidence: Record<string, unknown>;
  match_fingerprint: string;
  occurrences: FindingLocation[];
  llm_review_outcome?: "confirmed" | "disagreed" | "low-confidence" | "unreviewed";
}

export interface SuppressedFinding extends Finding {
  suppression_reason: string;
}

export interface DeobfuscationEvent {
  file: string;
  line: number;
  kind: "zero_width" | "unicode_tag" | "bidi_override" | "homoglyph" | "base64_payload" | "hex_payload" | "html_comment" | "whitespace_padding";
  summary: string;
  decoded_preview?: string;
}

export interface AnalyzerStatusRecord {
  analyzer_id: string;
  category: string;
  status: "completed" | "not_applicable" | "disabled" | "partial" | "failed";
  planned_work: number;
  completed: number;
  findings_count: number;
  duration_ms: number;
  reason_code?: string;
  message?: string;
}

export interface LedgerException {
  kind: "reference_missing" | "size_limit_exceeded" | "binary_skipped" | "parse_warning";
  file: string;
  line?: number;
  message: string;
}

export interface InspectionCompleteness {
  total_components: number;
  scanned_components: number;
  coverage_percent: number;
  is_complete: boolean;
  status: "complete" | "complete_with_caveats" | "partial" | "incomplete";
  execution_successful: boolean;
  fully_inspected_files: number;
  partially_inspected_files: number;
  entirely_uninspected_files: number;
  ledger_exceptions: LedgerException[];
  scope_exclusions: string[];
  analyzer_statuses: AnalyzerStatusRecord[];
}

export interface ScoreBreakdown {
  raw_points: number;
  executable_multiplier_applied: boolean;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface RiskAssessment {
  score: number;
  severity: Severity;
  recommendation: Recommendation;
  safe_to_install: boolean;
  max_issue_severity: Severity | "NONE";
  score_breakdown: ScoreBreakdown;
}

export interface ThreatCategoryCheck {
  category: string;
  status: "pass" | "warn" | "fail";
  issues_count: number;
}

export interface ExecutiveSummary {
  headline: string;
  plain_verdict: string;
  detected_capabilities: string[];
  category_checks: ThreatCategoryCheck[];
  transitive_urls_scanned: string[];
}

export interface SkillFrontmatter {
  name?: string;
  description?: string;
  permissions?: string[] | string;
  allowedTools?: string[] | string;
  triggers?: string[] | string;
  parameters?: Record<string, unknown>;
  raw: Record<string, unknown>;
  rawText: string;
  endLine: number;
}

export interface ScanReport {
  skill: {
    name: string;
    description?: string;
    source: string;
    source_kind: "directory" | "file" | "zip" | "git" | "url" | "inline";
    scanned_at: string;
    duration_ms: number;
  };
  risk_assessment: RiskAssessment;
  executive_summary: ExecutiveSummary;
  components: ComponentInfo[];
  issues: Finding[];
  suppressed: SuppressedFinding[];
  deobfuscation_events: DeobfuscationEvent[];
  inspection_completeness: InspectionCompleteness;
  metadata: {
    has_executable_scripts: boolean;
    skillspectator_version: string;
    llm_requested: boolean;
    llm_available: boolean;
    llm_used: boolean;
    scan_mode: "static+llm" | "static-only";
    llm_provider?: string;
    llm_model?: string;
    llm_error?: string;
    osv_mode: "live" | "offline_fallback" | "not_applicable";
  };
}

export interface VirtualFileInput {
  path: string;
  content: string;
}

export interface InlineSkillInput {
  name?: string;
  files: VirtualFileInput[];
}

export interface BaselineEntry {
  hash: string;
  rule_id: string;
  file: string;
  reason: string;
}

export interface BaselineRule {
  rule_id?: string;
  file_glob?: string;
  reason: string;
}

export interface BaselineDocument {
  version: number;
  scanner_version: string;
  rules: BaselineRule[];
  fingerprints: BaselineEntry[];
}

export interface EngineCapabilities {
  version: string;
  active_rule_ids: string[];
  active_rule_count: number;
  threat_vectors: string[];
  threat_vector_count: number;
  max_ingest_bytes: number;
  max_upload_bytes?: number;
  max_file_bytes: number;
  deployment_mode?: "serverless" | "standalone";
  supported_llm_providers: Array<{ id: string; label: string; requiresApiKey: boolean; supportsCustomBaseUrl: boolean }>;
}

export interface ScanOptions {
  useLlm?: boolean;
  llmProvider?: string;
  llmModel?: string;
  llmApiKey?: string;
  llmBaseUrl?: string;
  followTransitiveLinks?: boolean;
  outputFormat?: "terminal" | "json" | "markdown" | "sarif";
  baselinePath?: string;
  baselineData?: BaselineDocument;
  showSuppressed?: boolean;
  exclude?: string[];
  yaraRulesDir?: string;
  includeSourceContents?: boolean;
  offlineOsv?: boolean;
}
