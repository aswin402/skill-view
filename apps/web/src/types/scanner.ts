export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Recommendation = "SAFE" | "CAUTION" | "DO_NOT_INSTALL";

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
  surface: string;
  tags: string[];
  evidence: Record<string, unknown>;
  match_fingerprint: string;
  llm_review_outcome?: string;
}

export interface SuppressedFinding extends Finding {
  suppression_reason: string;
}

export interface DeobfuscationEvent {
  file: string;
  line: number;
  kind: string;
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
  kind: string;
  file: string;
  line?: number;
  message: string;
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
  supported_llm_providers: Array<{
    id: string;
    label: string;
    requiresApiKey: boolean;
    supportsCustomBaseUrl: boolean;
  }>;
}

export interface ScanReport {
  skill: {
    name: string;
    description?: string;
    source: string;
    source_kind: string;
    scanned_at: string;
    duration_ms: number;
  };
  risk_assessment: {
    score: number;
    severity: Severity;
    recommendation: Recommendation;
    safe_to_install: boolean;
    max_issue_severity: Severity | "NONE";
    score_breakdown: {
      raw_points: number;
      executable_multiplier_applied: boolean;
      critical_count: number;
      high_count: number;
      medium_count: number;
      low_count: number;
    };
  };
  executive_summary: ExecutiveSummary;
  components: ComponentInfo[];
  issues: Finding[];
  suppressed: SuppressedFinding[];
  deobfuscation_events: DeobfuscationEvent[];
  inspection_completeness: {
    total_components: number;
    scanned_components: number;
    coverage_percent: number;
    is_complete: boolean;
    status: string;
    execution_successful: boolean;
    fully_inspected_files: number;
    partially_inspected_files: number;
    entirely_uninspected_files: number;
    ledger_exceptions: LedgerException[];
    scope_exclusions: string[];
    analyzer_statuses: AnalyzerStatusRecord[];
  };
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
    osv_mode: string;
  };
}

export interface VirtualFileInput {
  path: string;
  content: string;
}

export interface HistorySummary {
  id: string;
  skillName: string;
  source: string;
  sourceKind: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  severity: Severity;
  recommendation: Recommendation;
  issuesCount: number;
}
