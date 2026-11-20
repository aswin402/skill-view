import type { HistorySummary, ScanReport } from "@/types/scanner";

const STORAGE_KEY = "skillspectator:history:v1";
const MAX_STORED_SCANS = 20;

interface StoredScanRecord {
  id: string;
  summary: HistorySummary;
  report: ScanReport;
}

function toSummary(id: string, report: ScanReport): HistorySummary {
  return {
    id,
    skillName: report.skill.name,
    source: report.skill.source,
    sourceKind: report.skill.source_kind,
    scannedAt: report.skill.scanned_at,
    durationMs: report.skill.duration_ms,
    score: report.risk_assessment.score,
    severity: report.risk_assessment.severity,
    recommendation: report.risk_assessment.recommendation,
    issuesCount: report.issues.length,
  };
}

function readRecords(): StoredScanRecord[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as StoredScanRecord[]) : [];
  } catch {
    return [];
  }
}

function compactReportForStorage(report: ScanReport, stripAllContent = false): ScanReport {
  if (stripAllContent) {
    return {
      ...report,
      components: report.components.map(({ content: _omit, ...rest }) => rest),
    };
  }
  const hitFiles = new Set(report.issues.map((i) => i.location.file));
  return {
    ...report,
    components: report.components.map((comp) => {
      const isManifest = comp.path.split("/").pop()?.toLowerCase() === "skill.md";
      if (isManifest || hitFiles.has(comp.path)) return comp;
      const { content: _omit, ...rest } = comp;
      return rest;
    }),
  };
}

function writeRecords(records: StoredScanRecord[]): void {
  if (typeof window === "undefined") return;
  const trimmed = records.slice(0, MAX_STORED_SCANS);
  while (trimmed.length > 0) {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
      return;
    } catch {
      if (trimmed.length === 1) {
        // Single large report exceeded quota — retry with compact content, then metadata-only
        const only = trimmed[0]!;
        try {
          window.localStorage.setItem(
            STORAGE_KEY,
            JSON.stringify([{ ...only, report: compactReportForStorage(only.report, false) }]),
          );
          return;
        } catch {
          try {
            window.localStorage.setItem(
              STORAGE_KEY,
              JSON.stringify([{ ...only, report: compactReportForStorage(only.report, true) }]),
            );
            return;
          } catch {
            break;
          }
        }
      }
      // Storage quota exceeded — evict oldest scan and retry
      trimmed.pop();
    }
  }
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage restriction errors
  }
}

export function listStoredHistory(): HistorySummary[] {
  return readRecords().map((r) => r.summary);
}

export function getStoredScan(id: string): { scanId: string; report: ScanReport } | null {
  const found = readRecords().find((r) => r.id === id);
  return found ? { scanId: found.id, report: found.report } : null;
}

export function saveStoredScan(id: string, report: ScanReport): HistorySummary[] {
  const existing = readRecords().filter((r) => r.id !== id);
  const next: StoredScanRecord[] = [{ id, summary: toSummary(id, report), report }, ...existing];
  writeRecords(next);
  return next.slice(0, MAX_STORED_SCANS).map((r) => r.summary);
}

export function clearStoredHistory(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage restriction errors
  }
}
