import {
  CheckCircle2,
  ChevronRight,
  Cpu,
  Eye,
  FileCode2,
  FileText,
  Layers,
  ShieldAlert,
} from "lucide-react";
import type React from "react";
import { useEffect, useMemo, useState } from "react";
import type { Finding, ScanReport, Severity } from "@/types/scanner";

interface ForensicXRayWorkbenchProps {
  report: ScanReport;
}

function severityPillClass(sev: Severity): string {
  switch (sev) {
    case "CRITICAL":
      return "bg-rose-500/20 text-rose-300 border-rose-500/50";
    case "HIGH":
      return "bg-orange-500/15 text-orange-300 border-orange-500/40";
    case "MEDIUM":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case "LOW":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
  }
}

export const ForensicXRayWorkbench: React.FC<ForensicXRayWorkbenchProps> = ({ report }) => {
  const [severityFilter, setSeverityFilter] = useState<"ALL" | Severity>("ALL");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    report.issues[0]?.finding_id ?? null,
  );
  const [selectedFilePath, setSelectedFilePath] = useState<string>(
    report.issues[0]?.location.file ?? report.components[0]?.path ?? "SKILL.md",
  );
  const [rightTab, setRightTab] = useState<"source" | "telemetry">("source");

  useEffect(() => {
    const firstIssue = report.issues[0];
    setSelectedFindingId(firstIssue?.finding_id ?? null);
    setSelectedFilePath(firstIssue?.location.file ?? report.components[0]?.path ?? "SKILL.md");
    setSeverityFilter("ALL");
  }, [report]);

  const filteredIssues = useMemo(() => {
    if (severityFilter === "ALL") return report.issues;
    return report.issues.filter((i) => i.severity === severityFilter);
  }, [report.issues, severityFilter]);

  const selectedFinding = useMemo(
    () => report.issues.find((f) => f.finding_id === selectedFindingId) ?? null,
    [report.issues, selectedFindingId],
  );

  const sortedComponents = useMemo(() => {
    const issueCountByFile = new Map<string, number>();
    for (const issue of report.issues) {
      issueCountByFile.set(issue.location.file, (issueCountByFile.get(issue.location.file) ?? 0) + 1);
    }
    return [...report.components].sort((a, b) => {
      const aManifest = a.path.split("/").pop()?.toLowerCase() === "skill.md" ? 0 : 1;
      const bManifest = b.path.split("/").pop()?.toLowerCase() === "skill.md" ? 0 : 1;
      if (aManifest !== bManifest) return aManifest - bManifest;
      const aHits = issueCountByFile.get(a.path) ?? 0;
      const bHits = issueCountByFile.get(b.path) ?? 0;
      if (aHits !== bHits) return bHits - aHits;
      return a.path.localeCompare(b.path);
    });
  }, [report.components, report.issues]);

  const activeComponent = useMemo(
    () => report.components.find((c) => c.path === selectedFilePath) ?? sortedComponents[0],
    [report.components, sortedComponents, selectedFilePath],
  );

  // Auto-scroll the Source Code X-Ray viewport to the selected finding line
  useEffect(() => {
    if (rightTab !== "source" || !selectedFinding) return;
    if (selectedFinding.location.file !== activeComponent?.path) return;
    const rowEl = document.getElementById(`xray-line-${selectedFinding.location.start_line}`);
    rowEl?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [rightTab, selectedFinding, activeComponent?.path]);

  const lineFindingsMap = useMemo(() => {
    const map = new Map<number, Finding[]>();
    for (const issue of report.issues) {
      if (issue.location.file !== activeComponent?.path) continue;
      for (let ln = issue.location.start_line; ln <= issue.location.end_line; ln++) {
        const arr = map.get(ln) ?? [];
        arr.push(issue);
        map.set(ln, arr);
      }
    }
    return map;
  }, [report.issues, activeComponent]);

  const handleSelectFinding = (issue: Finding) => {
    setSelectedFindingId(issue.finding_id);
    setSelectedFilePath(issue.location.file);
    setRightTab("source");
  };

  const codeLines = useMemo(() => {
    if (!activeComponent?.content) return [];
    return activeComponent.content.split(/\r?\n/);
  }, [activeComponent]);

  return (
    <div className="grid gap-4 lg:grid-cols-12">
      {/* LEFT PANE: Findings & De-obfuscation Feed (5 cols) */}
      <div
        className="flex flex-col rounded-md border lg:col-span-5"
        style={{ backgroundColor: "var(--bg-panel)", borderColor: "var(--border-grid)" }}
      >
        <div
          className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3"
          style={{ borderColor: "var(--border-grid)", backgroundColor: "var(--bg-elevated)" }}
        >
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
            <span className="font-display text-xs font-bold uppercase tracking-wider text-white">
              Security Findings ({filteredIssues.length})
            </span>
          </div>

          <div className="flex items-center gap-1">
            {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
              const active = severityFilter === sev;
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className="font-mono-code cursor-pointer rounded px-2 py-0.5 text-[10px] font-semibold transition-colors"
                  style={{
                    backgroundColor: active ? "var(--accent-telemetry-dim)" : "transparent",
                    color: active ? "var(--accent-telemetry)" : "var(--text-muted)",
                  }}
                >
                  {sev === "CRITICAL" ? "CRIT" : sev}
                </button>
              );
            })}
          </div>
        </div>

        <div className="max-h-[640px] flex-1 space-y-2.5 overflow-y-auto p-3">
          {/* De-obfuscation Interceptor Banner */}
          {report.deobfuscation_events.length > 0 && (
            <div
              className="rounded border p-3"
              style={{
                backgroundColor: "rgba(245, 158, 11, 0.08)",
                borderColor: "rgba(245, 158, 11, 0.35)",
              }}
            >
              <div className="font-mono-code mb-1.5 flex items-center gap-1.5 text-[11px] font-bold text-amber-300">
                <Eye className="h-3.5 w-3.5" />
                DE-OBFUSCATION PRE-PASS ({report.deobfuscation_events.length} HIDDEN LAYER
                {report.deobfuscation_events.length > 1 ? "S" : ""})
              </div>
              <div className="space-y-1.5">
                {report.deobfuscation_events.map((ev, idx) => (
                  <button
                    key={`${ev.file}-${ev.line}-${ev.kind}-${idx}`}
                    type="button"
                    onClick={() => {
                      setSelectedFilePath(ev.file);
                      setRightTab("source");
                    }}
                    className="block w-full cursor-pointer rounded border border-amber-500/20 bg-black/30 p-2 text-left transition-colors hover:border-amber-400/50"
                  >
                    <div className="font-mono-code flex items-center justify-between text-[10px] text-amber-200">
                      <span>[{ev.kind.toUpperCase()}]</span>
                      <span>
                        {ev.file}:{ev.line}
                      </span>
                    </div>
                    <p className="mt-0.5 text-[11px] text-slate-300">{ev.summary}</p>
                    {ev.decoded_preview && (
                      <pre className="font-mono-code mt-1 overflow-x-auto rounded bg-black/50 px-2 py-1 text-[10px] text-cyan-300">
                        Decoded: {ev.decoded_preview}
                      </pre>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {filteredIssues.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 text-center">
              <CheckCircle2 className="mb-2.5 h-9 w-9 text-emerald-400" />
              <p className="font-display text-sm font-semibold text-white">
                Zero Active Findings in Filter
              </p>
              <p className="mt-1 max-w-xs text-xs text-slate-400">
                All deterministic static, behavioral AST, taint-flow, YARA, and supply-chain checks passed cleanly.
              </p>
            </div>
          ) : (
            filteredIssues.map((issue) => {
              const isSelected = issue.finding_id === selectedFindingId;
              return (
                <button
                  key={issue.finding_id}
                  type="button"
                  onClick={() => handleSelectFinding(issue)}
                  className="w-full cursor-pointer rounded border p-3 text-left transition-all"
                  style={{
                    backgroundColor: isSelected ? "rgba(34, 211, 238, 0.06)" : "var(--bg-chassis)",
                    borderColor: isSelected ? "rgba(34, 211, 238, 0.55)" : "var(--border-grid)",
                  }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span
                        className={`font-mono-code rounded border px-1.5 py-0.5 text-[10px] font-bold ${severityPillClass(
                          issue.severity,
                        )}`}
                      >
                        {issue.severity}
                      </span>
                      <span className="font-mono-code text-xs font-bold text-cyan-300">
                        {issue.id}
                      </span>
                      <span className="font-mono-code text-[10px] text-slate-500">
                        {Math.round(issue.confidence * 100)}% conf
                      </span>
                    </div>
                    <span className="font-mono-code flex items-center gap-0.5 text-[11px] text-slate-400">
                      {issue.location.file}:{issue.location.start_line}
                      <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
                    </span>
                  </div>

                  <h4 className="mt-1.5 text-xs font-semibold text-white">{issue.pattern}</h4>
                  <p className="mt-1 text-xs leading-relaxed text-slate-400">{issue.explanation}</p>

                  <div className="font-mono-code mt-2 truncate rounded border border-slate-800 bg-black/40 px-2 py-1 text-[11px] text-rose-300">
                    {issue.finding}
                  </div>

                  <div className="mt-2 rounded bg-cyan-950/30 px-2.5 py-1.5 text-[11px] text-cyan-200/90">
                    <span className="font-semibold text-cyan-300">Fix: </span>
                    {issue.remediation}
                  </div>
                </button>
              );
            })
          )}

          {/* Suppressed findings note */}
          {report.suppressed.length > 0 && (
            <div className="rounded border border-slate-800 bg-black/30 p-3">
              <p className="font-mono-code text-[11px] font-semibold text-slate-300">
                SUPPRESSED BY BASELINE ({report.suppressed.length})
              </p>
              <div className="mt-1.5 space-y-1">
                {report.suppressed.map((sup) => (
                  <div
                    key={sup.finding_id}
                    className="font-mono-code flex items-center justify-between text-[11px] text-slate-500"
                  >
                    <span>
                      {sup.id} · {sup.location.file}:{sup.location.start_line}
                    </span>
                    <span className="truncate pl-2">{sup.suppression_reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* RIGHT PANE: Source Code X-Ray + Analyzer Telemetry Matrix (7 cols) */}
      <div
        className="flex flex-col rounded-md border lg:col-span-7"
        style={{ backgroundColor: "var(--bg-panel)", borderColor: "var(--border-grid)" }}
      >
        {/* Top bar: File tabs & Telemetry switch */}
        <div
          className="flex flex-wrap items-center justify-between gap-2 border-b px-3 py-2.5"
          style={{ borderColor: "var(--border-grid)", backgroundColor: "var(--bg-elevated)" }}
        >
          <div className="flex max-h-24 flex-1 flex-wrap items-center gap-1.5 overflow-y-auto pr-1">
            {sortedComponents.map((comp) => {
              const active = rightTab === "source" && comp.path === activeComponent?.path;
              const fileIssueCount = report.issues.filter((i) => i.location.file === comp.path).length;
              return (
                <button
                  key={comp.path}
                  type="button"
                  onClick={() => {
                    setSelectedFilePath(comp.path);
                    setRightTab("source");
                  }}
                  className="font-mono-code flex cursor-pointer items-center gap-1.5 rounded border px-2.5 py-1 text-xs transition-colors"
                  style={{
                    backgroundColor: active ? "var(--accent-telemetry-dim)" : "var(--bg-chassis)",
                    borderColor: active ? "rgba(34, 211, 238, 0.5)" : "var(--border-grid)",
                    color: active ? "var(--accent-telemetry)" : "var(--text-secondary)",
                  }}
                >
                  {comp.executable ? (
                    <FileCode2 className="h-3.5 w-3.5 text-amber-400" />
                  ) : (
                    <FileText className="h-3.5 w-3.5 text-slate-400" />
                  )}
                  <span>{comp.path}</span>
                  {fileIssueCount > 0 && (
                    <span className="rounded bg-rose-500/20 px-1.5 text-[10px] font-bold text-rose-300">
                      {fileIssueCount}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <button
            type="button"
            onClick={() => setRightTab((t) => (t === "source" ? "telemetry" : "source"))}
            className="font-mono-code flex cursor-pointer items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] transition-colors"
            style={{
              backgroundColor: rightTab === "telemetry" ? "var(--accent-telemetry-dim)" : "transparent",
              borderColor: rightTab === "telemetry" ? "rgba(34, 211, 238, 0.5)" : "var(--border-strong)",
              color: rightTab === "telemetry" ? "var(--accent-telemetry)" : "var(--text-secondary)",
            }}
          >
            <Layers className="h-3.5 w-3.5" />
            <span>
              {rightTab === "telemetry"
                ? "BACK TO X-RAY SOURCE"
                : `ANALYZER MATRIX (${report.inspection_completeness.analyzer_statuses.length})`}
            </span>
          </button>
        </div>

        {/* Right Body */}
        {rightTab === "source" ? (
          <div className="flex flex-1 flex-col justify-between">
            <div className="max-h-[590px] overflow-auto p-0" style={{ backgroundColor: "var(--bg-chassis)" }}>
              {activeComponent?.content ? (
                <table className="font-mono-code w-full border-collapse text-xs">
                  <tbody>
                    {codeLines.map((lineText, idx) => {
                      const ln = idx + 1;
                      const hits = lineFindingsMap.get(ln);
                      const isSelectedLine =
                        selectedFinding?.location.file === activeComponent.path &&
                        ln >= selectedFinding.location.start_line &&
                        ln <= selectedFinding.location.end_line;

                      const rowBg = isSelectedLine
                        ? "rgba(239, 68, 68, 0.2)"
                        : hits
                          ? "rgba(245, 158, 11, 0.1)"
                          : "transparent";

                      return (
                        <tr
                          key={`${activeComponent.path}-L${ln}`}
                          id={`xray-line-${ln}`}
                          style={{ backgroundColor: rowBg }}
                          className="hover:bg-white/[0.03]"
                        >
                          <td
                            className="w-12 select-none border-r px-2.5 py-0.5 text-right text-[11px]"
                            style={{
                              borderColor: "var(--border-grid)",
                              color: hits ? "#fca5a5" : "var(--text-muted)",
                            }}
                          >
                            {ln}
                          </td>
                          <td className="px-3 py-0.5 whitespace-pre text-slate-200">
                            <span>{lineText || " "}</span>
                            {hits && (
                              <span className="ml-3 inline-flex items-center gap-1 align-middle">
                                {hits.map((h) => (
                                  <span
                                    key={h.finding_id}
                                    className="rounded border border-rose-500/40 bg-rose-500/20 px-1.5 py-0 text-[10px] font-bold text-rose-300"
                                  >
                                    ⚑ {h.id}: {h.pattern}
                                  </span>
                                ))}
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div className="p-8 text-center text-xs text-slate-500">
                  Binary or oversized artifact — source preview omitted.
                </div>
              )}
            </div>

            {/* Component SHA-256 Metadata Footer */}
            {activeComponent && (
              <div
                className="font-mono-code flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-[11px]"
                style={{ borderColor: "var(--border-grid)", color: "var(--text-muted)" }}
              >
                <span>
                  TYPE: {activeComponent.type.toUpperCase()} · {activeComponent.lines} LINES ·{" "}
                  {activeComponent.size_bytes} BYTES · EXEC={String(activeComponent.executable)}
                </span>
                <span className="truncate">SHA256: {activeComponent.sha256.slice(0, 24)}…</span>
              </div>
            )}
          </div>
        ) : (
          <div className="max-h-[630px] overflow-y-auto p-4 space-y-4">
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <Cpu className="h-4 w-4 text-cyan-400" />
              <span className="font-display font-semibold">
                Analyzer Pipeline Ledger · OSV Mode: {report.metadata.osv_mode} · Scan Mode:{" "}
                {report.metadata.scan_mode}
              </span>
            </div>

            <div className="overflow-x-auto rounded border" style={{ borderColor: "var(--border-grid)" }}>
              <table className="font-mono-code w-full text-left text-xs">
                <thead style={{ backgroundColor: "var(--bg-elevated)", color: "var(--text-secondary)" }}>
                  <tr>
                    <th className="px-3 py-2">Analyzer Node</th>
                    <th className="px-3 py-2">Category</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2 text-right">Findings</th>
                    <th className="px-3 py-2 text-right">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {report.inspection_completeness.analyzer_statuses.map((st) => (
                    <tr
                      key={st.analyzer_id}
                      className="border-t"
                      style={{ borderColor: "var(--border-grid)" }}
                    >
                      <td className="px-3 py-2 text-slate-200">{st.analyzer_id}</td>
                      <td className="px-3 py-2 text-slate-400">{st.category}</td>
                      <td className="px-3 py-2">
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                            st.status === "completed"
                              ? "bg-emerald-500/15 text-emerald-300"
                              : st.status === "failed"
                                ? "bg-rose-500/20 text-rose-300"
                                : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {st.status}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-right text-slate-200">{st.findings_count}</td>
                      <td className="px-3 py-2 text-right text-slate-400">{st.duration_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {report.inspection_completeness.ledger_exceptions.length > 0 && (
              <div className="rounded border p-3" style={{ borderColor: "var(--border-grid)", backgroundColor: "var(--bg-chassis)" }}>
                <p className="font-mono-code mb-1.5 text-[11px] font-semibold text-amber-300">
                  INSPECTION LEDGER CAVEATS ({report.inspection_completeness.ledger_exceptions.length})
                </p>
                <div className="space-y-1">
                  {report.inspection_completeness.ledger_exceptions.map((ex, idx) => (
                    <div key={`${ex.file}-${idx}`} className="font-mono-code text-[11px] text-slate-400">
                      [{ex.kind}] {ex.file}
                      {ex.line ? `:${ex.line}` : ""} — {ex.message}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
