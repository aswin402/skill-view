import { Clock, ShieldCheck, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  exportScanArtifact,
  fetchEngineMeta,
  fetchHistoryEntry,
  scanInlinePayload,
  scanRemoteSkillUrl,
  scanUploadedFiles,
} from "@/api/scannerApi";
import { ForensicXRayWorkbench } from "@/components/ForensicXRayWorkbench";
import { Navbar } from "@/components/Navbar";
import { type CommonScanFlags, SkillIntakePanel } from "@/components/SkillIntakePanel";
import { VerdictGateBanner } from "@/components/VerdictGateBanner";
import {
  clearStoredHistory,
  getStoredScan,
  listStoredHistory,
  saveStoredScan,
} from "@/lib/historyStore";
import type {
  EngineCapabilities,
  HistorySummary,
  ScanReport,
  VirtualFileInput,
} from "@/types/scanner";

export function HomePage() {
  const [engineMeta, setEngineMeta] = useState<EngineCapabilities | null>(null);
  const [history, setHistory] = useState<HistorySummary[]>(() => listStoredHistory());
  const [showHistoryDrawer, setShowHistoryDrawer] = useState(false);

  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [activeReport, setActiveReport] = useState<ScanReport | null>(null);
  const [baselineYaml, setBaselineYaml] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const recordCompletedScan = useCallback((scanId: string, report: ScanReport) => {
    setActiveScanId(scanId);
    setActiveReport(report);
    setHistory(saveStoredScan(scanId, report));
  }, []);

  useEffect(() => {
    let mounted = true;
    fetchEngineMeta()
      .then((meta) => {
        if (!mounted) return;
        setEngineMeta(meta);
      })
      .catch((err) => {
        if (mounted) setErrorMsg(err instanceof Error ? err.message : String(err));
      });
    return () => {
      mounted = false;
    };
  }, []);

  const handleScanInline = useCallback(
    async (params: { name?: string; files: VirtualFileInput[] } & CommonScanFlags) => {
      setIsScanning(true);
      setErrorMsg(null);
      try {
        const res = await scanInlinePayload({
          ...params,
          baselineYaml: baselineYaml || undefined,
        });
        recordCompletedScan(res.scanId, res.report);
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : String(err));
      } finally {
        setIsScanning(false);
      }
    },
    [baselineYaml, recordCompletedScan],
  );

  const handleScanUrl = useCallback(
    async (params: { url: string } & CommonScanFlags) => {
      setIsScanning(true);
      setErrorMsg(null);
      try {
        const res = await scanRemoteSkillUrl({
          ...params,
          baselineYaml: baselineYaml || undefined,
        });
        recordCompletedScan(res.scanId, res.report);
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : String(err));
      } finally {
        setIsScanning(false);
      }
    },
    [baselineYaml, recordCompletedScan],
  );

  const handleScanUpload = useCallback(
    async (params: { files: File[] } & CommonScanFlags) => {
      setIsScanning(true);
      setErrorMsg(null);
      try {
        const res = await scanUploadedFiles({
          ...params,
          baselineYaml: baselineYaml || undefined,
        });
        recordCompletedScan(res.scanId, res.report);
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : String(err));
      } finally {
        setIsScanning(false);
      }
    },
    [baselineYaml, recordCompletedScan],
  );

  const handleExport = useCallback(
    async (format: "json" | "markdown" | "sarif" | "baseline") => {
      if (!activeReport) return;
      try {
        const artifact = await exportScanArtifact({
          scanId: activeScanId ?? undefined,
          report: activeReport,
          format,
        });
        const blob = new Blob([artifact.content], { type: artifact.mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = artifact.filename;
        a.click();
        URL.revokeObjectURL(url);
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : String(err));
      }
    },
    [activeScanId, activeReport],
  );

  const handleApplyBaselineToSession = useCallback(async () => {
    if (!activeReport) return;
    try {
      const artifact = await exportScanArtifact({
        scanId: activeScanId ?? undefined,
        report: activeReport,
        format: "baseline",
        reason: "Reviewed and accepted in SkillSpectator Web",
      });
      setBaselineYaml(artifact.content);
      const virtualFiles = activeReport.components
        .filter((c) => c.content !== undefined)
        .map((c) => ({ path: c.path, content: c.content! }));

      if (virtualFiles.length > 0) {
        const res = await scanInlinePayload({
          name: activeReport.skill.name,
          files: virtualFiles,
          baselineYaml: artifact.content,
        });
        recordCompletedScan(res.scanId, res.report);
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err));
    }
  }, [activeScanId, activeReport, recordCompletedScan]);

  return (
    <div className="forensic-grid-bg min-h-screen">
      <Navbar
        engineMeta={engineMeta}
        historyCount={history.length}
        onSelectHistoryToggle={() => setShowHistoryDrawer((v) => !v)}
      />

      <main className="mx-auto max-w-[1480px] space-y-5 px-4 py-6 sm:px-6">
        <SkillIntakePanel
          engineMeta={engineMeta}
          isScanning={isScanning}
          baselineYaml={baselineYaml}
          onBaselineYamlChange={setBaselineYaml}
          onScanInline={handleScanInline}
          onScanUrl={handleScanUrl}
          onScanUpload={handleScanUpload}
        />

        {errorMsg && (
          <div className="font-mono-code rounded border border-rose-500/50 bg-rose-950/40 px-4 py-3 text-xs text-rose-200">
            ERROR: {errorMsg}
          </div>
        )}

        {isScanning && (
          <div
            className="animate-scan-pulse font-mono-code rounded border px-4 py-3 text-xs text-cyan-300"
            style={{
              backgroundColor: "var(--accent-telemetry-dim)",
              borderColor: "rgba(34, 211, 238, 0.4)",
            }}
          >
            ⚡ RUNNING SECURITY PIPELINE (DE-OBFUSCATION · STATIC · AST · TAINT · HOOKS · YARA · OSV)...
          </div>
        )}

        {activeReport ? (
          <>
            <VerdictGateBanner
              report={activeReport}
              onExport={handleExport}
              onApplyBaselineToSession={handleApplyBaselineToSession}
            />
            <ForensicXRayWorkbench report={activeReport} />
          </>
        ) : (
          !isScanning && (
            <section
              className="flex flex-col items-center justify-center rounded-md border px-6 py-16 text-center"
              style={{ backgroundColor: "var(--bg-panel)", borderColor: "var(--border-grid)" }}
            >
              <div
                className="mb-3.5 flex h-11 w-11 items-center justify-center rounded-full border"
                style={{
                  backgroundColor: "var(--accent-telemetry-dim)",
                  borderColor: "rgba(34, 211, 238, 0.35)",
                  color: "var(--accent-telemetry)",
                }}
              >
                <ShieldCheck className="h-5 w-5" />
              </div>
              <h3 className="font-display text-base font-bold text-white">
                Scanner Ready — No Skill Loaded Yet
              </h3>
              <p className="mt-1 max-w-lg text-xs leading-relaxed text-slate-400">
                Enter a GitHub skill URL above, upload a <code className="font-mono-code text-slate-300">.zip</code> or skill files, or paste{" "}
                <code className="font-mono-code text-slate-300">SKILL.md</code> content to generate a full security verdict, risk score, and line-by-line X-Ray report.
              </p>
              {engineMeta && (
                <div className="font-mono-code mt-4 flex flex-wrap justify-center gap-2 text-[11px] text-slate-500">
                  {engineMeta.threat_vectors.map((vec) => (
                    <span
                      key={vec}
                      className="rounded border px-2 py-0.5"
                      style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-grid)" }}
                    >
                      {vec}
                    </span>
                  ))}
                </div>
              )}
            </section>
          )
        )}
      </main>

      {showHistoryDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-xs">
          <div
            className="flex h-full w-full max-w-md flex-col border-l p-4"
            style={{ backgroundColor: "var(--bg-panel)", borderColor: "var(--border-strong)" }}
          >
            <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: "var(--border-grid)" }}>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-cyan-400" />
                <span className="font-display text-sm font-bold text-white">
                  Recent Scans ({history.length})
                </span>
              </div>
              <div className="flex items-center gap-2">
                {history.length > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      clearStoredHistory();
                      setHistory([]);
                    }}
                    className="font-mono-code flex cursor-pointer items-center gap-1 rounded border border-rose-500/30 px-2 py-0.5 text-[11px] text-rose-300 hover:bg-rose-500/10"
                  >
                    <Trash2 className="h-3 w-3" />
                    Clear
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowHistoryDrawer(false)}
                  className="cursor-pointer text-slate-400 hover:text-white"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div className="mt-3 flex-1 space-y-2 overflow-y-auto">
              {history.length === 0 ? (
                <p className="font-mono-code py-10 text-center text-xs text-slate-500">
                  No scans saved in this browser yet.
                </p>
              ) : (
                history.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={async () => {
                      const local = getStoredScan(item.id);
                      if (local) {
                        setActiveScanId(local.scanId);
                        setActiveReport(local.report);
                        setShowHistoryDrawer(false);
                        return;
                      }
                      try {
                        const loaded = await fetchHistoryEntry(item.id);
                        setActiveScanId(loaded.scanId);
                        setActiveReport(loaded.report);
                        setShowHistoryDrawer(false);
                      } catch (err) {
                        setErrorMsg(err instanceof Error ? err.message : String(err));
                      }
                    }}
                    className="w-full cursor-pointer rounded border p-3 text-left transition-colors hover:border-cyan-400/50"
                    style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-grid)" }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono-code text-xs font-bold text-white">
                        {item.skillName}
                      </span>
                      <span
                        className={`font-mono-code rounded px-1.5 py-0.5 text-[10px] font-bold ${
                          item.recommendation === "SAFE"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : item.recommendation === "CAUTION"
                              ? "bg-amber-500/15 text-amber-300"
                              : "bg-rose-500/20 text-rose-300"
                        }`}
                      >
                        {item.score}/100 · {item.recommendation}
                      </span>
                    </div>
                    <div className="font-mono-code mt-1 flex items-center justify-between text-[11px] text-slate-500">
                      <span>{item.issuesCount} issues · {item.durationMs} ms</span>
                      <span>{new Date(item.scannedAt).toLocaleTimeString()}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
