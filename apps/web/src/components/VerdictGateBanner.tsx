import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCheck2,
  ShieldCheck,
  XCircle,
  Zap,
} from "lucide-react";
import type React from "react";
import { useState } from "react";
import type { ScanReport } from "@/types/scanner";

interface VerdictGateBannerProps {
  report: ScanReport;
  onExport: (format: "json" | "markdown" | "sarif" | "baseline") => void;
  onApplyBaselineToSession: () => void;
}

export const VerdictGateBanner: React.FC<VerdictGateBannerProps> = ({
  report,
  onExport,
  onApplyBaselineToSession,
}) => {
  const [showVectorMatrix, setShowVectorMatrix] = useState(true);
  const { score, recommendation, safe_to_install, score_breakdown } = report.risk_assessment;
  const execSummary = report.executive_summary;

  const theme =
    recommendation === "SAFE"
      ? {
          accent: "var(--verdict-safe)",
          bg: "var(--verdict-safe-bg)",
          border: "rgba(16, 185, 129, 0.42)",
          headline: "SAFE TO USE",
          Icon: CheckCircle2,
        }
      : recommendation === "CAUTION"
        ? {
            accent: "var(--verdict-caution)",
            bg: "var(--verdict-caution-bg)",
            border: "rgba(245, 158, 11, 0.45)",
            headline: "CAUTION — REVIEW BEFORE USING",
            Icon: AlertTriangle,
          }
        : {
            accent: "var(--verdict-block)",
            bg: "var(--verdict-block-bg)",
            border: "rgba(239, 68, 68, 0.5)",
            headline: "UNSAFE — DO NOT INSTALL",
            Icon: AlertOctagon,
          };

  const VerdictIcon = theme.Icon;
  const totalSegments = 25;
  const filledSegments = Math.round((score / 100) * totalSegments);
  const passedVectors = execSummary.category_checks.filter((c) => c.status === "pass").length;

  return (
    <section
      className="relative overflow-hidden rounded-md border p-5"
      style={{
        backgroundColor: "var(--bg-panel)",
        borderColor: theme.border,
        boxShadow: `inset 4px 0 0 0 ${theme.accent}`,
      }}
    >
      <div className="flex flex-col justify-between gap-6 lg:flex-row lg:items-start">
        {/* Left: Plain-English Executive Verdict + Capabilities */}
        <div className="flex-1 space-y-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className="font-mono-code inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-bold uppercase tracking-wider"
              style={{ backgroundColor: theme.bg, color: theme.accent, border: `1px solid ${theme.border}` }}
            >
              <VerdictIcon className="h-4 w-4" />
              {theme.headline}
            </span>

            <span
              className="font-mono-code inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px]"
              style={{ borderColor: "var(--border-strong)", color: "var(--text-secondary)" }}
            >
              <Zap className="h-3 w-3 text-cyan-400" />
              {report.skill.duration_ms} ms
            </span>

            <span
              className="font-mono-code inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px]"
              style={{ borderColor: "var(--border-strong)", color: "var(--text-secondary)" }}
            >
              <ShieldCheck className="h-3 w-3 text-emerald-400" />
              {passedVectors}/{execSummary.category_checks.length} Threat Vectors Clear
            </span>

            <span
              className="font-mono-code rounded border px-2 py-0.5 text-[11px]"
              style={{ borderColor: "var(--border-grid)", color: "var(--text-muted)" }}
            >
              safe_to_install={String(safe_to_install)}
            </span>
          </div>

          <div>
            <h1 className="font-display text-2xl font-bold tracking-tight text-white sm:text-3xl">
              {report.skill.name}
            </h1>
            {report.skill.description && (
              <p className="mt-1 text-xs italic text-slate-400">
                Claimed purpose: &ldquo;{report.skill.description}&rdquo;
              </p>
            )}
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-200">
              {execSummary.plain_verdict}
            </p>
          </div>

          {/* Detected Capabilities Chips */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            <span className="font-mono-code mr-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Detected Behavior:
            </span>
            {execSummary.detected_capabilities.map((cap) => (
              <span
                key={cap}
                className="font-mono-code rounded border px-2 py-0.5 text-[11px] text-slate-300"
                style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
              >
                {cap}
              </span>
            ))}
          </div>
        </div>

        {/* Right: 0-100 Segmented Telemetry Gauge */}
        <div
          className="min-w-[300px] rounded border p-3.5"
          style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-grid)" }}
        >
          <div className="flex items-baseline justify-between">
            <span className="font-mono-code text-[11px] uppercase tracking-wider text-slate-400">
              RISK SCORE
            </span>
            <div className="font-display flex items-baseline gap-1">
              <span className="text-3xl font-bold" style={{ color: theme.accent }}>
                {score}
              </span>
              <span className="font-mono-code text-xs text-slate-500">/ 100</span>
            </div>
          </div>

          <div className="mt-2.5 grid grid-cols-25 gap-1">
            {Array.from({ length: totalSegments }).map((_, idx) => {
              const active = idx < filledSegments;
              const segColor = idx < 5 ? "#10b981" : idx < 13 ? "#f59e0b" : "#ef4444";
              return (
                <div
                  key={`seg-${idx}`}
                  className="h-2.5 rounded-[1px] transition-all"
                  style={{
                    backgroundColor: active ? segColor : "#18202e",
                    opacity: active ? 1 : 0.45,
                  }}
                />
              );
            })}
          </div>

          <div className="font-mono-code mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <div className="flex items-center gap-2">
              <span className="text-rose-400">CRIT:{score_breakdown.critical_count}</span>
              <span className="text-orange-400">HIGH:{score_breakdown.high_count}</span>
              <span className="text-amber-300">MED:{score_breakdown.medium_count}</span>
              <span className="text-emerald-400">LOW:{score_breakdown.low_count}</span>
            </div>
            {score_breakdown.executable_multiplier_applied && (
              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-300">
                1.3× EXEC SCRIPT
              </span>
            )}
          </div>
        </div>
      </div>

      {/* 23-Category Threat Vector Shield Matrix */}
      {showVectorMatrix && (
        <div className="mt-4 border-t pt-3.5" style={{ borderColor: "var(--border-grid)" }}>
          <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
            {execSummary.category_checks.map((vec) => (
              <div
                key={vec.category}
                className="font-mono-code flex items-center justify-between rounded border px-2 py-1 text-[10px]"
                style={{
                  backgroundColor:
                    vec.status === "fail"
                      ? "rgba(239, 68, 68, 0.1)"
                      : vec.status === "warn"
                        ? "rgba(245, 158, 11, 0.1)"
                        : "var(--bg-chassis)",
                  borderColor:
                    vec.status === "fail"
                      ? "rgba(239, 68, 68, 0.4)"
                      : vec.status === "warn"
                        ? "rgba(245, 158, 11, 0.38)"
                        : "var(--border-grid)",
                }}
              >
                <span className="truncate pr-1 text-slate-300">{vec.category}</span>
                {vec.status === "pass" ? (
                  <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-400" />
                ) : vec.status === "warn" ? (
                  <span className="shrink-0 font-bold text-amber-300">{vec.issues_count}</span>
                ) : (
                  <span className="inline-flex shrink-0 items-center gap-0.5 font-bold text-rose-400">
                    <XCircle className="h-3 w-3" />
                    {vec.issues_count}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Bottom Action & Export Strip */}
      <div
        className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t pt-3"
        style={{ borderColor: "var(--border-grid)" }}
      >
        <div className="font-mono-code flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
          <button
            type="button"
            onClick={() => setShowVectorMatrix((v) => !v)}
            className="cursor-pointer text-cyan-300 hover:underline"
          >
            {showVectorMatrix
              ? `Hide ${execSummary.category_checks.length}-Vector Shield`
              : `Show ${execSummary.category_checks.length}-Vector Shield`}
          </button>
          <span>·</span>
          <span>FILES: {report.components.length}</span>
          <span>·</span>
          <span>COVERAGE: {report.inspection_completeness.coverage_percent}%</span>
          {report.deobfuscation_events.length > 0 && (
            <>
              <span>·</span>
              <span className="text-amber-300">
                HIDDEN LAYERS DECODED: {report.deobfuscation_events.length}
              </span>
            </>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {report.issues.length > 0 && (
            <button
              type="button"
              onClick={onApplyBaselineToSession}
              className="font-mono-code flex cursor-pointer items-center gap-1.5 rounded border border-cyan-400/40 bg-cyan-400/10 px-2.5 py-1 text-[11px] text-cyan-300 transition-colors hover:bg-cyan-400/20"
              title="Generate SHA-256 baseline from current findings and test suppression"
            >
              <FileCheck2 className="h-3.5 w-3.5" />
              Test Baseline Suppression
            </button>
          )}
          {(["json", "markdown", "sarif", "baseline"] as const).map((fmt) => (
            <button
              key={fmt}
              type="button"
              onClick={() => onExport(fmt)}
              className="font-mono-code flex cursor-pointer items-center gap-1 rounded border px-2.5 py-1 text-[11px] text-slate-300 transition-colors hover:border-slate-500 hover:text-white"
              style={{ backgroundColor: "var(--bg-elevated)", borderColor: "var(--border-grid)" }}
            >
              <Download className="h-3 w-3" />
              {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
};
