import { Activity, ShieldAlert } from "lucide-react";
import type React from "react";
import type { EngineCapabilities } from "@/types/scanner";

interface NavbarProps {
  engineMeta?: EngineCapabilities | null;
  historyCount?: number;
  onSelectHistoryToggle?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  engineMeta,
  historyCount = 0,
  onSelectHistoryToggle,
}) => {
  return (
    <header
      className="sticky top-0 z-40 border-b backdrop-blur-md"
      style={{
        backgroundColor: "rgba(7, 9, 13, 0.88)",
        borderColor: "var(--border-grid)",
      }}
    >
      <div className="mx-auto flex h-14 max-w-[1480px] items-center justify-between px-4 sm:px-6">
        <div className="flex items-center gap-3.5">
          <div
            className="flex h-8 w-8 items-center justify-center rounded border"
            style={{
              backgroundColor: "var(--accent-telemetry-dim)",
              borderColor: "rgba(34, 211, 238, 0.4)",
              color: "var(--accent-telemetry)",
            }}
          >
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div className="flex items-baseline gap-2.5">
            <span className="font-display text-base font-bold tracking-tight text-white">
              SKILLSPECTATOR
            </span>
            {engineMeta && (
              <span
                className="font-mono-code hidden text-[11px] uppercase tracking-widest sm:inline"
                style={{ color: "var(--accent-telemetry)" }}
              >
                // v{engineMeta.version}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {engineMeta && (
            <div
              className="font-mono-code hidden items-center gap-2 rounded border px-2.5 py-1 text-[11px] md:flex"
              style={{
                backgroundColor: "var(--bg-panel)",
                borderColor: "var(--border-grid)",
                color: "var(--text-secondary)",
              }}
            >
              <Activity className="h-3.5 w-3.5 text-emerald-400" />
              <span>
                {engineMeta.active_rule_count} RULES · {engineMeta.threat_vector_count} VECTORS
              </span>
              <span style={{ color: "var(--text-muted)" }}>·</span>
              <span>STATIC + AST + TAINT + YARA + OSV</span>
            </div>
          )}

          {onSelectHistoryToggle && (
            <button
              type="button"
              onClick={onSelectHistoryToggle}
              className="font-mono-code flex cursor-pointer items-center gap-2 rounded border px-3 py-1 text-xs transition-colors hover:border-cyan-400/50 hover:text-white"
              style={{
                backgroundColor: "var(--bg-elevated)",
                borderColor: "var(--border-strong)",
                color: "var(--text-secondary)",
              }}
            >
              <span>RECENT SCANS</span>
              <span
                className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
                style={{
                  backgroundColor: "var(--accent-telemetry-dim)",
                  color: "var(--accent-telemetry)",
                }}
              >
                {historyCount}
              </span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
