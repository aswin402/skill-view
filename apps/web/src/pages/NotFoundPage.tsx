import { MoveLeft, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <div className="forensic-grid-bg flex min-h-screen flex-col items-center justify-center px-6 py-16 text-center">
      <div
        className="mb-4 flex h-12 w-12 items-center justify-center rounded-full border"
        style={{
          backgroundColor: "var(--accent-telemetry-dim)",
          borderColor: "rgba(34, 211, 238, 0.4)",
          color: "var(--accent-telemetry)",
        }}
      >
        <ShieldAlert className="h-6 w-6" />
      </div>
      <p className="font-mono-code text-xs uppercase tracking-widest text-cyan-400">HTTP 404</p>
      <h1 className="font-display mt-2 text-3xl font-bold tracking-tight text-white sm:text-4xl">
        Route Not Found
      </h1>
      <p className="mt-2 max-w-md text-xs leading-relaxed text-slate-400">
        The requested path does not exist on SkillSpectator. Return to the scanner workbench to inspect an AI agent skill.
      </p>
      <Link
        to="/"
        className="font-display mt-6 inline-flex items-center gap-2 rounded bg-cyan-400 px-5 py-2.5 text-xs font-bold tracking-wide text-slate-950 transition-opacity hover:opacity-90"
      >
        <MoveLeft className="h-4 w-4" />
        Back to Scanner
      </Link>
    </div>
  );
}
