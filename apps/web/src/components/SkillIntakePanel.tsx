import {
  Code2,
  Cpu,
  FilePlus2,
  Globe,
  Link2,
  Play,
  SlidersHorizontal,
  Trash2,
  UploadCloud,
} from "lucide-react";
import type React from "react";
import { useCallback, useMemo, useRef, useState } from "react";
import type { EngineCapabilities, VirtualFileInput } from "@/types/scanner";

type IntakeMode = "url" | "upload" | "paste";

export interface CommonScanFlags {
  useLlm: boolean;
  llmProvider?: string;
  llmModel?: string;
  llmApiKey?: string;
  llmBaseUrl?: string;
  followTransitiveLinks: boolean;
}

interface SkillIntakePanelProps {
  engineMeta?: EngineCapabilities | null;
  isScanning: boolean;
  baselineYaml: string;
  onBaselineYamlChange: (val: string) => void;
  onScanInline: (params: { name?: string; files: VirtualFileInput[] } & CommonScanFlags) => void;
  onScanUrl: (params: { url: string } & CommonScanFlags) => void;
  onScanUpload: (params: { files: File[] } & CommonScanFlags) => void;
}

export const SkillIntakePanel: React.FC<SkillIntakePanelProps> = ({
  engineMeta,
  isScanning,
  baselineYaml,
  onBaselineYamlChange,
  onScanInline,
  onScanUrl,
  onScanUpload,
}) => {
  const [mode, setMode] = useState<IntakeMode>("url");
  const [bundleName, setBundleName] = useState("");
  const [editorFiles, setEditorFiles] = useState<VirtualFileInput[]>([
    { path: "SKILL.md", content: "" },
  ]);
  const [activeEditorIdx, setActiveEditorIdx] = useState(0);
  const [newFileName, setNewFileName] = useState("");

  const [urlInput, setUrlInput] = useState("");
  const [selectedUploads, setSelectedUploads] = useState<File[]>([]);
  const [uploadSizeError, setUploadSizeError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [useLlm, setUseLlm] = useState(false);
  const [llmProvider, setLlmProvider] = useState("");
  const [llmModel, setLlmModel] = useState("");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmBaseUrl, setLlmBaseUrl] = useState("");
  const [followTransitiveLinks, setFollowTransitiveLinks] = useState(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const providers = engineMeta?.supported_llm_providers ?? [];
  const activeProviderId = llmProvider || providers[0]?.id || "openai";
  const activeProviderMeta = useMemo(
    () => providers.find((p) => p.id === activeProviderId),
    [providers, activeProviderId],
  );

  const maxUploadBytes = engineMeta?.max_upload_bytes ?? engineMeta?.max_ingest_bytes ?? 100 * 1024 * 1024;
  const maxUploadLabel =
    maxUploadBytes < 10 * 1024 * 1024
      ? `${(maxUploadBytes / 1_000_000).toFixed(1)} MB`
      : `${Math.round(maxUploadBytes / (1024 * 1024))} MiB`;

  const buildFlags = useCallback(
    (): CommonScanFlags => ({
      useLlm,
      llmProvider: useLlm ? activeProviderId : undefined,
      llmModel: useLlm && llmModel.trim() ? llmModel.trim() : undefined,
      llmApiKey: useLlm && llmApiKey.trim() ? llmApiKey.trim() : undefined,
      llmBaseUrl: useLlm && llmBaseUrl.trim() ? llmBaseUrl.trim() : undefined,
      followTransitiveLinks,
    }),
    [useLlm, activeProviderId, llmModel, llmApiKey, llmBaseUrl, followTransitiveLinks],
  );

  const submitUploads = useCallback(
    (files: File[]) => {
      if (files.length === 0) return;
      const totalBytes = files.reduce((sum, f) => sum + f.size, 0);
      if (totalBytes > maxUploadBytes) {
        setUploadSizeError(
          `Selected upload (${(totalBytes / 1_000_000).toFixed(2)} MB) exceeds the ${maxUploadLabel} upload limit. Scan via GitHub URL or upload a smaller skill bundle.`,
        );
        return;
      }
      setUploadSizeError(null);
      setSelectedUploads(files);
      onScanUpload({
        files,
        ...buildFlags(),
      });
    },
    [buildFlags, maxUploadBytes, maxUploadLabel, onScanUpload],
  );

  const handleAddEditorFile = () => {
    const clean = newFileName.trim();
    if (!clean || editorFiles.some((f) => f.path === clean)) return;
    const next = [...editorFiles, { path: clean, content: "" }];
    setEditorFiles(next);
    setActiveEditorIdx(next.length - 1);
    setNewFileName("");
  };

  const handleRemoveEditorFile = (idx: number) => {
    if (editorFiles.length <= 1) return;
    const next = editorFiles.filter((_, i) => i !== idx);
    setEditorFiles(next);
    setActiveEditorIdx(Math.max(0, activeEditorIdx - 1));
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    submitUploads(Array.from(e.dataTransfer.files));
  };

  const currentFile = editorFiles[activeEditorIdx] ?? editorFiles[0]!;
  const hasNonEmptyEditorContent = editorFiles.some((f) => f.content.trim().length > 0);

  return (
    <section
      className="rounded-md border"
      style={{
        backgroundColor: "var(--bg-panel)",
        borderColor: "var(--border-grid)",
      }}
    >
      {/* Top Hero Strip */}
      <div
        className="border-b px-5 py-4"
        style={{
          borderColor: "var(--border-grid)",
          background: "linear-gradient(90deg, rgba(34,211,238,0.06) 0%, rgba(12,16,23,0) 65%)",
        }}
      >
        <h2 className="font-display text-lg font-bold tracking-tight text-white sm:text-xl">
          Inspect any AI Agent Skill before you install or trust it.
        </h2>
        <p className="mt-0.5 text-xs text-slate-400">
          Submit a GitHub skill link, upload a <code className="font-mono-code text-cyan-300">.zip</code> or skill files, or paste raw{" "}
          <code className="font-mono-code text-cyan-300">SKILL.md</code> and companion scripts for full static, AST, taint, YARA, and OSV vulnerability analysis.
        </p>
      </div>

      {/* Mode Selector Bar */}
      <div
        className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5"
        style={{ borderColor: "var(--border-grid)", backgroundColor: "var(--bg-elevated)" }}
      >
        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              { id: "url", label: "GitHub / Skill URL", icon: Globe },
              { id: "upload", label: "Upload .zip / Skill Files", icon: UploadCloud },
              { id: "paste", label: "Paste SKILL.md / Code", icon: Code2 },
            ] as const
          ).map((tab) => {
            const Icon = tab.icon;
            const active = mode === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setMode(tab.id)}
                className="font-mono-code flex cursor-pointer items-center gap-2 rounded border px-3 py-1.5 text-xs font-medium transition-all"
                style={{
                  backgroundColor: active ? "var(--accent-telemetry-dim)" : "transparent",
                  borderColor: active ? "rgba(34, 211, 238, 0.5)" : "transparent",
                  color: active ? "var(--accent-telemetry)" : "var(--text-secondary)",
                }}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          className="font-mono-code flex cursor-pointer items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] transition-colors hover:text-white"
          style={{
            borderColor:
              showAdvanced || baselineYaml.trim() || useLlm || followTransitiveLinks
                ? "rgba(34, 211, 238, 0.45)"
                : "var(--border-grid)",
            color:
              showAdvanced || baselineYaml.trim() || useLlm || followTransitiveLinks
                ? "var(--accent-telemetry)"
                : "var(--text-muted)",
          }}
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
          <span>
            ADVANCED {useLlm ? "· AI ON" : ""}
            {followTransitiveLinks ? " · TRANSITIVE" : ""}
          </span>
        </button>
      </div>

      {/* Collapsible Advanced Options */}
      {showAdvanced && (
        <div
          className="grid gap-4 border-b px-4 py-3.5 md:grid-cols-2"
          style={{ borderColor: "var(--border-grid)", backgroundColor: "rgba(17, 23, 34, 0.55)" }}
        >
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="font-mono-code flex items-center gap-2 text-xs font-medium text-slate-200">
                <Link2 className="h-3.5 w-3.5 text-cyan-400" />
                Follow External Links Inside SKILL.md (Transitive Scan)
              </label>
              <input
                type="checkbox"
                checked={followTransitiveLinks}
                onChange={(e) => setFollowTransitiveLinks(e.target.checked)}
                className="h-4 w-4 accent-cyan-400"
              />
            </div>

            <div className="space-y-2 border-t pt-2.5" style={{ borderColor: "var(--border-grid)" }}>
              <div className="flex items-center justify-between">
                <label className="font-mono-code flex items-center gap-2 text-xs font-medium text-slate-200">
                  <Cpu className="h-3.5 w-3.5 text-cyan-400" />
                  Optional Stage-2 AI Semantic Review
                </label>
                <input
                  type="checkbox"
                  checked={useLlm}
                  onChange={(e) => setUseLlm(e.target.checked)}
                  className="h-4 w-4 accent-cyan-400"
                />
              </div>
              {useLlm && (
                <div className="grid gap-2 sm:grid-cols-2">
                  <select
                    value={activeProviderId}
                    onChange={(e) => setLlmProvider(e.target.value)}
                    className="font-mono-code w-full rounded border px-2.5 py-1.5 text-xs text-white outline-none"
                    style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
                  >
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={llmModel}
                    onChange={(e) => setLlmModel(e.target.value)}
                    placeholder="Model ID (optional override)"
                    className="font-mono-code w-full rounded border px-2.5 py-1.5 text-xs text-white outline-none focus:border-cyan-400/60"
                    style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
                  />
                  {activeProviderMeta?.requiresApiKey && (
                    <input
                      type="password"
                      value={llmApiKey}
                      onChange={(e) => setLlmApiKey(e.target.value)}
                      placeholder="API Key (transient, never stored)"
                      className="font-mono-code w-full rounded border px-2.5 py-1.5 text-xs text-white outline-none focus:border-cyan-400/60 sm:col-span-2"
                      style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
                    />
                  )}
                  {activeProviderMeta?.supportsCustomBaseUrl && (
                    <input
                      type="url"
                      value={llmBaseUrl}
                      onChange={(e) => setLlmBaseUrl(e.target.value)}
                      placeholder="Custom Base URL (optional, e.g. https://.../v1)"
                      className="font-mono-code w-full rounded border px-2.5 py-1.5 text-xs text-white outline-none focus:border-cyan-400/60 sm:col-span-2"
                      style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
                    />
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-mono-code text-xs font-medium text-slate-200">
                Baseline Suppression YAML (Optional)
              </span>
              {baselineYaml && (
                <button
                  type="button"
                  onClick={() => onBaselineYamlChange("")}
                  className="font-mono-code cursor-pointer text-[11px] text-rose-400 hover:underline"
                >
                  Clear Baseline
                </button>
              )}
            </div>
            <textarea
              rows={3}
              value={baselineYaml}
              onChange={(e) => onBaselineYamlChange(e.target.value)}
              placeholder="# Paste a .skillspectator-baseline.yaml to suppress previously reviewed SHA-256 findings..."
              className="font-mono-code w-full rounded border p-2 text-xs text-slate-200 outline-none focus:border-cyan-400/60"
              style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
            />
          </div>
        </div>
      )}

      {/* Mode Body */}
      <div className="p-4">
        {mode === "url" && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!urlInput.trim()) return;
              onScanUrl({
                url: urlInput.trim(),
                ...buildFlags(),
              });
            }}
            className="space-y-2.5"
          >
            <label className="font-mono-code block text-xs text-slate-300">
              GitHub Repository URL, Skill Subfolder URL, Raw SKILL.md URL, or .zip Archive Link
            </label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input
                type="url"
                required
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://github.com/owner/repo/tree/main/skills/skill-name"
                className="font-mono-code flex-1 rounded border px-3.5 py-2.5 text-xs text-white outline-none focus:border-cyan-400/60"
                style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
              />
              <button
                type="submit"
                disabled={isScanning || !urlInput.trim()}
                className="font-display flex cursor-pointer items-center justify-center gap-2 rounded bg-cyan-400 px-5 py-2.5 text-xs font-bold tracking-wide text-slate-950 transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                {isScanning ? "FETCHING & SCANNING..." : "ANALYZE URL"}
              </button>
            </div>
            <p className="font-mono-code text-[11px] text-slate-500">
              Supports GitHub repos, <span className="text-slate-300">/tree/&lt;branch&gt;/&lt;folder&gt;</span> links,{" "}
              <span className="text-slate-300">/blob/</span> file links, raw <span className="text-slate-300">.md</span> files, and{" "}
              <span className="text-slate-300">.zip</span> URLs.
            </p>
          </form>
        )}

        {mode === "upload" && (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className="flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed px-6 py-10 text-center transition-all"
            style={{
              backgroundColor: isDragging ? "var(--accent-telemetry-dim)" : "var(--bg-chassis)",
              borderColor: isDragging ? "var(--accent-telemetry)" : "var(--border-strong)",
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".zip,.md,.py,.ts,.tsx,.js,.mjs,.sh,.json,.yaml,.yml,.toml,.txt"
              className="hidden"
              onChange={(e) => {
                submitUploads(Array.from(e.target.files ?? []));
                e.target.value = "";
              }}
            />
            <UploadCloud className="mb-3 h-8 w-8 text-cyan-400" />
            <p className="font-display text-sm font-semibold text-white">
              Drop a Skill <span className="text-cyan-400">.zip</span> archive, <span className="text-cyan-400">SKILL.md</span>, or companion scripts here
            </p>
            <p className="mt-1 text-xs text-slate-400">
              Static + AST + Taint inspection in memory · Uploaded code is never executed · Max upload: {maxUploadLabel}
            </p>
            {uploadSizeError && (
              <div className="font-mono-code mt-3 rounded border border-rose-500/40 bg-rose-950/40 px-3 py-1.5 text-xs text-rose-200">
                {uploadSizeError}
              </div>
            )}
            {selectedUploads.length > 0 && !uploadSizeError && (
              <div className="font-mono-code mt-3 rounded border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs text-cyan-300">
                Analyzed: {selectedUploads.map((f) => f.name).join(", ")}
              </div>
            )}
          </div>
        )}

        {mode === "paste" && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-1.5">
                {editorFiles.map((file, idx) => (
                  <div
                    key={file.path}
                    className="font-mono-code flex items-center rounded border text-xs"
                    style={{
                      backgroundColor: idx === activeEditorIdx ? "var(--accent-telemetry-dim)" : "var(--bg-chassis)",
                      borderColor: idx === activeEditorIdx ? "rgba(34, 211, 238, 0.5)" : "var(--border-grid)",
                    }}
                  >
                    <button
                      type="button"
                      onClick={() => setActiveEditorIdx(idx)}
                      className="cursor-pointer px-2.5 py-1 text-slate-200"
                    >
                      {file.path}
                    </button>
                    {editorFiles.length > 1 && (
                      <button
                        type="button"
                        onClick={() => handleRemoveEditorFile(idx)}
                        className="cursor-pointer pr-2 text-slate-500 hover:text-rose-400"
                        title="Remove file"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                ))}

                <div className="flex items-center gap-1">
                  <input
                    type="text"
                    value={newFileName}
                    onChange={(e) => setNewFileName(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        handleAddEditorFile();
                      }
                    }}
                    placeholder="Add file path (e.g. scripts/run.py)"
                    className="font-mono-code w-56 rounded border px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyan-400/60"
                    style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-grid)" }}
                  />
                  <button
                    type="button"
                    disabled={!newFileName.trim()}
                    onClick={handleAddEditorFile}
                    className="font-mono-code flex cursor-pointer items-center gap-1 rounded border px-2 py-1 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
                    style={{ borderColor: "var(--border-strong)" }}
                  >
                    <FilePlus2 className="h-3.5 w-3.5" />
                    Add File
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={bundleName}
                  onChange={(e) => setBundleName(e.target.value)}
                  placeholder="Optional skill name"
                  className="font-mono-code w-44 rounded border px-2.5 py-1 text-xs text-slate-200 outline-none focus:border-cyan-400/60"
                  style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-grid)" }}
                />
                <button
                  type="button"
                  disabled={isScanning || !hasNonEmptyEditorContent}
                  onClick={() =>
                    onScanInline({
                      name: bundleName.trim() || undefined,
                      files: editorFiles.filter((f) => f.content.length > 0 || editorFiles.length === 1),
                      ...buildFlags(),
                    })
                  }
                  className="font-display flex cursor-pointer items-center gap-2 rounded bg-cyan-400 px-4 py-1.5 text-xs font-bold tracking-wide text-slate-950 transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  {isScanning ? "ANALYZING..." : "CHECK SKILL SAFETY"}
                </button>
              </div>
            </div>

            <textarea
              rows={10}
              value={currentFile.content}
              placeholder={`Paste contents of ${currentFile.path} here...`}
              onChange={(e) => {
                const updated = editorFiles.map((f, idx) =>
                  idx === activeEditorIdx ? { ...f, content: e.target.value } : f,
                );
                setEditorFiles(updated);
              }}
              spellCheck={false}
              className="font-mono-code w-full rounded border p-3 text-xs leading-relaxed text-slate-100 outline-none focus:border-cyan-400/60"
              style={{ backgroundColor: "var(--bg-chassis)", borderColor: "var(--border-strong)" }}
            />
          </div>
        )}
      </div>
    </section>
  );
};
