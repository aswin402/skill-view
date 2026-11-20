import type {
  EngineCapabilities,
  HistorySummary,
  ScanReport,
  VirtualFileInput,
} from "@/types/scanner";

interface ApiEnvelope<T> {
  success: boolean;
  data: T;
  error?: string;
}

const API_BASE = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");

async function parseEnvelope<T>(res: Response): Promise<T> {
  const contentType = (res.headers.get("content-type") || "").toLowerCase();
  const rawText = await res.text();

  if (contentType.includes("application/json")) {
    const json = JSON.parse(rawText) as ApiEnvelope<T>;
    if (!res.ok || !json.success) {
      throw new Error(json.error || `Request failed with HTTP ${res.status}`);
    }
    return json.data;
  }

  if (res.status === 413) {
    throw new Error(
      "Upload exceeds the serverless 4.5 MB request body limit. Use a GitHub URL or upload only the skill folder / .zip archive.",
    );
  }
  if (res.status === 504) {
    throw new Error(
      "Scan timed out on the server. Try disabling optional Stage-2 LLM or transitive link scanning for very large repositories.",
    );
  }
  throw new Error(rawText.trim().slice(0, 240) || `Request failed with HTTP ${res.status}`);
}

export async function fetchEngineMeta(): Promise<EngineCapabilities> {
  const res = await fetch(`${API_BASE}/api/meta`);
  return parseEnvelope(res);
}

export async function scanInlinePayload(params: {
  name?: string;
  files: VirtualFileInput[];
  useLlm?: boolean;
  llmProvider?: string;
  llmModel?: string;
  llmApiKey?: string;
  llmBaseUrl?: string;
  followTransitiveLinks?: boolean;
  baselineYaml?: string;
}): Promise<{ scanId: string; report: ScanReport }> {
  const res = await fetch(`${API_BASE}/api/scan/inline`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  return parseEnvelope(res);
}

export async function scanRemoteSkillUrl(params: {
  url: string;
  useLlm?: boolean;
  llmProvider?: string;
  llmModel?: string;
  llmApiKey?: string;
  llmBaseUrl?: string;
  followTransitiveLinks?: boolean;
  baselineYaml?: string;
}): Promise<{ scanId: string; report: ScanReport }> {
  const res = await fetch(`${API_BASE}/api/scan/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  return parseEnvelope(res);
}

export async function scanUploadedFiles(params: {
  files: File[];
  useLlm?: boolean;
  llmProvider?: string;
  llmModel?: string;
  llmApiKey?: string;
  llmBaseUrl?: string;
  followTransitiveLinks?: boolean;
  baselineYaml?: string;
}): Promise<{ scanId: string; report: ScanReport }> {
  const form = new FormData();
  for (const file of params.files) {
    form.append("files", file);
    form.append("paths", file.webkitRelativePath || file.name);
  }
  form.append("useLlm", String(Boolean(params.useLlm)));
  form.append("followTransitiveLinks", String(Boolean(params.followTransitiveLinks)));
  if (params.llmProvider) form.append("llmProvider", params.llmProvider);
  if (params.llmModel) form.append("llmModel", params.llmModel);
  if (params.llmApiKey) form.append("llmApiKey", params.llmApiKey);
  if (params.llmBaseUrl) form.append("llmBaseUrl", params.llmBaseUrl);
  if (params.baselineYaml) form.append("baselineYaml", params.baselineYaml);

  const res = await fetch(`${API_BASE}/api/scan/upload`, {
    method: "POST",
    body: form,
  });
  return parseEnvelope(res);
}

export async function fetchScanHistory(): Promise<HistorySummary[]> {
  const res = await fetch(`${API_BASE}/api/history`);
  return parseEnvelope(res);
}

export async function fetchHistoryEntry(id: string): Promise<{ scanId: string; report: ScanReport }> {
  const res = await fetch(`${API_BASE}/api/history/${encodeURIComponent(id)}`);
  return parseEnvelope(res);
}

export async function exportScanArtifact(params: {
  scanId?: string;
  report?: ScanReport;
  format: "markdown" | "sarif" | "json" | "baseline";
  reason?: string;
}): Promise<{ filename: string; mimeType: string; content: string }> {
  const res = await fetch(`${API_BASE}/api/export`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
  return parseEnvelope(res);
}
