import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger as httpLogger } from "hono/logger";
import { z } from "zod";
import {
  type BaselineDocument,
  buildBaselineFromFindings,
  getEngineCapabilities,
  INGEST_MAX_BYTES,
  parseBaselineYamlString,
  renderReport,
  type ScanReport,
  SKILLSPECTATOR_VERSION,
  scanInline,
  scanTarget,
  scanZipBuffer,
  serializeBaselineYaml,
} from "skillspectator";
import { logger } from "./utils/logger";

const SERVERLESS_MAX_UPLOAD_BYTES = 4_500_000; // Vercel serverless request body cap (~4.5 MB)

/**
 * Resolves the true API path even when Vercel rewrites `/api/(.*)` -> `/api?__path=$1`,
 * without cloning or consuming the underlying Request body stream.
 */
function resolveRequestPath(req: Request): string {
  const url = new URL(req.url);
  const rewritten = url.searchParams.get("__path");
  if (rewritten !== null && (url.pathname === "/api" || url.pathname === "/api/index")) {
    return `/api/${rewritten.replace(/^\/+/, "")}`;
  }
  return url.pathname;
}

export function createApiApp(): Hono {
  const app = new Hono({ getPath: resolveRequestPath });

  app.use("*", httpLogger());
  app.use("*", cors());

  interface HistoryEntry {
    id: string;
    report: ScanReport;
  }

  const scanHistory: HistoryEntry[] = [];

  function recordHistory(report: ScanReport): string {
    const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    scanHistory.unshift({ id, report });
    if (scanHistory.length > 50) scanHistory.pop();
    return id;
  }

  function parseOptionalBaseline(yamlStr?: string): BaselineDocument | undefined {
    if (!yamlStr || !yamlStr.trim()) return undefined;
    return parseBaselineYamlString(yamlStr);
  }

  app.get("/api/health", (c) => {
    const isBun = typeof globalThis.Bun !== "undefined";
    return c.json({
      success: true,
      data: {
        service: "skillspectator-web-api",
        version: SKILLSPECTATOR_VERSION,
        runtime: isBun ? "bun" : "node",
        runtime_version: isBun ? globalThis.Bun.version : process.version,
        serverless: Boolean(process.env.VERCEL),
      },
    });
  });

  app.get("/api/meta", (c) => {
    const isVercel = Boolean(process.env.VERCEL);
    const caps = getEngineCapabilities();
    return c.json({
      success: true,
      data: {
        ...caps,
        max_upload_bytes: isVercel ? SERVERLESS_MAX_UPLOAD_BYTES : INGEST_MAX_BYTES,
        deployment_mode: isVercel ? "serverless" : "standalone",
      },
    });
  });

  const inlineScanSchema = z.object({
    name: z.string().optional(),
    files: z
      .array(
        z.object({
          path: z.string().min(1),
          content: z.string(),
        }),
      )
      .min(1),
    useLlm: z.boolean().optional().default(false),
    llmProvider: z.string().optional(),
    llmModel: z.string().optional(),
    llmApiKey: z.string().optional(),
    llmBaseUrl: z.string().optional(),
    followTransitiveLinks: z.boolean().optional().default(false),
    baselineYaml: z.string().optional(),
  });

  app.post("/api/scan/inline", zValidator("json", inlineScanSchema), async (c) => {
    const body = c.req.valid("json");
    const baselineData = parseOptionalBaseline(body.baselineYaml);
    const report = await scanInline(
      { name: body.name?.trim() || undefined, files: body.files },
      {
        useLlm: body.useLlm,
        llmProvider: body.llmProvider,
        llmModel: body.llmModel,
        llmApiKey: body.llmApiKey,
        llmBaseUrl: body.llmBaseUrl,
        followTransitiveLinks: body.followTransitiveLinks,
        baselineData,
        includeSourceContents: true,
      },
    );
    const scanId = recordHistory(report);
    return c.json({ success: true, data: { scanId, report } });
  });

  const urlScanSchema = z.object({
    url: z.string().url(),
    useLlm: z.boolean().optional().default(false),
    llmProvider: z.string().optional(),
    llmModel: z.string().optional(),
    llmApiKey: z.string().optional(),
    llmBaseUrl: z.string().optional(),
    followTransitiveLinks: z.boolean().optional().default(false),
    baselineYaml: z.string().optional(),
  });

  app.post("/api/scan/url", zValidator("json", urlScanSchema), async (c) => {
    const body = c.req.valid("json");
    const parsedUrl = new URL(body.url.trim());
    if (parsedUrl.protocol !== "https:") {
      return c.json(
        { success: false, error: "Only HTTPS URLs (GitHub repos, raw SKILL.md, or .zip links) are permitted." },
        400,
      );
    }

    const baselineData = parseOptionalBaseline(body.baselineYaml);
    const report = await scanTarget(body.url.trim(), {
      useLlm: body.useLlm,
      llmProvider: body.llmProvider,
      llmModel: body.llmModel,
      llmApiKey: body.llmApiKey,
      llmBaseUrl: body.llmBaseUrl,
      followTransitiveLinks: body.followTransitiveLinks,
      baselineData,
      includeSourceContents: true,
    });
    const scanId = recordHistory(report);
    return c.json({ success: true, data: { scanId, report } });
  });

  app.post("/api/scan/upload", async (c) => {
    const form = await c.req.formData();
    const useLlm = form.get("useLlm") === "true";
    const followTransitiveLinks = form.get("followTransitiveLinks") === "true";
    const llmProvider = typeof form.get("llmProvider") === "string" ? (form.get("llmProvider") as string) : undefined;
    const llmModel = typeof form.get("llmModel") === "string" ? (form.get("llmModel") as string) : undefined;
    const llmApiKey = typeof form.get("llmApiKey") === "string" ? (form.get("llmApiKey") as string) : undefined;
    const llmBaseUrl = typeof form.get("llmBaseUrl") === "string" ? (form.get("llmBaseUrl") as string) : undefined;
    const baselineYaml = typeof form.get("baselineYaml") === "string" ? (form.get("baselineYaml") as string) : undefined;
    const baselineData = parseOptionalBaseline(baselineYaml);

    const uploadedFiles = form.getAll("files");
    const relativePaths = form.getAll("paths").map(String);

    if (uploadedFiles.length === 0) {
      return c.json({ success: false, error: "No files uploaded." }, 400);
    }

    // Single .zip archive upload
    const first = uploadedFiles[0];
    if (uploadedFiles.length === 1 && first instanceof File && first.name.toLowerCase().endsWith(".zip")) {
      const bytes = new Uint8Array(await first.arrayBuffer());
      const report = await scanZipBuffer(bytes, first.name, {
        useLlm,
        llmProvider,
        llmModel,
        llmApiKey,
        llmBaseUrl,
        followTransitiveLinks,
        baselineData,
        includeSourceContents: true,
      });
      const scanId = recordHistory(report);
      return c.json({ success: true, data: { scanId, report } });
    }

    // Multi-file / folder upload
    const virtualFiles: Array<{ path: string; content: string }> = [];
    let inferredName: string | undefined;

    for (let i = 0; i < uploadedFiles.length; i++) {
      const item = uploadedFiles[i];
      if (!(item instanceof File)) continue;
      const rawRel = relativePaths[i] || item.name;
      const segments = rawRel.replace(/\\/g, "/").split("/").filter(Boolean);
      if (segments.length > 1 && !inferredName) {
        inferredName = segments[0]!;
      }
      const cleanPath = segments.length > 1 ? segments.slice(1).join("/") : segments.join("/");
      const text = await item.text();
      virtualFiles.push({ path: cleanPath || item.name, content: text });
    }

    const report = await scanInline(
      { name: inferredName, files: virtualFiles },
      {
        useLlm,
        llmProvider,
        llmModel,
        llmApiKey,
        llmBaseUrl,
        followTransitiveLinks,
        baselineData,
        includeSourceContents: true,
      },
    );
    const scanId = recordHistory(report);
    return c.json({ success: true, data: { scanId, report } });
  });

  const exportSchema = z.object({
    scanId: z.string().optional(),
    report: z.record(z.string(), z.unknown()).optional(),
    format: z.enum(["markdown", "sarif", "json", "baseline"]),
    reason: z.string().optional(),
  });

  app.post("/api/export", zValidator("json", exportSchema), (c) => {
    const { scanId, report: inlineReport, format, reason } = c.req.valid("json");
    const report =
      (inlineReport as unknown as ScanReport | undefined) ??
      (scanId ? scanHistory.find((h) => h.id === scanId)?.report : undefined);

    if (!report || !report.skill || !Array.isArray(report.issues)) {
      return c.json(
        { success: false, error: "Scan report not provided or not found in session history." },
        404,
      );
    }

    if (format === "baseline") {
      const doc = buildBaselineFromFindings(report.issues, reason || "Reviewed via SkillSpectator Web");
      return c.json({
        success: true,
        data: {
          filename: ".skillspectator-baseline.yaml",
          mimeType: "text/yaml",
          content: serializeBaselineYaml(doc),
        },
      });
    }

    const ext = format === "markdown" ? "md" : format === "sarif" ? "sarif.json" : "json";
    return c.json({
      success: true,
      data: {
        filename: `${report.skill.name}-report.${ext}`,
        mimeType: format === "markdown" ? "text/markdown" : "application/json",
        content: renderReport(report, format),
      },
    });
  });

  app.get("/api/history", (c) => {
    return c.json({
      success: true,
      data: scanHistory.map((h) => ({
        id: h.id,
        skillName: h.report.skill.name,
        source: h.report.skill.source,
        sourceKind: h.report.skill.source_kind,
        scannedAt: h.report.skill.scanned_at,
        durationMs: h.report.skill.duration_ms,
        score: h.report.risk_assessment.score,
        severity: h.report.risk_assessment.severity,
        recommendation: h.report.risk_assessment.recommendation,
        issuesCount: h.report.issues.length,
      })),
    });
  });

  app.get("/api/history/:id", (c) => {
    const id = c.req.param("id");
    const entry = scanHistory.find((h) => h.id === id);
    if (!entry) {
      return c.json({ success: false, error: "Scan not found" }, 404);
    }
    return c.json({ success: true, data: { scanId: entry.id, report: entry.report } });
  });

  app.onError((err, c) => {
    logger.error({ err }, "Unhandled API error");
    return c.json(
      {
        success: false,
        error: err.message || "Internal scanner error",
      },
      500,
    );
  });

  return app;
}

export const app = createApiApp();
export default app;
