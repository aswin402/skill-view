import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createApiApp } from "./app";
import { logger } from "./utils/logger";

const app = createApiApp();
const PORT = Number(process.env.PORT || 3847);

// Serve built apps/web/dist when running locally in single-port production mode
const currentDir = dirname(fileURLToPath(import.meta.url));
const webDistDir = resolve(currentDir, "../../web/dist");
const MIME_BY_EXT: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

app.get("*", async (c) => {
  if (!existsSync(webDistDir)) {
    return c.json({
      success: true,
      message: "SkillSpectator Web API running. Build apps/web or run scripts/dev.ts for live UI.",
    });
  }
  const reqPath = c.req.path === "/" ? "/index.html" : c.req.path;
  const candidate = resolve(webDistDir, `.${reqPath}`);
  if (candidate.startsWith(webDistDir) && existsSync(candidate)) {
    const st = await stat(candidate);
    if (st.isFile()) {
      const ext = extname(candidate).toLowerCase();
      const body = await readFile(candidate);
      return new Response(body, {
        headers: { "Content-Type": MIME_BY_EXT[ext] || "application/octet-stream" },
      });
    }
  }
  const indexHtml = await readFile(join(webDistDir, "index.html"));
  return new Response(indexHtml, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
});

logger.info(`SkillSpectator Web API listening on port ${PORT}`);

export { app };

export default {
  port: PORT,
  fetch: app.fetch,
};
