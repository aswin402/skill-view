import { mkdtemp, readdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, extname, join, posix, relative } from "node:path";
import { unzipSync } from "fflate";
import { parse as parseYaml } from "yaml";
import type { ComponentInfo, InlineSkillInput, LedgerException, SkillFrontmatter } from "./types";
import { classifyFileType, globMatch, isExecutableComponent, sha256Hex } from "./utils";

export const INGEST_MAX_BYTES = 100 * 1024 * 1024; // 100 MiB
export const MAX_FILE_BYTES = 1 * 1024 * 1024; // 1 MiB per analyzed text file
export const INGEST_MAX_ZIP_MEMBERS = 10_000;

const IGNORED_DIRS = new Set([".git", "node_modules", ".venv", "venv", "dist", "build", ".next", ".turbo"]);

export interface IngestedBundle {
  skillName: string;
  skillDescription?: string;
  source: string;
  sourceKind: "directory" | "file" | "zip" | "git" | "url" | "inline";
  components: ComponentInfo[];
  rawFiles: Map<string, string>;
  shippedBytecodeFiles: string[];
  concealedExecutables: string[];
  frontmatter?: SkillFrontmatter;
  manifestPath?: string;
  ledgerExceptions: LedgerException[];
  scopeExclusions: string[];
}

function isPrivateOrLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h === "::1" ||
    h === "::" ||
    h === "0.0.0.0" ||
    h === "metadata.google.internal" ||
    h === "metadata" ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".localhost") ||
    h.startsWith("fe80:") ||
    h.startsWith("fc") ||
    h.startsWith("fd") ||
    h.startsWith("::ffff:127.") ||
    h.startsWith("::ffff:10.") ||
    h.startsWith("::ffff:169.254.") ||
    h.startsWith("::ffff:192.168.")
  ) {
    return true;
  }
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

function isLikelyBinaryBuffer(buf: Uint8Array): boolean {
  const checkLen = Math.min(buf.length, 4096);
  let suspicious = 0;
  for (let i = 0; i < checkLen; i++) {
    const byte = buf[i]!;
    if (byte === 0) return true;
    if (byte < 7 || (byte > 14 && byte < 32 && byte !== 27)) suspicious++;
  }
  return checkLen > 0 && suspicious / checkLen > 0.15;
}

export function parseSkillFrontmatter(content: string): SkillFrontmatter | undefined {
  const clean = content.startsWith("\uFEFF") ? content.slice(1) : content;
  const match = clean.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/);
  if (!match || match[1] === undefined) return undefined;

  const rawText = match[1];
  const endLine = match[0].split(/\r?\n/).length;
  try {
    const parsed = (parseYaml(rawText) ?? {}) as Record<string, unknown>;
    return {
      name: typeof parsed.name === "string" ? parsed.name : undefined,
      description: typeof parsed.description === "string" ? parsed.description : undefined,
      permissions:
        Array.isArray(parsed.permissions) || typeof parsed.permissions === "string"
          ? (parsed.permissions as string[] | string)
          : undefined,
      allowedTools:
        Array.isArray(parsed["allowed-tools"]) || typeof parsed["allowed-tools"] === "string"
          ? (parsed["allowed-tools"] as string[] | string)
          : Array.isArray(parsed.allowedTools) || typeof parsed.allowedTools === "string"
            ? (parsed.allowedTools as string[] | string)
            : undefined,
      triggers:
        Array.isArray(parsed.triggers) || typeof parsed.triggers === "string"
          ? (parsed.triggers as string[] | string)
          : parsed.metadata &&
              typeof parsed.metadata === "object" &&
              (Array.isArray((parsed.metadata as Record<string, unknown>).triggers) ||
                typeof (parsed.metadata as Record<string, unknown>).triggers === "string")
            ? ((parsed.metadata as Record<string, unknown>).triggers as string[] | string)
            : undefined,
      parameters:
        parsed.parameters && typeof parsed.parameters === "object"
          ? (parsed.parameters as Record<string, unknown>)
          : undefined,
      raw: parsed,
      rawText,
      endLine,
    };
  } catch {
    return {
      raw: {},
      rawText,
      endLine,
    };
  }
}

function checkMissingReferences(
  manifestPath: string,
  manifestContent: string,
  knownPaths: Set<string>,
): LedgerException[] {
  const exceptions: LedgerException[] = [];
  const lines = manifestContent.split(/\r?\n/);
  const mdLinkRegex = /\[[^\]]+\]\(([^)#\s]+)\)/g;

  lines.forEach((line, idx) => {
    let m: RegExpExecArray | null;
    mdLinkRegex.lastIndex = 0;
    while ((m = mdLinkRegex.exec(line)) !== null) {
      const ref = m[1]!;
      if (/^(https?:|mailto:|file:|conversation:|#)/.test(ref)) continue;
      const normalized = posix.normalize(posix.join(posix.dirname(manifestPath), ref)).replace(/^\.\//, "");
      if (!knownPaths.has(normalized) && !knownPaths.has(ref.replace(/^\.\//, ""))) {
        exceptions.push({
          kind: "reference_missing",
          file: manifestPath,
          line: idx + 1,
          message: `Referenced local path '${ref}' does not match any bundled artifact.`,
        });
      }
    }
  });

  return exceptions;
}

function finalizeEntries(
  entries: Array<{ relPath: string; bytes: Uint8Array; modeExecutable?: boolean }>,
  source: string,
  sourceKind: IngestedBundle["sourceKind"],
  fallbackName: string,
  excludePatterns: string[] = [],
  includeSourceContents = false,
): IngestedBundle {
  const components: ComponentInfo[] = [];
  const rawFiles = new Map<string, string>();
  const shippedBytecodeFiles: string[] = [];
  const concealedExecutables: string[] = [];
  const ledgerExceptions: LedgerException[] = [];
  const scopeExclusions: string[] = [];

  let totalBytes = 0;
  for (const entry of entries) {
    totalBytes += entry.bytes.byteLength;
    if (totalBytes > INGEST_MAX_BYTES) {
      throw new Error(`IngestLimitExceededError: Bundle exceeds maximum allowed size (${INGEST_MAX_BYTES} bytes).`);
    }
  }

  for (const entry of entries) {
    const relPath = entry.relPath.replace(/\\/g, "/").replace(/^\.\//, "");
    if (!relPath || relPath.endsWith("/")) continue;

    // Check caller exclusions (never allow excluding SKILL.md)
    const base = basename(relPath).toLowerCase();
    if (base !== "skill.md" && excludePatterns.some((pat) => globMatch(pat, relPath))) {
      scopeExclusions.push(relPath);
      continue;
    }

    const ext = extname(relPath).toLowerCase();
    if (ext === ".pyc" || ext === ".pyo" || relPath.includes("__pycache__/")) {
      shippedBytecodeFiles.push(relPath);
    }
    if ([".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".scr", ".com"].includes(ext) || basename(relPath).startsWith(".")) {
      if ([".exe", ".dll", ".so", ".dylib", ".elf", ".scr"].includes(ext)) {
        concealedExecutables.push(relPath);
      }
    }

    const sha256 = sha256Hex(entry.bytes);
    if (entry.bytes.byteLength > MAX_FILE_BYTES) {
      ledgerExceptions.push({
        kind: "size_limit_exceeded",
        file: relPath,
        message: `File size (${entry.bytes.byteLength} bytes) exceeds 1 MiB per-file analysis ceiling.`,
      });
      components.push({
        path: relPath,
        type: classifyFileType(relPath, false),
        lines: 0,
        executable: Boolean(entry.modeExecutable),
        size_bytes: entry.bytes.byteLength,
        sha256,
      });
      continue;
    }

    const binary = isLikelyBinaryBuffer(entry.bytes);
    if (binary) {
      ledgerExceptions.push({
        kind: "binary_skipped",
        file: relPath,
        message: "Binary artifact excluded from text/AST parsing; SHA-256 recorded.",
      });
      components.push({
        path: relPath,
        type: "binary",
        lines: 0,
        executable: Boolean(entry.modeExecutable),
        size_bytes: entry.bytes.byteLength,
        sha256,
      });
      continue;
    }

    const text = new TextDecoder("utf-8", { fatal: false }).decode(entry.bytes);
    const linesCount = text.length === 0 ? 0 : text.split(/\r?\n/).length;
    const executable = isExecutableComponent(relPath, text, entry.modeExecutable);
    rawFiles.set(relPath, text);
    components.push({
      path: relPath,
      type: classifyFileType(relPath, false),
      lines: linesCount,
      executable,
      size_bytes: entry.bytes.byteLength,
      sha256,
      ...(includeSourceContents ? { content: text } : {}),
    });
  }

  // Locate primary SKILL.md / skill.md manifest
  const manifestCandidates = Array.from(rawFiles.keys()).filter(
    (k) => basename(k).toLowerCase() === "skill.md",
  );
  manifestCandidates.sort((a, b) => a.split("/").length - b.split("/").length);
  const manifestPath = manifestCandidates[0];
  const frontmatter = manifestPath ? parseSkillFrontmatter(rawFiles.get(manifestPath)!) : undefined;

  if (manifestPath) {
    const knownPaths = new Set(components.map((c) => c.path));
    ledgerExceptions.push(...checkMissingReferences(manifestPath, rawFiles.get(manifestPath)!, knownPaths));
  }

  const skillName = frontmatter?.name?.trim() || fallbackName || "unnamed-skill";
  const skillDescription = frontmatter?.description?.trim();

  return {
    skillName,
    ...(skillDescription ? { skillDescription } : {}),
    source,
    sourceKind,
    components,
    rawFiles,
    shippedBytecodeFiles,
    concealedExecutables,
    ...(frontmatter ? { frontmatter } : {}),
    ...(manifestPath ? { manifestPath } : {}),
    ledgerExceptions,
    scopeExclusions,
  };
}

export function ingestZipBytes(
  zipBytes: Uint8Array,
  sourceLabel: string,
  excludePatterns: string[] = [],
  includeSourceContents = false,
  subpath?: string,
  fallbackNameOverride?: string,
  sourceKind: IngestedBundle["sourceKind"] = "zip",
): IngestedBundle {
  if (zipBytes.byteLength > INGEST_MAX_BYTES) {
    throw new Error(`IngestLimitExceededError: Zip archive exceeds ${INGEST_MAX_BYTES} bytes.`);
  }
  const unzipped = unzipSync(zipBytes);
  const names = Object.keys(unzipped);
  if (names.length > INGEST_MAX_ZIP_MEMBERS) {
    throw new Error(`IngestLimitExceededError: Zip archive has ${names.length} members (limit ${INGEST_MAX_ZIP_MEMBERS}).`);
  }

  // Strip common single top-level folder prefix if all files share one (e.g. GitHub repo-main/)
  const fileNames = names.filter((n) => !n.endsWith("/"));
  let commonRoot = "";
  if (fileNames.length > 0 && fileNames.every((n) => n.includes("/"))) {
    const firstSeg = fileNames[0]!.split("/")[0]!;
    if (fileNames.every((n) => n.startsWith(`${firstSeg}/`))) {
      commonRoot = firstSeg;
    }
  }

  const normalizedSubpath = subpath ? subpath.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "") : undefined;
  const entries: Array<{ relPath: string; bytes: Uint8Array }> = [];

  for (const name of fileNames) {
    let relPath = commonRoot ? name.slice(commonRoot.length + 1) : name;
    relPath = relPath.replace(/\\/g, "/").replace(/^\/+/, "");
    if (!relPath) continue;

    // Skip ignored build/dependency/VCS folders inside archives
    const segments = relPath.split("/");
    if (segments.some((seg) => IGNORED_DIRS.has(seg))) continue;

    if (normalizedSubpath) {
      if (relPath === normalizedSubpath) {
        relPath = basename(relPath);
      } else if (relPath.startsWith(`${normalizedSubpath}/`)) {
        relPath = relPath.slice(normalizedSubpath.length + 1);
      } else {
        continue;
      }
    }

    if (!relPath) continue;
    entries.push({ relPath, bytes: unzipped[name]! });
  }

  if (normalizedSubpath && entries.length === 0) {
    throw new Error(`Subpath '${normalizedSubpath}' was not found inside archive '${sourceLabel}'.`);
  }

  const fallbackName =
    fallbackNameOverride ||
    (normalizedSubpath ? basename(normalizedSubpath) : undefined) ||
    commonRoot ||
    basename(sourceLabel, ".zip") ||
    "uploaded-skill";
  return finalizeEntries(entries, sourceLabel, sourceKind, fallbackName, excludePatterns, includeSourceContents);
}

export function ingestInlineSkill(
  inline: InlineSkillInput,
  excludePatterns: string[] = [],
  includeSourceContents = true,
): IngestedBundle {
  const encoder = new TextEncoder();
  const entries = inline.files.map((f) => ({
    relPath: f.path.replace(/^\/+/, ""),
    bytes: encoder.encode(f.content),
  }));
  return finalizeEntries(
    entries,
    `inline://${inline.name || "pasted-skill"}`,
    "inline",
    inline.name || "pasted-skill",
    excludePatterns,
    includeSourceContents,
  );
}

async function walkDirectory(rootDir: string, currentDir: string, acc: Array<{ relPath: string; bytes: Uint8Array; modeExecutable: boolean }>) {
  const dirEntries = await readdir(currentDir, { withFileTypes: true });
  for (const dirent of dirEntries) {
    if (IGNORED_DIRS.has(dirent.name)) continue;
    const fullPath = join(currentDir, dirent.name);
    if (dirent.isSymbolicLink()) continue; // Do not follow symlinks outside bundle
    if (dirent.isDirectory()) {
      await walkDirectory(rootDir, fullPath, acc);
    } else if (dirent.isFile()) {
      const st = await stat(fullPath);
      const buf = await readFile(fullPath);
      acc.push({
        relPath: relative(rootDir, fullPath),
        bytes: new Uint8Array(buf),
        modeExecutable: (st.mode & 0o111) !== 0,
      });
    }
  }
}

interface NormalizedRemoteTarget {
  kind: "github_archive" | "git" | "raw";
  cloneUrl: string;
  owner?: string;
  repo?: string;
  branch?: string;
  subpath?: string;
  treeSegments?: string[];
  rawUrl?: string;
}

function normalizeRemoteUrl(rawUrl: string): NormalizedRemoteTarget {
  const url = new URL(rawUrl);
  if (isPrivateOrLoopbackHost(url.hostname)) {
    throw new Error(`SSRFBlockedError: Refusing to connect to private or loopback host '${url.hostname}'.`);
  }

  // Handle github.com/<owner>/<repo>[/tree/<branch>[/<subpath>]|/blob/<branch>/<path>]
  if (url.hostname === "github.com" || url.hostname === "www.github.com") {
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length >= 2) {
      const [owner, repo, mode, branch, ...rest] = parts;
      const cleanRepo = repo!.replace(/\.git$/, "");
      if (mode === "blob" && branch && rest.length > 0) {
        return {
          kind: "raw",
          cloneUrl: rawUrl,
          rawUrl: `https://raw.githubusercontent.com/${owner}/${cleanRepo}/${branch}/${rest.join("/")}`,
        };
      }
      if (mode === "tree" && branch) {
        return {
          kind: "github_archive",
          cloneUrl: `https://github.com/${owner}/${cleanRepo}.git`,
          owner: owner!,
          repo: cleanRepo,
          branch,
          subpath: rest.length > 0 ? rest.join("/") : undefined,
          treeSegments: [branch, ...rest],
        };
      }
      return {
        kind: "github_archive",
        cloneUrl: `https://github.com/${owner}/${cleanRepo}.git`,
        owner: owner!,
        repo: cleanRepo,
      };
    }
  }

  if (url.pathname.endsWith(".git")) {
    return { kind: "git", cloneUrl: rawUrl };
  }

  return { kind: "raw", cloneUrl: rawUrl, rawUrl };
}

async function fetchSafeHttpsBytes(targetUrl: string, headers?: Record<string, string>): Promise<Response> {
  const parsed = new URL(targetUrl);
  if (parsed.protocol !== "https:" || isPrivateOrLoopbackHost(parsed.hostname)) {
    throw new Error(`SSRFBlockedError: Refusing to fetch '${targetUrl}'.`);
  }
  const res = await fetch(targetUrl, {
    redirect: "follow",
    headers: {
      "User-Agent": "SkillSpectator-Scanner/1.0",
      ...headers,
    },
  });
  if (res.url) {
    const finalParsed = new URL(res.url);
    if (finalParsed.protocol !== "https:" || isPrivateOrLoopbackHost(finalParsed.hostname)) {
      throw new Error(`SSRFBlockedError: Redirect target '${finalParsed.hostname}' is blocked.`);
    }
  }
  const contentLength = Number(res.headers.get("content-length") || "0");
  if (contentLength > INGEST_MAX_BYTES) {
    throw new Error(`IngestLimitExceededError: Remote archive (${contentLength} bytes) exceeds ${INGEST_MAX_BYTES} bytes.`);
  }
  return res;
}

async function fetchGitHubArchiveBundle(
  info: NormalizedRemoteTarget,
  originalUrl: string,
  excludePatterns: string[],
  includeSourceContents: boolean,
): Promise<IngestedBundle> {
  const owner = info.owner!;
  const repo = info.repo!;
  const ghHeaders: Record<string, string> = { Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) {
    ghHeaders.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  // Build candidate archive URLs (prefer codeload.github.com — no 60/hr REST API rate limit)
  const candidates: Array<{ url: string; subpath?: string; headers?: Record<string, string> }> = [];
  if (info.treeSegments && info.treeSegments.length > 0) {
    // Support both standard single-segment branches (main/subpath) and slash branches (feat/x/subpath)
    const maxBranchDepth = Math.min(info.treeSegments.length, 3);
    for (let depth = 1; depth <= maxBranchDepth; depth++) {
      const refCandidate = info.treeSegments.slice(0, depth).join("/");
      const subCandidate = info.treeSegments.slice(depth).join("/") || undefined;
      candidates.push({
        url: `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/${refCandidate}`,
        subpath: subCandidate,
      });
      candidates.push({
        url: `https://codeload.github.com/${owner}/${repo}/zip/refs/tags/${refCandidate}`,
        subpath: subCandidate,
      });
    }
    // Fallback for commit SHAs or special refs via GitHub zipball API
    candidates.push({
      url: `https://api.github.com/repos/${owner}/${repo}/zipball/${encodeURIComponent(info.branch!)}`,
      subpath: info.subpath,
      headers: ghHeaders,
    });
  } else {
    candidates.push({ url: `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/main` });
    candidates.push({ url: `https://codeload.github.com/${owner}/${repo}/zip/refs/heads/master` });
    candidates.push({
      url: `https://api.github.com/repos/${owner}/${repo}/zipball`,
      headers: ghHeaders,
    });
  }

  let lastStatus = 0;
  for (const candidate of candidates) {
    const res = await fetchSafeHttpsBytes(candidate.url, candidate.headers);
    if (res.ok) {
      const bytes = new Uint8Array(await res.arrayBuffer());
      const fallbackName = candidate.subpath ? basename(candidate.subpath) : repo;
      return ingestZipBytes(
        bytes,
        originalUrl,
        excludePatterns,
        includeSourceContents,
        candidate.subpath,
        fallbackName,
        "git",
      );
    }
    lastStatus = res.status;
    // Stop early on auth/rate-limit errors from GitHub API, otherwise try next candidate
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        `GitHub rejected archive fetch for '${owner}/${repo}' (HTTP ${res.status}). Repository may be private or rate-limited.`,
      );
    }
  }

  throw new Error(
    `Failed to fetch GitHub repository '${owner}/${repo}' (HTTP ${lastStatus || 404}). Verify the repository is public and the branch/path exists.`,
  );
}

export async function ingestTarget(
  target: string,
  excludePatterns: string[] = [],
  includeSourceContents = false,
): Promise<IngestedBundle> {
  const trimmed = target.trim();

  // Remote URL or Git repository
  if (/^https?:\/\//i.test(trimmed)) {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") {
      throw new Error("Only HTTPS remote URLs are permitted.");
    }
    const remoteInfo = normalizeRemoteUrl(trimmed);

    // Serverless-safe GitHub zipball fetch (zero git binary, zero /tmp disk writes)
    if (remoteInfo.kind === "github_archive") {
      return fetchGitHubArchiveBundle(remoteInfo, trimmed, excludePatterns, includeSourceContents);
    }

    // Non-GitHub .git repositories: use local git clone when running outside serverless with Bun
    if (remoteInfo.kind === "git") {
      if (process.env.VERCEL || typeof globalThis.Bun === "undefined") {
        throw new Error(
          "Direct .git cloning of non-GitHub hosts requires a standalone server with the git CLI. Submit a GitHub URL, raw file URL, or .zip archive link instead.",
        );
      }
      const tempRoot = await mkdtemp(join(tmpdir(), "skillspectator-git-"));
      try {
        const proc = globalThis.Bun.spawn(
          ["git", "clone", "--depth", "1", "--single-branch", "--config", "core.hooksPath=/dev/null", remoteInfo.cloneUrl, tempRoot],
          {
            stdout: "pipe",
            stderr: "pipe",
            env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
          },
        );
        const exitCode = await proc.exited;
        if (exitCode !== 0) {
          const errText = await new Response(proc.stderr).text();
          throw new Error(`Failed to clone Git repository '${remoteInfo.cloneUrl}': ${errText.trim()}`);
        }
        const scanDir = remoteInfo.subpath ? join(tempRoot, remoteInfo.subpath) : tempRoot;
        const files: Array<{ relPath: string; bytes: Uint8Array; modeExecutable: boolean }> = [];
        await walkDirectory(scanDir, scanDir, files);
        const repoName = basename(remoteInfo.cloneUrl, ".git");
        return finalizeEntries(files, trimmed, "git", remoteInfo.subpath ? basename(remoteInfo.subpath) : repoName, excludePatterns, includeSourceContents);
      } finally {
        await rm(tempRoot, { recursive: true, force: true });
      }
    }

    // Fetch raw URL or remote .zip
    const fetchUrl = remoteInfo.rawUrl ?? trimmed;
    const res = await fetchSafeHttpsBytes(fetchUrl);
    if (!res.ok) {
      throw new Error(`Failed to fetch URL '${fetchUrl}': HTTP ${res.status}`);
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    const contentType = (res.headers.get("content-type") || "").toLowerCase();
    if (fetchUrl.toLowerCase().endsWith(".zip") || contentType.includes("application/zip")) {
      return ingestZipBytes(buf, trimmed, excludePatterns, includeSourceContents);
    }
    const fileName = basename(new URL(fetchUrl).pathname) || "SKILL.md";
    return finalizeEntries(
      [{ relPath: fileName, bytes: buf }],
      trimmed,
      "url",
      basename(fileName, extname(fileName)),
      excludePatterns,
      includeSourceContents,
    );
  }

  // Strip file:// scheme if provided
  const localPath = trimmed.startsWith("file://") ? new URL(trimmed).pathname : trimmed;
  const st = await stat(localPath);

  if (st.isDirectory()) {
    const files: Array<{ relPath: string; bytes: Uint8Array; modeExecutable: boolean }> = [];
    await walkDirectory(localPath, localPath, files);
    return finalizeEntries(files, localPath, "directory", basename(localPath), excludePatterns, includeSourceContents);
  }

  if (st.isFile()) {
    const buf = new Uint8Array(await readFile(localPath));
    if (localPath.toLowerCase().endsWith(".zip")) {
      return ingestZipBytes(buf, localPath, excludePatterns, includeSourceContents);
    }
    return finalizeEntries(
      [{ relPath: basename(localPath), bytes: buf, modeExecutable: (st.mode & 0o111) !== 0 }],
      localPath,
      "file",
      basename(localPath, extname(localPath)),
      excludePatterns,
      includeSourceContents,
    );
  }

  throw new Error(`Unsupported target path: '${target}'`);
}
