# SkillSpectator

High-speed **TypeScript + Bun** AI Skill Security Website & Forensic Analysis Engine. Users submit a GitHub URL, upload a `.zip` or skill folder, or paste raw `SKILL.md` + scripts, and SkillSpectator tells them in milliseconds whether the skill is **Safe to Use**, **Caution**, or **Unsafe — Do Not Install**.

## Architecture

- **`packages/core` (`skillspectator`)** — Static, AST, Taint, YARA, and live OSV.dev analysis engine:
  - **Stage 0 De-obfuscation Pre-pass:** Decodes Base64, hex escapes, HTML comments, Unicode Tag (`U+E0000`..`U+E007F`) smuggling, Bidirectional overrides, off-screen whitespace padding, letter-spaced evasion (`AE2`), multi-line split overrides (`AE3`), NFKC compatibility evasion (`AE4`), and Cyrillic/Greek homoglyphs (`TP2`).
  - **Stage 1 Deterministic Pipeline (~3–20 ms):**
    - Prompt injection (`P1–P5, P9`), System prompt leakage (`P6–P8`), Anti-refusal (`AR1–AR3`)
    - Data exfiltration (`E1–E5`), Privilege escalation (`PE1–PE3`), Agent snooping (`AS1–AS3`)
    - Bundled lifecycle hooks & auto-executing settings (`BH1–BH4` across `hooks.json`, `.claude/settings.json`, `apiKeyHelper`, `statusLine`)
    - Behavioral AST (`AST1–AST10`) & Cross-variable Taint Tracking (`TT1–TT6`) across Python, TypeScript/JavaScript, and Shell
    - Supply chain (`SC1–SC10`: Damerau-Levenshtein typosquatting, compromised/abandoned packages, live OSV.dev queries across `package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`, mutable branch rug-pulls `RP1–RP2`)
    - Full YARA signature corpus (`YR1–YR4`: reverse shells, commodity webhook exfil, PHP/Python/JSP/ASPX webshells, Stratum/cryptominers, offensive tooling)
    - Multi-language deserialization (`DS1–DS4`), SSRF (`SSRF1–SSRF3`), Memory poisoning (`MP1–MP3`), Tool misuse (`TM1–TM4`), Rogue agent (`RA1–RA2`), Excessive agency (`EA1–EA5`), Output handling (`OH1–OH3`), Trigger abuse (`TR1–TR3`)
    - Optional Transitive External Link inspection (`followTransitiveLinks`)
  - **Stage 2 Semantic AI Review (Optional BYOK):** Runs the 4-angle rubric (`SSD-1..4`, `SDI-1..4`, `SQP-1..3`, and Meta confirmation) using OpenAI, Gemini, Anthropic, NVIDIA NIM, OpenAI-compatible endpoints, or Ollama.
- **`apps/api` (`@skillspectator/api`)** — Stateless, serverless-compatible Hono API enforcing HTTPS-only remote URL scanning (GitHub zipball fetch without requiring the `git` CLI), memory-bounded `.zip`/file uploads, inline scanning, and `JSON / Markdown / SARIF 2.1.0 / Baseline YAML` export.
- **`api/index.ts` + `vercel.json`** — Zero-config Vercel Serverless Function entrypoint (Bun runtime) paired with the Vite SPA build (`apps/web/dist`).
- **`apps/web` (`@skillspectator/web`)** — React 19 + Vite 8 + Tailwind 4 Web Platform with browser-persisted scan history, Executive Verdict, Detected Capabilities, Threat Vector Shield, and interactive Source Code X-Ray.

## Run Locally

```bash
# Install dependencies
bun install

# Live HMR Development Mode (API on :3847 + Vite UI on :5173)
bun scripts/dev.ts

# Single-port Production Website + API (http://localhost:3847)
bun run build
bun apps/api/src/server.ts

# Run Test Suite
bun test packages/core/tests apps/api/tests
```

## Deploy to Vercel

This repository is pre-configured for one-click Vercel import (`vercel.json` + `api/index.ts`):

1. Push this repository to GitHub.
2. Go to **Vercel → Add New Project → Import Git Repository**.
3. Leave the default settings as-is (`vercel.json` automatically configures Bun runtime, `bun install`, `bun run build`, `apps/web/dist`, and `/api/*` serverless routing).
4. *(Optional)* Add a `GITHUB_TOKEN` environment variable in Vercel Project Settings if you want higher GitHub API fallback rate limits for non-`main`/`master` default branches.
5. Click **Deploy**.
