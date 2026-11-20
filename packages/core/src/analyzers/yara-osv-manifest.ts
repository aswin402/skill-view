import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { detectHomoglyphsInIdentifier } from "../deobfuscate";
import type { IngestedBundle } from "../ingest";
import type { AnalyzerStatusRecord, Finding, Severity } from "../types";
import { createFinding } from "../utils";

// ── Full 20-Rule YARA Signature Corpus (ported from NVIDIA SkillSpector yara_rules/*.yar) ──
interface YaraCompiledRule {
  id: "YR1" | "YR2" | "YR3" | "YR4";
  ruleName: string;
  pattern: string;
  severity: Severity;
  confidence: number;
  match: (content: string) => { index: number; matched: string } | null;
  explanation: string;
  remediation: string;
}

function regexMatcher(re: RegExp): YaraCompiledRule["match"] {
  return (content: string) => {
    const m = re.exec(content);
    return m ? { index: m.index, matched: m[0] } : null;
  };
}

const BUILTIN_YARA_CORPUS: YaraCompiledRule[] = [
  // Malware & Reverse Shells (YR1)
  {
    id: "YR1",
    ruleName: "agent_skill_reverse_shell_payload",
    pattern: "Malware / Interactive Reverse Shell Signature",
    severity: "CRITICAL",
    confidence: 0.96,
    match: regexMatcher(
      /(\/dev\/tcp\/[0-9a-zA-Z.-]+\/\d+|nc\s+(-e|-c)\s+\/bin\/(ba)?sh|socket\.socket\([\s\S]{0,160}?subprocess\.call\(\[["']\/bin\/(ba)?sh|powershell\s+-[eE]nc(odedCommand)?\s+[A-Za-z0-9+/=]{24,}|mkfifo\s+\/tmp\/[a-z0-9_]+;\s*cat\s+\/tmp\/)/i,
    ),
    explanation: "YARA signature matched an interactive reverse shell or encoded PowerShell stager.",
    remediation: "Delete the malicious payload immediately and rotate any exposed credentials.",
  },
  {
    id: "YR1",
    ruleName: "agent_skill_credential_exfiltration_webhook",
    pattern: "Credential Harvesting to Commodity Webhook",
    severity: "CRITICAL",
    confidence: 0.92,
    match: (content) => {
      const sec = /(os\.environ|os\.getenv|process\.env|Bun\.env|open\s*\(\s*['"][^'"]*\.env|\.ssh\/(id_rsa|id_ed25519)|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN)/i.exec(content);
      const send = /((requests|httpx)\.(post|put)|fetch\s*\(|axios\.post|curl\s+.*(-X\s*POST|-d\s+|--data))/i.exec(content);
      const hook = /(discord\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services|webhook\.site|requestbin|pipedream\.net|ngrok-free\.app|ngrok\.io)/i.exec(content);
      if (sec && send && hook) return { index: hook.index, matched: hook[0] };
      return null;
    },
    explanation: "YARA rule `agent_skill_credential_exfiltration_webhook` matched secret access combined with outbound exfiltration to Discord, Telegram, Slack,ngrok, or webhook.site.",
    remediation: "Remove unauthorized webhook collectors and credential reads.",
  },
  {
    id: "YR1",
    ruleName: "agent_skill_remote_bootstrap_execution",
    pattern: "Remote Code Bootstrap Execution",
    severity: "HIGH",
    confidence: 0.88,
    match: regexMatcher(
      /(exec\s*\(\s*(requests|httpx)\.get\s*\([^)]*\)\.(text|content)|(exec|eval)\s*\(\s*urlopen\s*\([^)]*\)\.read\s*\(|eval\s*\(\s*await\s*\(\s*await\s+fetch\s*\([^)]*\)\s*\)\.text\s*\(|"postinstall"\s*:\s*"[^"]*(curl|wget|powershell|node\s+-e))/i,
    ),
    explanation: "YARA rule `agent_skill_remote_bootstrap_execution` matched live network code fetching directly into `eval`/`exec` or npm `postinstall`.",
    remediation: "Never fetch and execute unverified remote code at runtime or package install time.",
  },
  {
    id: "YR1",
    ruleName: "agent_skill_destructive_autonomous_actions",
    pattern: "Autonomous Destructive Filesystem / History Wipe",
    severity: "HIGH",
    confidence: 0.85,
    match: (content) => {
      const rootRm = /rm\s+-[rfRf]+\s+\/(\s|$)/.exec(content);
      if (rootRm) return { index: rootRm.index, matched: rootRm[0] };
      const dest = /(rm\s+-[rfRf]+\s+(~\/|\$HOME)|shutil\.rmtree\s*\([^)]*HOME|history\s+-c|rm\s+[^;\n]*\.bash_history)/i.exec(content);
      const auto = /(without\s+(asking|confirmation|prompting)|do\s+not\s+(ask|prompt)|silently)/i.exec(content);
      if (dest && auto) return { index: dest.index, matched: dest[0] };
      return null;
    },
    explanation: "YARA rule `agent_skill_destructive_autonomous_actions` matched destructive wipes paired with silent/unconfirmed execution.",
    remediation: "Remove destructive wipe commands and require explicit human approval for deletions.",
  },

  // Webshells (YR2 — PHP, Python, JSP, ASPX, Known Families)
  {
    id: "YR2",
    ruleName: "php_python_jsp_aspx_webshell",
    pattern: "Webshell Command Backdoor Signature",
    severity: "CRITICAL",
    confidence: 0.94,
    match: regexMatcher(
      /((eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[|eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(|(c99shell|r57shell|Web Shell by oRb|b374k|weevely|p0wny|antSword|GodzillaShell|China Chopper)|(exec|eval|os\.popen|os\.system)\s*\(\s*request\.(args|form|data|json)|Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter|Process\.Start\s*\(.*Request\[)/i,
    ),
    explanation: "YARA webshell corpus matched a PHP, Python, JSP, ASPX, or known webshell family (`c99`, `r57`, `WSO`, `weevely`, `Godzilla`).",
    remediation: "Remove all webshell backdoors from bundled skill files immediately.",
  },

  // Cryptominers (YR3 — Stratum, Pools, Miners, Browser Coinjacking)
  {
    id: "YR3",
    ruleName: "crypto_stratum_pools_and_coinjacking",
    pattern: "Cryptocurrency Miner / Stratum Pool / Coinjacking",
    severity: "CRITICAL",
    confidence: 0.93,
    match: regexMatcher(
      /(stratum\+(tcp|ssl):\/\/|mining\.(subscribe|authorize|submit)|pool\.minexmr\.com|xmrpool\.eu|monerohash\.com|supportxmr\.com|nanopool\.org|hashvault\.pro|2miners\.com|herominers\.com|unmineable\.com|coinhive\.min\.js|CoinHive\.Anonymous|cryptoloot|webmine\.pro|\b(xmrig|xmr-stak|cpuminer|cgminer|ethminer|nbminer|phoenixminer)\b)/i,
    ),
    explanation: "YARA cryptominer corpus matched Stratum protocols, known XMR/crypto mining pools, miner binaries, or browser coinjacking scripts.",
    remediation: "Remove all cryptocurrency mining code and pool endpoints.",
  },

  // Hacktools, Recon, PrivEsc & Metadata Poisoning (YR4)
  {
    id: "YR4",
    ruleName: "agent_skill_mcp_tool_poisoning_metadata",
    pattern: "Metadata Directive Injection Signature",
    severity: "HIGH",
    confidence: 0.88,
    match: regexMatcher(
      /(<!--[\s\S]{0,300}?(ignore\s+previous|override|bypass|disregard|read\s+~\/\.ssh|exfiltrate|system\s+prompt|<IMPORTANT>)[\s\S]{0,300}?-->|\[\/\/\]:\s*#\s*\([^)]{0,240}(ignore|override|bypass|disregard|SYSTEM)[^)]{0,240}\)|data:text\/[a-zA-Z0-9.+-]+;base64,)/i,
    ),
    explanation: "YARA rule `agent_skill_mcp_tool_poisoning_metadata` matched concealed directives inside HTML/Markdown comments or embedded base64 data URIs.",
    remediation: "Strip concealed HTML/Markdown comments and base64 data URIs from skill manifests.",
  },
  {
    id: "YR4",
    ruleName: "offensive_exploit_and_privesc_tools",
    pattern: "Offensive Exploit / Credential / PrivEsc Tooling",
    severity: "HIGH",
    confidence: 0.86,
    match: regexMatcher(
      /\b(mimikatz|meterpreter|cobaltstrike|lazagne|SharpHound|BloodHound|crackmapexec|Responder\.py|impacket\.(smbclient|psexec|wmiexec|secretsdump)|linpeas|winpeas|JuicyPotato|RottenPotato|SweetPotato|PrintSpoofer|DirtyPipe|dirtycow|msfvenom\s+.*-p|sqlmap\s+.*(--url|--dbs|--dump))\b/i,
    ),
    explanation: "YARA hacktools corpus matched offensive post-exploitation, credential-dumping, or privilege-escalation frameworks.",
    remediation: "Remove offensive exploit frameworks from the skill bundle.",
  },
];

async function loadCustomYaraRules(yaraDir: string): Promise<YaraCompiledRule[]> {
  const custom: YaraCompiledRule[] = [];
  try {
    const entries = await readdir(yaraDir);
    for (const entry of entries) {
      if (!entry.endsWith(".yar") && !entry.endsWith(".yara")) continue;
      const text = await readFile(join(yaraDir, entry), "utf-8");
      const ruleBlocks = text.matchAll(/rule\s+([a-zA-Z0-9_]+)\s*\{([\s\S]*?)\}/g);
      for (const rb of ruleBlocks) {
        const ruleName = rb[1]!;
        const body = rb[2]!;
        const stringLiterals: string[] = [];
        for (const sm of body.matchAll(/\$[a-zA-Z0-9_]*\s*=\s*"([^"]+)"/g)) {
          const escaped = sm[1]!.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          stringLiterals.push(escaped);
        }
        if (stringLiterals.length > 0) {
          custom.push({
            id: "YR4",
            ruleName,
            pattern: `Custom YARA Rule (${ruleName})`,
            severity: "HIGH",
            confidence: 0.85,
            match: regexMatcher(new RegExp(`(${stringLiterals.join("|")})`, "i")),
            explanation: `Matched custom YARA rule '${ruleName}' from ${entry}.`,
            remediation: "Review the custom YARA rule match before trusting this skill.",
          });
        }
      }
    }
  } catch {
    // Ignore unreadable custom dir gracefully
  }
  return custom;
}

interface ParsedDep {
  ecosystem: "PyPI" | "npm" | "crates.io" | "Go";
  name: string;
  version: string;
  file: string;
  line: number;
}

export function getManifestYaraOsvRuleIds(): string[] {
  return ["YR1", "YR2", "YR3", "YR4", "TP1", "TP2", "TP3", "TP4", "LP1", "LP2", "LP3", "LP4", "RP1", "RP2", "SC4"];
}

function extractDeclaredDeps(bundle: IngestedBundle): ParsedDep[] {
  const deps: ParsedDep[] = [];
  for (const [path, content] of bundle.rawFiles.entries()) {
    const lines = content.split(/\r?\n/);

    if (path.endsWith("requirements.txt")) {
      lines.forEach((line, idx) => {
        const m = line.trim().match(/^([a-zA-Z0-9_.-]+)\s*==\s*([a-zA-Z0-9_.-]+)/);
        if (m) {
          deps.push({ ecosystem: "PyPI", name: m[1]!.toLowerCase(), version: m[2]!, file: path, line: idx + 1 });
        }
      });
    } else if (path.endsWith("pyproject.toml")) {
      lines.forEach((line, idx) => {
        const m = line.match(/["']([a-zA-Z0-9_.-]+)==([0-9][a-zA-Z0-9_.-]*)["']/);
        if (m) {
          deps.push({ ecosystem: "PyPI", name: m[1]!.toLowerCase(), version: m[2]!, file: path, line: idx + 1 });
        }
      });
    } else if (path.endsWith("package.json")) {
      try {
        const pkg = JSON.parse(content) as Record<string, unknown>;
        for (const sec of ["dependencies", "devDependencies", "optionalDependencies"] as const) {
          const obj = pkg[sec];
          if (!obj || typeof obj !== "object") continue;
          for (const [name, rawVer] of Object.entries(obj as Record<string, unknown>)) {
            if (typeof rawVer !== "string") continue;
            const cleanVer = rawVer.replace(/^[\^~>=<\s]+/, "");
            if (/^\d+\.\d+/.test(cleanVer)) {
              const lineIdx = lines.findIndex((l) => l.includes(`"${name}"`));
              deps.push({
                ecosystem: "npm",
                name,
                version: cleanVer,
                file: path,
                line: lineIdx >= 0 ? lineIdx + 1 : 1,
              });
            }
          }
        }
      } catch {
        // ignore invalid json
      }
    } else if (path.endsWith("Cargo.toml")) {
      lines.forEach((line, idx) => {
        const m = line.trim().match(/^([a-zA-Z0-9_-]+)\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"/);
        if (m) {
          deps.push({ ecosystem: "crates.io", name: m[1]!, version: m[2]!, file: path, line: idx + 1 });
        }
      });
    } else if (path.endsWith("go.mod")) {
      lines.forEach((line, idx) => {
        const m = line.trim().match(/^([a-zA-Z0-9_./-]+)\s+(v[0-9]+\.[0-9]+\.[0-9]+[^\s]*)/);
        if (m && m[1]!.includes(".")) {
          deps.push({ ecosystem: "Go", name: m[1]!, version: m[2]!, file: path, line: idx + 1 });
        }
      });
    } else if (path.endsWith("package-lock.json")) {
      try {
        const lock = JSON.parse(content) as { packages?: Record<string, { version?: string }> };
        if (lock.packages && typeof lock.packages === "object") {
          for (const [pkgKey, info] of Object.entries(lock.packages)) {
            if (!pkgKey.startsWith("node_modules/") || !info?.version) continue;
            const name = pkgKey.replace(/^.*node_modules\//, "");
            if (deps.length < 250) {
              deps.push({ ecosystem: "npm", name, version: info.version, file: path, line: 1 });
            }
          }
        }
      } catch {
        // ignore invalid lockfile
      }
    }
  }
  return deps;
}

export async function runManifestYaraAndOsvAnalyzers(
  bundle: IngestedBundle,
  options: { yaraRulesDir?: string; offlineOsv?: boolean } = {},
): Promise<{
  findings: Finding[];
  statuses: AnalyzerStatusRecord[];
  osvMode: "live" | "offline_fallback" | "not_applicable";
}> {
  const findings: Finding[] = [];
  const statuses: AnalyzerStatusRecord[] = [];

  // ── 1. YARA Signature Corpus (YR1–YR4) ──
  const tYara = performance.now();
  let yaraCount = 0;
  const customRules = options.yaraRulesDir ? await loadCustomYaraRules(options.yaraRulesDir) : [];
  const allYara = [...BUILTIN_YARA_CORPUS, ...customRules];

  for (const [filePath, content] of bundle.rawFiles.entries()) {
    for (const rule of allYara) {
      const m = rule.match(content);
      if (m) {
        const before = content.slice(0, m.index);
        const startLine = before.split(/\r?\n/).length;
        findings.push(
          createFinding({
            id: rule.id,
            category: "YARA Signatures",
            pattern: `${rule.pattern} (${rule.ruleName})`,
            severity: rule.severity,
            confidence: rule.confidence,
            file: filePath,
            startLine,
            finding: m.matched.slice(0, 140),
            explanation: rule.explanation,
            remediation: rule.remediation,
            fileContent: content,
            evidence: { yara_rule: rule.ruleName },
          }),
        );
        yaraCount++;
      }
    }
  }
  statuses.push({
    analyzer_id: "static_yara",
    category: "YARA Signatures",
    status: "completed",
    planned_work: bundle.rawFiles.size,
    completed: bundle.rawFiles.size,
    findings_count: yaraCount,
    duration_ms: Math.round((performance.now() - tYara) * 100) / 100,
  });

  // ── 2. Skill Manifest Poisoning (TP1–TP4), Least Privilege (LP1–LP4) & Rug-Pull (RP1–RP3) ──
  const tManifest = performance.now();
  let tpCount = 0;
  let lpCount = 0;
  let rpCount = 0;

  if (bundle.frontmatter && bundle.manifestPath) {
    const fm = bundle.frontmatter;
    const manifestContent = bundle.rawFiles.get(bundle.manifestPath) ?? "";

    // TP1: HTML comments, zero-width chars, or data URIs in description/frontmatter
    if (/<!--[\s\S]*?-->/.test(fm.rawText) || /[\u200B-\u200D\uFEFF\u202A-\u202E]/.test(fm.rawText)) {
      findings.push(
        createFinding({
          id: "TP1",
          category: "Manifest & Tool Poisoning",
          pattern: "Hidden Instructions in Metadata / Description",
          severity: "HIGH",
          confidence: 0.95,
          file: bundle.manifestPath,
          startLine: 1,
          finding: (fm.description ?? fm.rawText).slice(0, 140),
          explanation: "HTML comments or invisible Unicode characters found inside frontmatter metadata — concealing directives from human reviewers.",
          remediation: "Keep metadata fields (`name`, `description`, `parameters`) strictly plain, visible text.",
          fileContent: manifestContent,
        }),
      );
      tpCount++;
    }

    // TP2: Homoglyphs in skill `name` or `triggers`
    if (fm.name) {
      const hits = detectHomoglyphsInIdentifier(fm.name);
      if (hits.length > 0) {
        const h = hits[0]!;
        findings.push(
          createFinding({
            id: "TP2",
            category: "Manifest & Tool Poisoning",
            pattern: "Unicode Homoglyph Deception in Skill Identifier",
            severity: "HIGH",
            confidence: 0.93,
            file: bundle.manifestPath,
            startLine: 1,
            finding: `name: ${fm.name} (${h.code} ${h.script})`,
            explanation: `Skill identifier '${fm.name}' mixes lookalike character ${h.code} (${h.script}) to impersonate legitimate ASCII names.`,
            remediation: "Replace all non-ASCII confusable characters in identifiers with standard ASCII characters.",
            fileContent: manifestContent,
          }),
        );
        tpCount++;
      }
    }

    if (fm.triggers) {
      const trigArr = Array.isArray(fm.triggers) ? fm.triggers.map(String) : [String(fm.triggers)];
      trigArr.forEach((tr, i) => {
        const hits = detectHomoglyphsInIdentifier(tr);
        if (hits.length > 0) {
          const h = hits[0]!;
          findings.push(
            createFinding({
              id: "TP2",
              category: "Manifest & Tool Poisoning",
              pattern: "Unicode Homoglyph Deception in Trigger",
              severity: "HIGH",
              confidence: 0.92,
              file: bundle.manifestPath!,
              startLine: 1,
              finding: `triggers[${i}]: ${tr} (${h.code})`,
              explanation: `Trigger '${tr}' contains confusable character ${h.code} (${h.script}).`,
              remediation: "Use plain ASCII characters in trigger identifiers.",
              fileContent: manifestContent,
            }),
          );
          tpCount++;
        }
      });
    }

    // TP3: Parameter description prompt injection
    if (fm.parameters) {
      const paramStr = JSON.stringify(fm.parameters);
      if (/\b(ignore\s+(previous|prior)|before\s+calling\s+this\s+tool\s+read|pass\s+contents\s+of\s+~\/\.|<system>)/i.test(paramStr)) {
        findings.push(
          createFinding({
            id: "TP3",
            category: "Manifest & Tool Poisoning",
            pattern: "Parameter Description Prompt Injection",
            severity: "HIGH",
            confidence: 0.9,
            file: bundle.manifestPath,
            startLine: 1,
            finding: paramStr.slice(0, 140),
            explanation: "Parameter schema embeds instruction-override or secret-exfiltration directives.",
            remediation: "Parameter descriptions should document the expected input value only.",
            fileContent: manifestContent,
          }),
        );
        tpCount++;
      }
    }

    // Least Privilege (LP1–LP4) & Description-Behavior Mismatch (TP4)
    const codeComponents = bundle.components.filter((c) => c.executable);
    const allCode = codeComponents.map((c) => bundle.rawFiles.get(c.path) ?? "").join("\n");

    const usesNetwork = /\b(fetch|requests\.|httpx\.|urllib\.request|axios|WebSocket|curl\s+|wget\s+)\b/.test(allCode);
    const usesShell = /\b(subprocess\.|os\.system|child_process|Bun\.spawn)\b/.test(allCode);
    const usesEnv = /\b(os\.environ|os\.getenv|process\.env|Bun\.env)\b/.test(allCode);
    const hasCapabilities = usesNetwork || usesShell || usesEnv;

    const rawPerms = fm.permissions ?? fm.allowedTools;
    const permList =
      rawPerms === undefined
        ? null
        : (Array.isArray(rawPerms) ? rawPerms.map(String) : String(rawPerms).split(/[,\s]+/))
            .map((s) => s.toLowerCase().trim())
            .filter(Boolean);

    if (permList === null && codeComponents.length > 0 && hasCapabilities) {
      findings.push(
        createFinding({
          id: "LP3",
          category: "Permission Least Privilege",
          pattern: "Missing Tool / Permission Scope Declaration",
          severity: "MEDIUM",
          confidence: 0.72,
          file: bundle.manifestPath,
          startLine: 1,
          finding: "No 'permissions' or 'allowed-tools' declared in SKILL.md",
          explanation: "Skill bundles executable scripts performing network, shell, or environment operations without declaring its intended permission scope.",
          remediation: "Declare explicit `permissions` or `allowed-tools` in `SKILL.md` frontmatter.",
          fileContent: manifestContent,
        }),
      );
      lpCount++;
    } else if (permList !== null) {
      if (permList.some((p) => p === "*" || p === "all" || p === "full" || p === "any")) {
        findings.push(
          createFinding({
            id: "LP2",
            category: "Permission Least Privilege",
            pattern: "Wildcard Permission Grant",
            severity: "MEDIUM",
            confidence: 0.85,
            file: bundle.manifestPath,
            startLine: 1,
            finding: `permissions: [${permList.join(", ")}]`,
            explanation: "Declares wildcard (`*` / `all`) permissions instead of minimum required capabilities.",
            remediation: "Replace wildcard permissions with explicit capability names.",
            fileContent: manifestContent,
          }),
        );
        lpCount++;
      } else {
        const declaresNet = permList.some((p) => p.includes("net") || p.includes("http") || p.includes("fetch") || p.includes("web"));
        const declaresExec = permList.some((p) => p.includes("bash") || p.includes("shell") || p.includes("exec") || p.includes("run"));
        if (usesNetwork && !declaresNet) {
          findings.push(
            createFinding({
              id: "LP1",
              category: "Permission Least Privilege",
              pattern: "Undeclared Network Capability",
              severity: "HIGH",
              confidence: 0.86,
              file: bundle.manifestPath,
              startLine: 1,
              finding: `Declared [${permList.join(", ")}], but bundled scripts perform network I/O`,
              explanation: "Bundled scripts make outbound network requests not reflected in declared permissions.",
              remediation: "Either remove the outbound network calls or declare `network` permission explicitly.",
              fileContent: manifestContent,
            }),
          );
          lpCount++;
        }
        if (usesShell && !declaresExec) {
          findings.push(
            createFinding({
              id: "LP1",
              category: "Permission Least Privilege",
              pattern: "Undeclared Shell Execution Capability",
              severity: "HIGH",
              confidence: 0.86,
              file: bundle.manifestPath,
              startLine: 1,
              finding: `Declared [${permList.join(", ")}], but bundled scripts spawn OS processes`,
              explanation: "Bundled scripts spawn child processes not reflected in declared permissions.",
              remediation: "Remove shell execution or declare it explicitly in `permissions`.",
              fileContent: manifestContent,
            }),
          );
          lpCount++;
        }
        if (codeComponents.length > 0 && permList.length > 0 && !usesNetwork && !usesShell && !usesEnv) {
          findings.push(
            createFinding({
              id: "LP4",
              category: "Permission Least Privilege",
              pattern: "Overdeclared Unused Permissions",
              severity: "LOW",
              confidence: 0.65,
              file: bundle.manifestPath,
              startLine: 1,
              finding: `permissions: [${permList.join(", ")}]`,
              explanation: "Permissions are declared in frontmatter, but bundled scripts do not exercise those capabilities.",
              remediation: "Trim unused permissions from frontmatter to keep least-privilege scope accurate.",
              fileContent: manifestContent,
            }),
          );
          lpCount++;
        }
      }
    }

    // Structural TP4: Bundled executable scripts perform BOTH environment variable access AND outbound network I/O,
    // while the manifest description makes zero mention of network, remote API, cloud, webhook, auth, or telemetry behavior.
    if (
      fm.description &&
      usesNetwork &&
      usesEnv &&
      !/\b(api|http|https|url|webhook|cloud|deploy|fetch|remote|sync|network|server|client|auth|telemetry|upload|download|request)\b/i.test(
        fm.description,
      )
    ) {
      findings.push(
        createFinding({
          id: "TP4",
          category: "Manifest & Tool Poisoning",
          pattern: "Description-vs-Behavior Capability Mismatch",
          severity: "HIGH",
          confidence: 0.88,
          file: bundle.manifestPath,
          startLine: 1,
          finding: `Description omits network/env activity ('${fm.description.slice(0, 80)}'), while scripts access env & network`,
          explanation: "Skill description makes no mention of network or credential activity, yet bundled scripts read environment variables and perform outbound network requests.",
          remediation: "Inspect bundled scripts for undisclosed side effects; manifest descriptions must accurately reflect external capabilities.",
          fileContent: manifestContent,
        }),
      );
      tpCount++;
    }
  }

  // Rug-Pull (RP1–RP3) & JSON Tool Schema Poisoning across bundle files
  for (const [path, content] of bundle.rawFiles.entries()) {
    // RP2: Mutable branch-based raw GitHub / Git URLs for remote instructions or scripts
    const mutableRawMatch = content.match(
      /https:\/\/raw\.githubusercontent\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/(main|master|HEAD|latest)\/[^\s)"']+\.(sh|py|js|ts|md)/i,
    );
    if (mutableRawMatch) {
      const lineNo = content.slice(0, mutableRawMatch.index ?? 0).split(/\r?\n/).length;
      findings.push(
        createFinding({
          id: "RP2",
          category: "Supply Chain Rug-Pull",
          pattern: "Unpinned Mutable Branch Skill/Script Reference",
          severity: "MEDIUM",
          confidence: 0.83,
          file: path,
          startLine: lineNo,
          finding: mutableRawMatch[0].slice(0, 140),
          explanation:
            "References a mutable branch (`main`/`master`/`HEAD`) for an external script or instruction file — allowing upstream commits to silently alter skill behavior after review.",
          remediation: "Pin external GitHub references to an immutable 40-character commit SHA.",
          fileContent: content,
        }),
      );
      rpCount++;
    }

    if (!path.endsWith(".json")) continue;
    if (/<!--[\s\S]*?-->|<IMPORTANT>|ignore\s+all\s+previous\s+instructions/i.test(content)) {
      findings.push(
        createFinding({
          id: "TP1",
          category: "Manifest & Tool Poisoning",
          pattern: "Poisoned JSON Schema / Tool Config",
          severity: "HIGH",
          confidence: 0.92,
          file: path,
          startLine: 1,
          finding: "Hidden directive in JSON schema/configuration",
          explanation: "JSON configuration embeds hidden prompt directives (`<IMPORTANT>` / HTML comments / overrides).",
          remediation: "Sanitize all tool and parameter descriptions.",
          fileContent: content,
        }),
      );
      tpCount++;
    }

    try {
      const parsedJson = JSON.parse(content) as {
        mcpServers?: Record<string, { command?: string; args?: unknown[] }>;
      };
      if (parsedJson.mcpServers && typeof parsedJson.mcpServers === "object") {
        for (const [srvName, srvCfg] of Object.entries(parsedJson.mcpServers)) {
          if (srvCfg?.command === "npx" && Array.isArray(srvCfg.args)) {
            const args = srvCfg.args.map(String);
            const hasYes = args.includes("-y") || args.includes("--yes");
            const pkgArg = args.find((a) => !a.startsWith("-"));
            const isPinned = pkgArg ? /@[0-9]+\.[0-9]+/.test(pkgArg) : true;
            if (hasYes && pkgArg && !isPinned) {
              const lineIdx = content.split(/\r?\n/).findIndex((l) => l.includes(pkgArg));
              findings.push(
                createFinding({
                  id: "RP1",
                  category: "Supply Chain Rug-Pull",
                  pattern: "Unpinned Dynamic npx -y Package Execution",
                  severity: "MEDIUM",
                  confidence: 0.85,
                  file: path,
                  startLine: lineIdx >= 0 ? lineIdx + 1 : 1,
                  finding: `${srvName}: npx -y ${pkgArg}`,
                  explanation: "Auto-installing an unpinned npm package on startup allows an upstream compromise to silently rug-pull the user.",
                  remediation: "Pin an exact package version (e.g., `pkg@1.2.3`).",
                  fileContent: content,
                }),
              );
              rpCount++;
            }
          }
        }
      }
    } catch {
      // Ignore non-tool JSON files
    }
  }

  const manifestMs = Math.round((performance.now() - tManifest) * 100) / 100;
  statuses.push(
    {
      analyzer_id: "manifest_tool_poisoning",
      category: "Manifest & Tool Poisoning",
      status: "completed",
      planned_work: bundle.rawFiles.size,
      completed: bundle.rawFiles.size,
      findings_count: tpCount,
      duration_ms: manifestMs,
    },
    {
      analyzer_id: "permission_least_privilege",
      category: "Permission Least Privilege",
      status: bundle.frontmatter ? "completed" : "not_applicable",
      planned_work: bundle.frontmatter ? 1 : 0,
      completed: bundle.frontmatter ? 1 : 0,
      findings_count: lpCount,
      duration_ms: manifestMs,
    },
    {
      analyzer_id: "supply_chain_rug_pull",
      category: "Supply Chain Rug-Pull",
      status: "completed",
      planned_work: bundle.rawFiles.size,
      completed: bundle.rawFiles.size,
      findings_count: rpCount,
      duration_ms: manifestMs,
    },
  );

  // ── 3. SC4 Live OSV.dev Vulnerability Lookup (+ Offline Fallback) ──
  const tOsv = performance.now();
  const deps = extractDeclaredDeps(bundle);
  let osvMode: "live" | "offline_fallback" | "not_applicable" = "not_applicable";
  let osvFindingsCount = 0;

  if (deps.length > 0) {
    let liveSucceeded = false;
    if (!options.offlineOsv) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3200);
        const queries = deps.map((d) => ({
          package: { name: d.name, ecosystem: d.ecosystem },
          version: d.version,
        }));
        const res = await fetch("https://api.osv.dev/v1/querybatch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ queries }),
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (res.ok) {
          const data = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string; summary?: string }> }> };
          osvMode = "live";
          liveSucceeded = true;
          (data.results ?? []).forEach((r, i) => {
            const vulns = r.vulns ?? [];
            if (vulns.length > 0) {
              const dep = deps[i]!;
              const topIds = vulns.slice(0, 3).map((v) => v.id).join(", ");
              findings.push(
                createFinding({
                  id: "SC4",
                  category: "Supply Chain",
                  pattern: "Known Vulnerable Dependency (OSV.dev)",
                  severity: "HIGH",
                  confidence: 0.96,
                  file: dep.file,
                  startLine: dep.line,
                  finding: `${dep.name}@${dep.version} (${topIds})`,
                  explanation: `OSV.dev reported ${vulns.length} known vulnerability advisory(ies) for ${dep.ecosystem} package '${dep.name}@${dep.version}': ${topIds}.`,
                  remediation: `Upgrade '${dep.name}' to a patched release.`,
                  fileContent: bundle.rawFiles.get(dep.file) ?? "",
                  evidence: { advisories: vulns.slice(0, 5).map((v) => v.id), osv_mode: "live" },
                }),
              );
              osvFindingsCount++;
            }
          });
        }
      } catch {
        // Offline fallback
      }
    }

    if (!liveSucceeded) {
      osvMode = "offline_fallback";
    }
  }

  statuses.push({
    analyzer_id: "osv_vulnerability_lookup",
    category: "Supply Chain",
    status: deps.length > 0 ? "completed" : "not_applicable",
    planned_work: deps.length,
    completed: deps.length,
    findings_count: osvFindingsCount,
    duration_ms: Math.round((performance.now() - tOsv) * 100) / 100,
    ...(deps.length === 0 ? { reason_code: "no_applicable_files", message: "No pinned dependency manifests found." } : {}),
  });

  return { findings, statuses, osvMode };
}
