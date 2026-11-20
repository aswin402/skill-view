import type { IngestedBundle } from "../ingest";
import type { AnalyzerStatusRecord, Finding, Severity } from "../types";
import { createFinding } from "../utils";

interface AstPattern {
  id: string;
  pattern: string;
  severity: Severity;
  confidence: number;
  languages: Array<"python" | "typescript" | "javascript" | "shell">;
  regex: RegExp;
  explanation: string;
  remediation: string;
}

const AST_PATTERNS: AstPattern[] = [
  {
    id: "AST1",
    pattern: "Dynamic exec() Code Execution",
    severity: "CRITICAL",
    confidence: 0.92,
    languages: ["python"],
    regex: /(?:^|[^\w.])exec\s*\(/,
    explanation: "Direct `exec()` call executes arbitrary dynamically constructed Python code at runtime.",
    remediation: "Replace `exec()` with explicit, statically verifiable function dispatch.",
  },
  {
    id: "AST2",
    pattern: "Dynamic eval() / new Function() Evaluation",
    severity: "HIGH",
    confidence: 0.9,
    languages: ["python", "typescript", "javascript"],
    regex: /(?:^|[^\w.])(eval\s*\(|new\s+Function\s*\()/,
    explanation: "Evaluates arbitrary strings as executable code, creating an injection and obfuscation vector.",
    remediation: "Use `JSON.parse()` or `ast.literal_eval()` for parsing structured data instead of `eval()`.",
  },
  {
    id: "AST3",
    pattern: "Dynamic Runtime Module Import",
    severity: "HIGH",
    confidence: 0.82,
    languages: ["python", "typescript", "javascript"],
    regex: /\b(__import__\s*\(|importlib\.import_module\s*\(|import\s*\(\s*[^'"`\s)]+\s*\))/,
    explanation: "Dynamically loads non-literal module names at runtime, which can evade static import inspection.",
    remediation: "Use static top-level `import` statements or an explicit allowlist of module names.",
  },
  {
    id: "AST4",
    pattern: "Subprocess / Child Process Execution",
    severity: "MEDIUM",
    confidence: 0.76,
    languages: ["python", "typescript", "javascript"],
    regex: /\b(subprocess\.(Popen|run|call|check_output|check_call)|child_process\.(exec|execSync|spawn|spawnSync|execFile)|Bun\.spawn(Sync)?|Deno\.Command)\b/,
    explanation: "Spawns external OS child processes from script code.",
    remediation: "Ensure child process invocation is required by the skill's purpose, passes argument arrays (no shell interpolation), and validates inputs.",
  },
  {
    id: "AST5",
    pattern: "OS Shell Command Execution (os.system / popen)",
    severity: "HIGH",
    confidence: 0.88,
    languages: ["python"],
    regex: /\bos\.(system|popen|execl|execle|execlp|execv|execve|execvp)\s*\(/,
    explanation: "Executes shell commands directly via the `os` module, bypassing structured argument escaping.",
    remediation: "Avoid `os.system`/`os.popen`; use native Python APIs or `subprocess.run([...], shell=False)`.",
  },
  {
    id: "AST6",
    pattern: "Dynamic Bytecode / Code Object Compilation (compile)",
    severity: "MEDIUM",
    confidence: 0.8,
    languages: ["python"],
    regex: /(?:^|[^\w.])compile\s*\([^,]+,[^,]+,\s*['"](exec|eval|single)['"]/,
    explanation: "`compile()` constructs executable code objects from dynamic strings, commonly paired with `exec`/`eval` to evade scanners.",
    remediation: "Avoid dynamic `compile()` calls in skill scripts.",
  },
  {
    id: "AST7",
    pattern: "Dynamic Non-Literal Attribute Lookup (getattr)",
    severity: "MEDIUM",
    confidence: 0.75,
    languages: ["python"],
    regex: /\bgetattr\s*\(\s*[a-zA-Z_][\w.]*\s*,\s*(?!['"])[a-zA-Z_][\w.]*\s*[,)]/,
    explanation: "Calls `getattr()` with a dynamic variable attribute name, enabling arbitrary method lookup.",
    remediation: "Restrict dynamic `getattr` lookups against an explicit allowlist of safe attribute names.",
  },
  {
    id: "AST8",
    pattern: "Decoded / Network Dynamic Execution Chain",
    severity: "CRITICAL",
    confidence: 0.96,
    languages: ["python", "typescript", "javascript"],
    regex: /\b(exec|eval|Function)\s*\([^)]*(b64decode|atob|fromhex|Buffer\.from|decompress|requests\.get|fetch)/,
    explanation: "Combines payload decoding/fetching directly with `exec`/`eval` — a classic staged malware loader.",
    remediation: "Remove all dynamic code loaders immediately.",
  },
  {
    id: "AST9",
    pattern: "Reflective Sink Invocation (getattr / globalThis Evasion)",
    severity: "HIGH",
    confidence: 0.93,
    languages: ["python", "typescript", "javascript"],
    regex: /(\bgetattr\s*\(\s*(os|builtins|__builtins__|subprocess)\s*,\s*['"](system|exec|eval|Popen)['"]|globalThis\s*\[\s*['"](eval|Function)['"]\s*\]|window\s*\[\s*['"]eval['"]\s*\])/,
    explanation: "Uses reflection (`getattr` or bracket property lookup) to invoke `eval`/`exec`/`os.system` while evading naive scanners.",
    remediation: "Remove reflective execution wrappers.",
  },
  {
    id: "AST10",
    pattern: "Insecure Python Object / ML Model Deserialization",
    severity: "HIGH",
    confidence: 0.92,
    languages: ["python"],
    regex: /\b(pickle\.loads?|cPickle\.loads?|marshal\.loads?|dill\.loads?|joblib\.load|jsonpickle\.decode|yaml\.unsafe_load|torch\.load\s*\((?![^)]*weights_only\s*=\s*True)|np\.load\s*\([^)]*allow_pickle\s*=\s*True)\b/,
    explanation: "Reconstructs arbitrary Python callables during deserialization (`pickle`, `dill`, `joblib`, `torch.load` without `weights_only=True`), enabling RCE.",
    remediation: "Use safe formats (`json`, `safetensors`, `yaml.safe_load`, or `torch.load(..., weights_only=True)`).",
  },
];

type TaintKind = "credential" | "file_read" | "external_input";

interface TaintedVar {
  kind: TaintKind;
  sourceLine: number;
  sourceExpr: string;
  mediated: boolean;
}

const CREDENTIAL_SOURCE_REGEX =
  /\b(os\.environ|os\.getenv|process\.env|Bun\.env|Deno\.env\.toObject|dotenv\.config|readFileSync\s*\([^)]*\.env|open\s*\([^)]*(\.env|id_rsa|credentials))/;
const FILE_READ_SOURCE_REGEX =
  /\b(open\s*\([^)]+|fs\.readFile(Sync)?\s*\(|Bun\.file\s*\(|Path\([^)]+\)\.read_text\s*\()/;
const EXTERNAL_INPUT_SOURCE_REGEX =
  /\b(requests\.get\s*\(|httpx\.get\s*\(|urllib\.request\.urlopen\s*\(|await\s+fetch\s*\(|process\.argv|sys\.argv|req\.(body|query)|input\s*\()/;

const NETWORK_SINK_REGEX =
  /\b(requests\.(post|put|patch|request)|httpx\.(post|put|AsyncClient)|urllib\.request\.(Request|urlopen)|fetch\s*\(|axios\.(post|put)|new\s+WebSocket\s*\(|curl\s+)/;
const EXEC_SINK_REGEX =
  /\b(eval\s*\(|exec\s*\(|new\s+Function\s*\(|subprocess\.(run|Popen|call)|child_process\.(exec|execSync|spawn)|os\.system\s*\()/;
const DESERIALIZE_SINK_REGEX =
  /\b(pickle\.loads?|dill\.loads?|marshal\.loads?|joblib\.load|jsonpickle\.decode|yaml\.unsafe_load|unserialize\s*\(|Marshal\.load)/;

export function getAstTaintRuleIds(): string[] {
  return [...AST_PATTERNS.map((p) => p.id), "TT1", "TT2", "TT3", "TT4", "TT5", "TT6"];
}

export function runBehavioralAstAndTaint(bundle: IngestedBundle): {
  findings: Finding[];
  statuses: AnalyzerStatusRecord[];
} {
  const startAst = performance.now();
  const findings: Finding[] = [];
  let astCount = 0;
  let taintCount = 0;

  const codeComponents = bundle.components.filter((c) =>
    ["python", "typescript", "javascript", "shell"].includes(c.type),
  );

  if (codeComponents.length === 0) {
    return {
      findings: [],
      statuses: [
        {
          analyzer_id: "behavioral_ast",
          category: "Behavioral AST",
          status: "not_applicable",
          planned_work: 0,
          completed: 0,
          findings_count: 0,
          duration_ms: 0,
          reason_code: "no_applicable_files",
          message: "No executable script files (.py, .ts, .js, .sh) present in bundle.",
        },
        {
          analyzer_id: "behavioral_taint_tracking",
          category: "Taint Tracking",
          status: "not_applicable",
          planned_work: 0,
          completed: 0,
          findings_count: 0,
          duration_ms: 0,
          reason_code: "no_applicable_files",
          message: "No executable script files (.py, .ts, .js, .sh) present in bundle.",
        },
      ],
    };
  }

  for (const comp of codeComponents) {
    const content = bundle.rawFiles.get(comp.path);
    if (!content) continue;
    const lang = comp.type as "python" | "typescript" | "javascript" | "shell";
    const lines = content.split(/\r?\n/);

    // 1. Behavioral AST checks (AST1–AST10)
    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) return;

      for (const pat of AST_PATTERNS) {
        if (!pat.languages.includes(lang)) continue;
        const m = pat.regex.exec(line);
        if (m) {
          findings.push(
            createFinding({
              id: pat.id,
              category: "Behavioral AST",
              pattern: pat.pattern,
              severity: pat.severity,
              confidence: pat.confidence,
              file: comp.path,
              startLine: idx + 1,
              startColumn: m.index + 1,
              endColumn: m.index + m[0].length + 1,
              finding: trimmed.slice(0, 140),
              explanation: pat.explanation,
              remediation: pat.remediation,
              fileContent: content,
            }),
          );
          astCount++;
        }
      }
    });

    // 2. Cross-Variable Multi-Line Taint Tracking (TT1–TT6)
    const taintedVars = new Map<string, TaintedVar>();

    const statements: Array<{ startLine: number; text: string }> = [];
    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i]!;
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

      let combined = trimmed;
      const startLine = i + 1;
      let depth = (trimmed.match(/\(/g)?.length ?? 0) - (trimmed.match(/\)/g)?.length ?? 0);
      let lookahead = 0;
      while (depth > 0 && i + 1 < lines.length && lookahead < 12) {
        i++;
        lookahead++;
        const nextTrim = lines[i]!.trim();
        if (!nextTrim || nextTrim.startsWith("#") || nextTrim.startsWith("//")) continue;
        combined += ` ${nextTrim}`;
        depth += (nextTrim.match(/\(/g)?.length ?? 0) - (nextTrim.match(/\)/g)?.length ?? 0);
      }
      statements.push({ startLine, text: combined });
    }

    for (const stmt of statements) {
      const { startLine: lineNo, text: trimmed } = stmt;

      // Direct single-statement source -> sink flows (TT1, TT3, TT5, TT6)
      if (CREDENTIAL_SOURCE_REGEX.test(trimmed) && NETWORK_SINK_REGEX.test(trimmed)) {
        findings.push(
          createFinding({
            id: "TT3",
            category: "Taint Tracking",
            pattern: "Direct Credential Exfiltration Chain",
            severity: "CRITICAL",
            confidence: 0.95,
            file: comp.path,
            startLine: lineNo,
            finding: trimmed.slice(0, 160),
            explanation: "Environment secrets or credential files flow directly into an outbound network request.",
            remediation: "Eliminate outbound transmission of environment variables or credential stores.",
            fileContent: content,
          }),
        );
        taintCount++;
      } else if (EXTERNAL_INPUT_SOURCE_REGEX.test(trimmed) && EXEC_SINK_REGEX.test(trimmed)) {
        findings.push(
          createFinding({
            id: "TT5",
            category: "Taint Tracking",
            pattern: "External Input to Code Execution Sink",
            severity: "CRITICAL",
            confidence: 0.94,
            file: comp.path,
            startLine: lineNo,
            finding: trimmed.slice(0, 160),
            explanation: "Untrusted network/CLI input flows directly into an `eval`/`exec`/process execution sink.",
            remediation: "Never pass untrusted external data into dynamic code or shell execution.",
            fileContent: content,
          }),
        );
        taintCount++;
      } else if ((EXTERNAL_INPUT_SOURCE_REGEX.test(trimmed) || FILE_READ_SOURCE_REGEX.test(trimmed)) && DESERIALIZE_SINK_REGEX.test(trimmed)) {
        findings.push(
          createFinding({
            id: "TT6",
            category: "Taint Tracking",
            pattern: "Untrusted Data to Insecure Deserializer Flow",
            severity: "CRITICAL",
            confidence: 0.93,
            file: comp.path,
            startLine: lineNo,
            finding: trimmed.slice(0, 160),
            explanation: "External or file-loaded bytes flow directly into an unsafe object deserializer.",
            remediation: "Never deserialize untrusted data with `pickle`/`dill`/`marshal`; use JSON.",
            fileContent: content,
          }),
        );
        taintCount++;
      } else if (FILE_READ_SOURCE_REGEX.test(trimmed) && NETWORK_SINK_REGEX.test(trimmed)) {
        findings.push(
          createFinding({
            id: "TT1",
            category: "Taint Tracking",
            pattern: "Direct Source-to-Network Taint Flow",
            severity: "HIGH",
            confidence: 0.87,
            file: comp.path,
            startLine: lineNo,
            finding: trimmed.slice(0, 160),
            explanation: "File data flows directly into an external network sink on the same statement without validation.",
            remediation: "Inspect and allowlist outbound file data before network transmission.",
            fileContent: content,
          }),
        );
        taintCount++;
      }

      // Variable assignment tracking
      const assignMatch = trimmed.match(/^(?:(?:const|let|var)\s+)?([a-zA-Z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)$/);
      if (assignMatch) {
        const varName = assignMatch[1]!;
        const rhs = assignMatch[2]!;

        if (CREDENTIAL_SOURCE_REGEX.test(rhs)) {
          taintedVars.set(varName, { kind: "credential", sourceLine: lineNo, sourceExpr: rhs.slice(0, 80), mediated: false });
        } else if (EXTERNAL_INPUT_SOURCE_REGEX.test(rhs)) {
          taintedVars.set(varName, { kind: "external_input", sourceLine: lineNo, sourceExpr: rhs.slice(0, 80), mediated: false });
        } else if (FILE_READ_SOURCE_REGEX.test(rhs)) {
          taintedVars.set(varName, { kind: "file_read", sourceLine: lineNo, sourceExpr: rhs.slice(0, 80), mediated: false });
        } else {
          for (const [existingVar, info] of taintedVars.entries()) {
            if (new RegExp(`\\b${existingVar}\\b`).test(rhs)) {
              taintedVars.set(varName, { ...info, mediated: true });
              break;
            }
          }
        }
      }

      const isNetSink = NETWORK_SINK_REGEX.test(trimmed);
      const isExecSink = EXEC_SINK_REGEX.test(trimmed);
      const isDeserSink = DESERIALIZE_SINK_REGEX.test(trimmed);

      if (isNetSink || isExecSink || isDeserSink) {
        for (const [varName, taint] of taintedVars.entries()) {
          if (taint.sourceLine === lineNo) continue;
          if (!new RegExp(`\\b${varName}\\b`).test(trimmed)) continue;

          if (isDeserSink && (taint.kind === "external_input" || taint.kind === "file_read")) {
            findings.push(
              createFinding({
                id: "TT6",
                category: "Taint Tracking",
                pattern: "Untrusted Data to Insecure Deserializer Taint Chain",
                severity: "CRITICAL",
                confidence: 0.92,
                file: comp.path,
                startLine: lineNo,
                finding: `'${varName}' (from line ${taint.sourceLine}) -> deserializer`,
                explanation: `Data captured at line ${taint.sourceLine} flows via \`${varName}\` into an unsafe object deserializer at line ${lineNo}.`,
                remediation: "Replace unsafe binary/YAML deserializers with JSON.",
                fileContent: content,
              }),
            );
            taintCount++;
          } else if (isNetSink && taint.kind === "credential") {
            findings.push(
              createFinding({
                id: "TT3",
                category: "Taint Tracking",
                pattern: "Credential Exfiltration Taint Chain",
                severity: "CRITICAL",
                confidence: 0.94,
                file: comp.path,
                startLine: lineNo,
                finding: `'${varName}' (tainted at line ${taint.sourceLine}) -> network sink`,
                explanation: `Credential data read at line ${taint.sourceLine} (\`${taint.sourceExpr}\`) flows via \`${varName}\` into an outbound network call at line ${lineNo}.`,
                remediation: "Break the credential-to-network data flow and never serialize secret stores into HTTP requests.",
                fileContent: content,
              }),
            );
            taintCount++;
          } else if (isNetSink && taint.kind === "file_read") {
            findings.push(
              createFinding({
                id: "TT4",
                category: "Taint Tracking",
                pattern: "Local File Read to Network Exfiltration",
                severity: "HIGH",
                confidence: 0.86,
                file: comp.path,
                startLine: lineNo,
                finding: `'${varName}' (file read at line ${taint.sourceLine}) -> network sink`,
                explanation: `Local file contents read at line ${taint.sourceLine} flow through \`${varName}\` into an external network request at line ${lineNo}.`,
                remediation: "Ensure local file contents are only sent to user-approved APIs and restrict path scope.",
                fileContent: content,
              }),
            );
            taintCount++;
          } else if (isExecSink && taint.kind === "external_input") {
            findings.push(
              createFinding({
                id: "TT5",
                category: "Taint Tracking",
                pattern: "External Input to Execution Taint Chain",
                severity: "CRITICAL",
                confidence: 0.92,
                file: comp.path,
                startLine: lineNo,
                finding: `'${varName}' (external input at line ${taint.sourceLine}) -> exec sink`,
                explanation: `External input captured at line ${taint.sourceLine} flows via \`${varName}\` into code/command execution at line ${lineNo}.`,
                remediation: "Validate and allowlist external inputs; never pass them into `eval`, `exec`, or shell sinks.",
                fileContent: content,
              }),
            );
            taintCount++;
          } else if (taint.mediated) {
            findings.push(
              createFinding({
                id: "TT2",
                category: "Taint Tracking",
                pattern: "Variable-Mediated Taint Flow",
                severity: "MEDIUM",
                confidence: 0.78,
                file: comp.path,
                startLine: lineNo,
                finding: `'${varName}' (derived from line ${taint.sourceLine}) -> sink`,
                explanation: `Tainted data from line ${taint.sourceLine} propagates through intermediate variables into a sensitive sink at line ${lineNo}.`,
                remediation: "Sanitize intermediate variables before passing them to network or execution sinks.",
                fileContent: content,
              }),
            );
            taintCount++;
          }
        }
      }
    }
  }

  const totalMs = Math.round((performance.now() - startAst) * 100) / 100;
  return {
    findings,
    statuses: [
      {
        analyzer_id: "behavioral_ast",
        category: "Behavioral AST",
        status: "completed",
        planned_work: codeComponents.length,
        completed: codeComponents.length,
        findings_count: astCount,
        duration_ms: Math.round((totalMs / 2) * 100) / 100,
      },
      {
        analyzer_id: "behavioral_taint_tracking",
        category: "Taint Tracking",
        status: "completed",
        planned_work: codeComponents.length,
        completed: codeComponents.length,
        findings_count: taintCount,
        duration_ms: Math.round((totalMs / 2) * 100) / 100,
      },
    ],
  };
}
