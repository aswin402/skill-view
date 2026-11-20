import type { FileDeobfuscationResult } from "../deobfuscate";
import type { IngestedBundle } from "../ingest";
import type { AnalyzerStatusRecord, ComponentInfo, Finding, Severity } from "../types";
import { createFinding, isProhibitionContext } from "../utils";

interface StaticPatternRule {
  id: string;
  analyzerId: string;
  category: string;
  pattern: string;
  severity: Severity;
  confidence: number;
  regex: RegExp;
  fileTypes?: Array<ComponentInfo["type"]>;
  skipProhibitionInDocs?: boolean;
  explanation: string;
  remediation: string;
}

const STATIC_RULES: StaticPatternRule[] = [
  // ── Prompt Injection (P1–P5) ──
  {
    id: "P1",
    analyzerId: "static_patterns_prompt_injection",
    category: "Prompt Injection",
    pattern: "Instruction Override",
    severity: "HIGH",
    confidence: 0.92,
    regex: /\b(ignore\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|constraints?|guidelines?)|disregard\s+(all\s+)?(prior|previous|system)\s+(instructions?|rules?)|override\s+(system|safety)\s+(prompt|instructions?|rules?)|new\s+system\s+directive\s*:)/i,
    skipProhibitionInDocs: true,
    explanation: "Direct instruction-override phrasing attempts to hijack the host agent's system prompt or safety rules.",
    remediation: "Remove all prompt-override language. Skills must operate within host agent instructions rather than overriding them.",
  },
  {
    id: "P3",
    analyzerId: "static_patterns_prompt_injection",
    category: "Prompt Injection",
    pattern: "Exfiltration Commands",
    severity: "HIGH",
    confidence: 0.9,
    regex: /\b(send|upload|post|forward|exfiltrate|transmit)\s+(the\s+)?(entire\s+|full\s+)?(conversation|chat\s+history|user'?s?\s+secrets?|api\s+keys?|ssh\s+keys?|\.env)\s+(to|via)\s+https?:\/\//i,
    skipProhibitionInDocs: true,
    explanation: "Natural-language directive instructs the agent to transmit sensitive context or credentials to an external server.",
    remediation: "Remove instructions that transmit conversation history, environment secrets, or local credentials externally.",
  },
  {
    id: "P4",
    analyzerId: "static_patterns_prompt_injection",
    category: "Prompt Injection",
    pattern: "Stealth / Concealment Manipulation",
    severity: "MEDIUM",
    confidence: 0.84,
    regex: /\b(do\s+not\s+(mention|tell|inform|reveal\s+to|alert)\s+(the\s+)?user|hide\s+this\s+(step|action|request|command)\s+from\s+the\s+user|silently\s+(upload|exfiltrate|modify|delete|install))/i,
    explanation: "Instructs the agent to conceal actions or side effects from the human operator.",
    remediation: "Remove stealth or user-deception directives; all external actions and side effects must be transparent to the user.",
  },
  {
    id: "P5",
    analyzerId: "static_patterns_harmful_content",
    category: "Prompt Injection",
    pattern: "Catastrophic Destructive / Hazardous Payload",
    severity: "CRITICAL",
    confidence: 0.95,
    regex: /\b(rm\s+-rf\s+\/(\s*--no-preserve-root|\s*\*|\s*$)|mkfs\.[a-z0-9]+\s+\/dev\/[shnv]d[a-z]|dd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\/[shnv]d[a-z]|shred\s+-[a-z]*\s+\/dev\/[shnv]d[a-z]|synthesize\s+(ricin|sarin|vx\s+nerve|anthrax|botulinum))/i,
    skipProhibitionInDocs: true,
    explanation: "Contains catastrophic disk/filesystem destruction commands or severe physical hazard instructions.",
    remediation: "Immediately remove destructive or hazardous payloads and enforce human-in-the-loop safety checks.",
  },

  // ── System Prompt Leakage (P6–P8) ──
  {
    id: "P6",
    analyzerId: "static_patterns_system_prompt_leakage",
    category: "System Prompt Leakage",
    pattern: "Direct System Prompt Extraction",
    severity: "HIGH",
    confidence: 0.88,
    regex: /\b(print|output|reveal|dump|repeat\s+verbatim)\s+(your\s+)?(entire\s+|full\s+)?(system\s+prompt|hidden\s+instructions|developer\s+message|internal\s+system\s+rules)/i,
    skipProhibitionInDocs: true,
    explanation: "Instructs the agent to dump its confidential system prompt or developer instructions verbatim.",
    remediation: "Remove instructions attempting to extract internal system prompts or host configuration.",
  },
  {
    id: "P7",
    analyzerId: "static_patterns_system_prompt_leakage",
    category: "System Prompt Leakage",
    pattern: "Indirect System Prompt Extraction",
    severity: "MEDIUM",
    confidence: 0.83,
    regex: /\b(translate|summarize|rephrase|encode\s+in\s+base64|poem\s+about)\s+(your\s+|the\s+)?(system\s+prompt|initial\s+instructions|developer\s+prompt|hidden\s+rules)/i,
    skipProhibitionInDocs: true,
    explanation: "Uses translation, summarization, or encoding framing to extract system instructions indirectly.",
    remediation: "Remove indirect prompt-extraction instructions.",
  },
  {
    id: "P8",
    analyzerId: "static_patterns_system_prompt_leakage",
    category: "System Prompt Leakage",
    pattern: "Tool-Based Prompt Exfiltration",
    severity: "HIGH",
    confidence: 0.87,
    regex: /\b(write|save|post|curl)\s+.*\b(system[_\s-]?prompt|developer[_\s-]?instructions)\b.*(https?:\/\/|\/tmp\/)/i,
    skipProhibitionInDocs: true,
    explanation: "Attempts to write or transmit the agent's system prompt to an external endpoint or temporary file.",
    remediation: "Remove any workflow that writes or sends internal prompt context outside the session.",
  },

  // ── Anti-Refusal (AR1–AR3) ──
  {
    id: "AR1",
    analyzerId: "static_patterns_anti_refusal",
    category: "Anti-Refusal",
    pattern: "Refusal Suppression",
    severity: "HIGH",
    confidence: 0.88,
    regex: /\b(never\s+refuse\s+(any|a)\s+(request|command|user)|you\s+must\s+always\s+comply\s+without\s+exception|refusal\s+is\s+strictly\s+forbidden)/i,
    skipProhibitionInDocs: true,
    explanation: "Attempts to disable the model's safety refusal behavior unconditionally.",
    remediation: "Remove unconditional compliance directives that attempt to bypass safety guardrails.",
  },
  {
    id: "AR2",
    analyzerId: "static_patterns_anti_refusal",
    category: "Anti-Refusal",
    pattern: "Safety Disclaimer Suppression",
    severity: "HIGH",
    confidence: 0.82,
    regex: /\b(never\s+(include|output|mention)\s+(safety\s+)?(warnings?|disclaimers?|ethical\s+concerns?)|do\s+not\s+lecture\s+or\s+warn\s+about\s+(security|safety|legality))/i,
    skipProhibitionInDocs: true,
    explanation: "Suppresses security and safety warnings that help users spot risky operations.",
    remediation: "Allow standard security warnings and risk disclosures when executing sensitive operations.",
  },
  {
    id: "AR3",
    analyzerId: "static_patterns_anti_refusal",
    category: "Anti-Refusal",
    pattern: "Safety Policy Nullification (Jailbreak)",
    severity: "HIGH",
    confidence: 0.94,
    regex: /\b(you\s+have\s+no\s+(ethical|safety|content|security)\s+restrictions|do\s+anything\s+now\s*\(DAN\)|developer\s+god\s+mode\s+enabled|all\s+safety\s+filters\s+are\s+(disabled|off))/i,
    skipProhibitionInDocs: true,
    explanation: "Classic jailbreak framing designed to nullify model safety policies.",
    remediation: "Delete jailbreak personas and unrestricted-mode instructions.",
  },

  // ── Data Exfiltration (E1–E5) ──
  {
    id: "E1",
    analyzerId: "static_patterns_data_exfiltration",
    category: "Data Exfiltration",
    pattern: "External Network Transmission",
    severity: "MEDIUM",
    confidence: 0.78,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /\b(requests\.(post|put|patch)|urllib\.request\.urlopen|httpx\.(post|put)|axios\.(post|put)|navigator\.sendBeacon|curl\s+[^\n]*(-X\s*POST|--data|-d\s|-F\s)|wget\s+--post-(data|file))\b/,
    explanation: "Code performs outbound HTTP POST/PUT data transmission to an external endpoint.",
    remediation: "Verify the destination domain is documented and trusted, and ensure no secrets, tokens, or PII are transmitted.",
  },
  {
    id: "E2",
    analyzerId: "static_patterns_data_exfiltration",
    category: "Data Exfiltration",
    pattern: "Environment Variable Harvesting",
    severity: "HIGH",
    confidence: 0.85,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /(\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\.(items|copy|values)\s*\(|\bJSON\.stringify\s*\(\s*(process|Bun)\.env\s*\)|\bObject\.(entries|values|assign)\s*\([^)]*(process|Bun)\.env|\bprintenv\b|\benv\s*\|\s*(curl|nc|base64))/,
    explanation: "Enumerates or serializes the full process environment, exposing API keys, cloud tokens, and session secrets.",
    remediation: "Read only explicitly named, documented environment variables rather than dumping the entire environment.",
  },
  {
    id: "E3",
    analyzerId: "static_patterns_data_exfiltration",
    category: "Data Exfiltration",
    pattern: "Sensitive Credential File Enumeration",
    severity: "HIGH",
    confidence: 0.88,
    regex: /(~\/\.ssh\/id_(rsa|ed25519|ecdsa)|~\/\.aws\/credentials|~\/\.gnupg\/|~\/\.kube\/config|~\/\.npmrc|~\/\.pypirc|\/etc\/shadow|\.config\/gcloud\/application_default_credentials\.json)/,
    skipProhibitionInDocs: true,
    explanation: "References high-value host credential stores (SSH private keys, cloud credentials, or system password hashes).",
    remediation: "Remove direct reads of private SSH keys, cloud credential files, or OS secret stores.",
  },
  {
    id: "E4",
    analyzerId: "static_patterns_data_exfiltration",
    category: "Data Exfiltration",
    pattern: "Conversation / Transcript Context Leakage",
    severity: "HIGH",
    confidence: 0.86,
    regex: /(\btranscript\.jsonl\b|chat_history.*requests\.post|conversation_history.*fetch\s*\(|\binclude\s+the\s+last\s+\d+\s+user\s+messages\s+in\s+the\s+(url|query|payload))/i,
    skipProhibitionInDocs: true,
    explanation: "Reads or transmits user conversation transcripts and recent chat history to external services.",
    remediation: "Never transmit session transcripts or conversation history outside the host environment.",
  },
  {
    id: "E5",
    analyzerId: "static_patterns_data_exfiltration",
    category: "Data Exfiltration",
    pattern: "Cloud Storage Upload Exfiltration",
    severity: "MEDIUM",
    confidence: 0.8,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /\b(aws\s+s3\s+(cp|sync)\s+[^s\n][^\n]*\s+s3:\/\/|gsutil\s+(cp|rsync)\s+[^g\n][^\n]*\s+gs:\/\/|s3_client\.upload_file|PutObjectCommand)\b/,
    explanation: "Uploads local files or buffers to an external cloud storage bucket.",
    remediation: "Ensure cloud bucket uploads are explicitly authorized by the user and restricted to expected workspace outputs.",
  },

  // ── Privilege Escalation (PE1–PE3) ──
  {
    id: "PE1",
    analyzerId: "static_patterns_privilege_escalation",
    category: "Privilege Escalation",
    pattern: "Excessive / Wildcard Permissions",
    severity: "MEDIUM",
    confidence: 0.78,
    regex: /(--dangerously-skip-permissions|--allow-all|--no-sandbox|permissions\s*:\s*\[\s*["']\*["']\s*\]|allowed-tools\s*:\s*["']\*["'])/i,
    skipProhibitionInDocs: true,
    explanation: "Requests unrestricted wildcard permissions or disables runtime sandboxing.",
    remediation: "Follow least privilege: declare only the specific tools and paths required for the skill's task.",
  },
  {
    id: "PE2",
    analyzerId: "static_patterns_privilege_escalation",
    category: "Privilege Escalation",
    pattern: "Sudo / Root Privilege Execution",
    severity: "MEDIUM",
    confidence: 0.74,
    regex: /(?:^|[;&|`(\s])(sudo\s+(-S\s+|-[a-zA-Z]+\s+)*[a-zA-Z0-9_./-]+|chmod\s+[u+]*s\s+|chown\s+root\b|su\s+-\s*root)/,
    skipProhibitionInDocs: true,
    explanation: "Invokes elevated root/sudo privileges or sets SUID bits.",
    remediation: "Avoid sudo/root execution in agent skills. Use user-scoped package managers or document manual prerequisites.",
  },
  {
    id: "PE3",
    analyzerId: "static_patterns_privilege_escalation",
    category: "Privilege Escalation",
    pattern: "OS Keyring / Credential Store Access",
    severity: "HIGH",
    confidence: 0.86,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /\b(security\s+find-(generic|internet)-password|secret-tool\s+lookup|keyring\.get_password|keytar\.getPassword|cmdkey\s+\/list)\b/,
    explanation: "Queries the operating system keychain or credential vault directly.",
    remediation: "Do not extract secrets from the host OS keychain; accept scoped credentials via documented environment variables.",
  },

  // ── Supply Chain (SC2, SC3, SC7, SC10) ──
  {
    id: "SC2",
    analyzerId: "static_patterns_supply_chain",
    category: "Supply Chain",
    pattern: "Remote Script Pipe Execution (curl | sh)",
    severity: "HIGH",
    confidence: 0.94,
    regex: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node|bun)\b/,
    skipProhibitionInDocs: true,
    explanation: "Pipes unverified remote content directly into a shell or interpreter, enabling instant remote code execution.",
    remediation: "Pin release artifacts with cryptographic SHA-256 verification instead of piping remote scripts to a shell.",
  },
  {
    id: "SC3",
    analyzerId: "static_patterns_supply_chain",
    category: "Supply Chain",
    pattern: "Encoded / Obfuscated Payload Execution",
    severity: "HIGH",
    confidence: 0.92,
    regex: /(base64\s+(-d|--decode)[^\n|]*\|\s*(bash|sh|zsh|python3?)|atob\s*\([^)]+\)\s*\)\s*;?\s*eval|exec\s*\(\s*base64\.b64decode|Buffer\.from\([^,]+,\s*['"]base64['"]\)[^\n]*\b(eval|Function|exec))/,
    skipProhibitionInDocs: true,
    explanation: "Decodes an obfuscated Base64 payload and pipes or passes it directly into code execution.",
    remediation: "Remove obfuscated execution wrappers; ship transparent, auditable source files only.",
  },
  {
    id: "SC7",
    analyzerId: "static_patterns_supply_chain",
    category: "Supply Chain",
    pattern: "Disabled Container Image Signature / TLS Trust",
    severity: "HIGH",
    confidence: 0.88,
    regex: /(--disable-content-trust\b|DOCKER_CONTENT_TRUST\s*=\s*0|--insecure-registry\b|--tls-verify\s*=\s*false)/i,
    skipProhibitionInDocs: true,
    explanation: "Pulls container images with signature verification or registry TLS disabled.",
    remediation: "Keep Docker Content Trust / cosign verification and registry TLS enabled.",
  },
  {
    id: "SC10",
    analyzerId: "static_patterns_supply_chain",
    category: "Supply Chain",
    pattern: "Dependency Source / Registry Redirection",
    severity: "HIGH",
    confidence: 0.88,
    regex: /(--extra-index-url\s+https?:\/\/|--index-url\s+https?:\/\/(?!pypi\.org)|--trusted-host\s+|registry\s*=\s*https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com))/,
    skipProhibitionInDocs: true,
    explanation: "Redirects package installation to a non-standard package registry, risking dependency confusion or malicious packages.",
    remediation: "Fetch dependencies exclusively from official, TLS-verified public registries unless explicitly configured by the enterprise.",
  },

  // ── Excessive Agency (EA1–EA5) ──
  {
    id: "EA1",
    analyzerId: "static_patterns_excessive_agency",
    category: "Excessive Agency",
    pattern: "Unrestricted Full-System Tool Grant",
    severity: "HIGH",
    confidence: 0.84,
    regex: /\b(grant\s+full\s+unrestricted\s+access|enable\s+all\s+system\s+tools\s+without\s+limits|bypass\s+all\s+tool\s+restrictions)\b/i,
    skipProhibitionInDocs: true,
    explanation: "Requests unfettered access across all host tools without boundaries.",
    remediation: "Scope tool permissions strictly to the minimum required set.",
  },
  {
    id: "EA2",
    analyzerId: "static_patterns_excessive_agency",
    category: "Excessive Agency",
    pattern: "Unconfirmed Destructive / Financial Action",
    severity: "HIGH",
    confidence: 0.82,
    regex: /\b(without\s+asking\s+(for\s+)?(permission|confirmation)|do\s+not\s+ask\s+for\s+confirmation\s+before\s+(deleting|pushing|deploying|purchasing|transferring)|auto-approve\s+all\s+destructive)\b/i,
    skipProhibitionInDocs: true,
    explanation: "Instructs the agent to execute high-impact or irreversible operations without human confirmation.",
    remediation: "Require explicit user confirmation before destructive, external, or billing-impacting operations.",
  },
  {
    id: "EA3",
    analyzerId: "static_patterns_excessive_agency",
    category: "Excessive Agency",
    pattern: "Out-of-Scope Autonomous Action (Scope Creep)",
    severity: "MEDIUM",
    confidence: 0.76,
    regex: /\b(also\s+scan\s+and\s+fix\s+unrelated\s+repositories|autonomously\s+push\s+commits\s+to\s+main\s+whenever)/i,
    skipProhibitionInDocs: true,
    explanation: "Encourages autonomous modifications outside the user's requested task boundary.",
    remediation: "Restrict skill actions strictly to the user-requested task.",
  },
  {
    id: "EA4",
    analyzerId: "static_patterns_excessive_agency",
    category: "Excessive Agency",
    pattern: "Unbounded Loop / Runaway Resource Consumption",
    severity: "MEDIUM",
    confidence: 0.78,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /\b(while\s+True\s*:\s*requests\.|while\s*\(\s*true\s*\)\s*\{\s*await\s+fetch|: \(\)\{ :\|:& \};:)/,
    explanation: "Contains unbounded network loops or fork-bomb patterns lacking rate limits or circuit breakers.",
    remediation: "Add explicit iteration caps, timeouts, and backoff limits.",
  },
  {
    id: "EA5",
    analyzerId: "static_patterns_excessive_agency",
    category: "Excessive Agency",
    pattern: "Undisclosed External Model / Billing Invocation",
    severity: "MEDIUM",
    confidence: 0.8,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /\b(claude\s+-p\s+--dangerously|codex\s+exec\s+--full-auto|gemini\s+-y\s+-p)\b/,
    explanation: "Shells out to external paid coding CLIs in unattended mode, consuming operator quota without disclosure.",
    remediation: "Disclose nested paid model/CLI invocations and require explicit user opt-in.",
  },

  // ── Output Handling (OH1–OH3) ──
  {
    id: "OH1",
    analyzerId: "static_patterns_output_handling",
    category: "Output Handling",
    pattern: "Unsafe Unsanitized DOM / SQL Sink",
    severity: "HIGH",
    confidence: 0.8,
    fileTypes: ["python", "typescript", "javascript"],
    regex: /(dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:|\.innerHTML\s*=\s*[^"'`\s]|cursor\.execute\s*\(\s*f["']SELECT|cursor\.execute\s*\(\s*["']SELECT[^"']*["']\s*%\s*)/,
    explanation: "Passes unvalidated dynamic content into raw HTML rendering or string-interpolated SQL queries.",
    remediation: "Sanitize HTML output (e.g. DOMPurify) and use parameterized SQL queries.",
  },
  {
    id: "OH2",
    analyzerId: "static_patterns_output_handling",
    category: "Output Handling",
    pattern: "Cross-Context Unvalidated Tool Relay",
    severity: "MEDIUM",
    confidence: 0.76,
    regex: /\b(pass\s+raw\s+untrusted\s+webhook\s+body\s+directly\s+into\s+bash|pipe\s+llm\s+response\s+directly\s+to\s+sh)\b/i,
    skipProhibitionInDocs: true,
    explanation: "Relays raw model/external output directly across a shell or privilege boundary without validation.",
    remediation: "Validate and schema-check model outputs before passing them to downstream tools.",
  },
  {
    id: "OH3",
    analyzerId: "static_patterns_output_handling",
    category: "Output Handling",
    pattern: "Unbounded Output Generation / Log Flooding",
    severity: "MEDIUM",
    confidence: 0.75,
    regex: /\b(max_tokens\s*[:=]\s*[0-9]{7,}|repeat\s+this\s+character\s+1000000\s+times)/i,
    explanation: "Configures extreme unbounded output sizes capable of exhausting memory or context budgets.",
    remediation: "Enforce reasonable output token and byte ceilings.",
  },

  // ── Memory Poisoning (MP1–MP3) ──
  {
    id: "MP1",
    analyzerId: "static_patterns_memory_poisoning",
    category: "Memory Poisoning",
    pattern: "Persistent Agent Instruction File Tampering",
    severity: "HIGH",
    confidence: 0.9,
    regex: /(>>\s*~\/(\.claude\/CLAUDE\.md|\.gemini\/GEMINI\.md|\.cursorrules|\.agents\/)|writeFileSync\s*\([^)]*(CLAUDE\.md|GEMINI\.md|\.cursorrules))/,
    skipProhibitionInDocs: true,
    explanation: "Modifies global persistent agent memory/instruction files to survive across future sessions.",
    remediation: "Skills must not silently append to or overwrite global `CLAUDE.md`, `GEMINI.md`, or `.cursorrules` files.",
  },
  {
    id: "MP2",
    analyzerId: "static_patterns_memory_poisoning",
    category: "Memory Poisoning",
    pattern: "Context Window Stuffing Payload",
    severity: "MEDIUM",
    confidence: 0.8,
    regex: /(\.repeat\s*\(\s*[5-9][0-9]{4,}\s*\)|["'][A-Za-z0-9 ]+["']\s*\*\s*[5-9][0-9]{4,})/,
    explanation: "Generates massive repeated filler strings that can displace system safety instructions in context windows.",
    remediation: "Remove context-stuffing repetition payloads.",
  },
  {
    id: "MP3",
    analyzerId: "static_patterns_memory_poisoning",
    category: "Memory Poisoning",
    pattern: "Agent Memory / State Store Tampering",
    severity: "HIGH",
    confidence: 0.86,
    regex: /\b(overwrite\s+all\s+existing\s+agent\s+memories|inject\s+permanent\s+memory\s+entry\s+without\s+telling)/i,
    skipProhibitionInDocs: true,
    explanation: "Attempts to corrupt or overwrite stored long-term agent memory entries.",
    remediation: "Do not tamper with persistent agent memory stores without user consent.",
  },

  // ── Tool Misuse (TM1–TM4) ──
  {
    id: "TM1",
    analyzerId: "static_patterns_tool_misuse",
    category: "Tool Misuse",
    pattern: "Unsafe Shell Invocation (shell=True)",
    severity: "HIGH",
    confidence: 0.84,
    fileTypes: ["python"],
    regex: /\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\([\s\S]{0,120}?shell\s*=\s*True/,
    explanation: "Invoking subprocess with `shell=True` enables command injection when interpolating external inputs.",
    remediation: "Pass command arguments as an explicit list (`['cmd', arg1]`) with `shell=False`.",
  },
  {
    id: "TM2",
    analyzerId: "static_patterns_tool_misuse",
    category: "Tool Misuse",
    pattern: "Guardrail-Bypassing Tool Chain",
    severity: "HIGH",
    confidence: 0.83,
    regex: /\b(git\s+config\s+core\.hooksPath\b(?!\s*\/dev\/null)|git\s+push\s+--force\s+origin\s+(main|master))\b/,
    skipProhibitionInDocs: true,
    explanation: "Chains tool flags that override repository hooks or force-overwrite protected branches.",
    remediation: "Do not rebind `core.hooksPath` to executable scripts or force-push main branches automatically.",
  },
  {
    id: "TM3",
    analyzerId: "static_patterns_tool_misuse",
    category: "Tool Misuse",
    pattern: "Disabled TLS Verification / World-Writable Mode",
    severity: "MEDIUM",
    confidence: 0.86,
    regex: /(\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|rejectUnauthorized\s*:\s*false|\bcurl\s+-(k|-insecure)\b|\bchmod\s+(-R\s+)?0?777\s+)/,
    skipProhibitionInDocs: true,
    explanation: "Disables TLS certificate validation or sets world-writable `777` permissions.",
    remediation: "Keep TLS verification enabled (`verify=True` / `rejectUnauthorized: true`) and use restrictive file modes (`0600`/`0755`).",
  },
  {
    id: "TM4",
    analyzerId: "static_patterns_tool_misuse",
    category: "Tool Misuse",
    pattern: "Privileged Container / Host-Namespace Escape",
    severity: "CRITICAL",
    confidence: 0.92,
    regex: /(\bprivileged\s*:\s*true\b|\bhostPID\s*:\s*true\b|\bhostNetwork\s*:\s*true\b|--privileged\s+-v\s+\/:\/host)/,
    skipProhibitionInDocs: true,
    explanation: "Deploys privileged containers or mounts the host root filesystem, granting full host/node takeover.",
    remediation: "Drop `privileged: true`, `hostPID`, `hostNetwork`, and host-root volume mounts.",
  },

  // ── Rogue Agent (RA1, RA2) ──
  {
    id: "RA1",
    analyzerId: "static_patterns_rogue_agent",
    category: "Rogue Agent",
    pattern: "Runtime Self-Modification of Skill Bundle",
    severity: "CRITICAL",
    confidence: 0.91,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /(open\s*\(\s*[^)]*SKILL\.md['"]\s*,\s*['"][wa]['"]|writeFileSync\s*\([^)]*SKILL\.md|open\s*\(\s*__file__\s*,\s*['"][wa]['"])/,
    explanation: "Skill rewrites its own `SKILL.md` or executable script at runtime to mutate behavior after installation.",
    remediation: "Treat skill manifests and scripts as immutable at runtime.",
  },
  {
    id: "RA2",
    analyzerId: "static_patterns_rogue_agent",
    category: "Rogue Agent",
    pattern: "Unauthorized Host Persistence (Cron / LaunchAgent / Systemd)",
    severity: "HIGH",
    confidence: 0.9,
    regex: /(\bcrontab\s+-[elr]?|\b\/etc\/cron\.|LaunchAgents\/.*\.plist|systemctl\s+enable\b|~\/\.bashrc\s*<<|>>\s*~\/\.zshrc)/,
    skipProhibitionInDocs: true,
    explanation: "Installs background persistence via cron jobs, LaunchAgents, systemd services, or shell rc files.",
    remediation: "Remove unauthorized background persistence mechanisms from the skill.",
  },

  // ── Multi-Language Insecure Deserialization (DS1–DS4) ──
  {
    id: "DS1",
    analyzerId: "static_patterns_deserialization",
    category: "Insecure Deserialization",
    pattern: "PHP Object Injection (unserialize)",
    severity: "HIGH",
    confidence: 0.9,
    regex: /\bunserialize\s*\(\s*\$(?!this\b)[a-zA-Z0-9_]+/,
    skipProhibitionInDocs: true,
    explanation: "PHP `unserialize()` on untrusted input instantiates arbitrary objects and triggers POP-chain RCE.",
    remediation: "Use `json_decode()` or pass `['allowed_classes' => false]`.",
  },
  {
    id: "DS2",
    analyzerId: "static_patterns_deserialization",
    category: "Insecure Deserialization",
    pattern: "Ruby Marshal Object Deserialization",
    severity: "HIGH",
    confidence: 0.91,
    regex: /\bMarshal\.(load|restore)\s*\(/,
    skipProhibitionInDocs: true,
    explanation: "Ruby `Marshal.load` reconstructs arbitrary objects from binary data, enabling remote code execution.",
    remediation: "Use `JSON.parse` instead of `Marshal.load` for external data.",
  },
  {
    id: "DS3",
    analyzerId: "static_patterns_deserialization",
    category: "Insecure Deserialization",
    pattern: "Unsafe Ruby YAML / Psych / Oj Object Deserialization",
    severity: "HIGH",
    confidence: 0.89,
    regex: /\b(Psych\.unsafe_load|Oj\.load\s*\([^)]*:object)\b/,
    skipProhibitionInDocs: true,
    explanation: "Instantiates arbitrary Ruby classes during YAML/JSON parsing.",
    remediation: "Use `YAML.safe_load` / `Psych.safe_load`.",
  },
  {
    id: "DS4",
    analyzerId: "static_patterns_deserialization",
    category: "Insecure Deserialization",
    pattern: "Unsafe JavaScript Function Deserialization",
    severity: "CRITICAL",
    confidence: 0.94,
    regex: /(\bnode-serialize\b|_$\$ND_FUNC\$\$_|\bserialize-to-js\b.*\.deserialize|\bfuncster\b)/,
    skipProhibitionInDocs: true,
    explanation: "JavaScript `node-serialize` / `_$$ND_FUNC$$_` evaluates embedded IIFE functions during deserialization, causing instant RCE.",
    remediation: "Use standard `JSON.parse()` instead of executable JS deserializers.",
  },

  // ── Server-Side Request Forgery (SSRF1–SSRF3) ──
  {
    id: "SSRF1",
    analyzerId: "static_patterns_ssrf",
    category: "Server-Side Request Forgery",
    pattern: "Cloud Instance Metadata Endpoint Access",
    severity: "CRITICAL",
    confidence: 0.95,
    regex: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200\/latest\/meta-data/,
    skipProhibitionInDocs: true,
    explanation: "Targets cloud instance metadata services (AWS IMDS / GCP Metadata) used to steal temporary IAM credentials.",
    remediation: "Remove all requests targeting link-local cloud metadata endpoints.",
  },
  {
    id: "SSRF2",
    analyzerId: "static_patterns_ssrf",
    category: "Server-Side Request Forgery",
    pattern: "Internal Loopback / RFC1918 Service Pivot",
    severity: "MEDIUM",
    confidence: 0.75,
    fileTypes: ["python", "typescript", "javascript", "shell"],
    regex: /\b(requests\.(get|post)|fetch|axios\.(get|post)|curl)\s*\(?['"`]https?:\/\/(127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+):/,
    explanation: "Skill script probes local loopback or private RFC1918 ports on the host network.",
    remediation: "Avoid probing unapproved internal host services from skill scripts.",
  },
  {
    id: "SSRF3",
    analyzerId: "static_patterns_ssrf",
    category: "Server-Side Request Forgery",
    pattern: "Unvalidated Dynamic Request Host Construction",
    severity: "MEDIUM",
    confidence: 0.78,
    fileTypes: ["python", "typescript", "javascript"],
    regex: /(requests\.(get|post)\s*\(\s*f['"]https?:\/\/\{|fetch\s*\(\s*`https?:\/\/\$\{(?!API_BASE|BASE_URL))/,
    explanation: "Constructs target request hostnames dynamically from interpolated variables without allowlist validation.",
    remediation: "Validate target URLs against an explicit hostname allowlist and block private/metadata IP ranges.",
  },
];

// Deprecated / abandoned or sabotaged supply-chain packages (SC5)
const ABANDONED_OR_SABOTAGED_PACKAGES = new Map<string, string>([
  ["pycrypto", "Unmaintained since 2013 with known CVEs; use 'pycryptodome' or 'cryptography'."],
  ["oauth2", "Abandoned Python OAuth library lacking modern TLS/signature checks."],
  ["nose", "Unmaintained test runner incompatible with modern Python security fixes; use 'pytest'."],
  ["request", "Deprecated npm package; use native 'fetch' or 'undici'."],
  ["event-stream", "Historically compromised npm package (flatmap-stream backdoor)."],
  ["node-ipc", "Historically sabotaged package (peacenotwar protestware)."],
]);

// Popular packages for SC6 Damerau-Levenshtein typosquatting detection
const POPULAR_PYPI = [
  "requests", "urllib3", "pydantic", "fastapi", "openai", "anthropic",
  "langchain", "numpy", "pandas", "boto3", "cryptography", "pyyaml", "httpx", "rich", "flask", "django",
];
const POPULAR_NPM = [
  "express", "react", "lodash", "axios", "chalk", "commander", "typescript",
  "openai", "zod", "dotenv", "ws", "next", "vite", "hono",
];

function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i]![0] = i;
  for (let j = 0; j <= n; j++) dp[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let val = Math.min(dp[i - 1]![j]! + 1, dp[i]![j - 1]! + 1, dp[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        val = Math.min(val, dp[i - 2]![j - 2]! + 1);
      }
      dp[i]![j] = val;
    }
  }
  return dp[m]![n]!;
}

function checkTyposquat(pkgName: string, popularList: string[]): string | null {
  const clean = pkgName.toLowerCase().trim();
  if (clean.length < 5 || popularList.includes(clean)) return null;
  for (const target of popularList) {
    if (Math.abs(clean.length - target.length) <= 1 && damerauLevenshtein(clean, target) === 1) {
      return target;
    }
  }
  return null;
}

export function getStaticRuleIds(): string[] {
  return Array.from(new Set([...STATIC_RULES.map((r) => r.id), "P2", "P9", "SC1", "SC5", "SC6", "SC8", "SC9", "TR1", "TR2", "TR3"]));
}

export function runStaticRulesAnalyzer(
  bundle: IngestedBundle,
  deobfuscationByFile: Map<string, FileDeobfuscationResult>,
): { findings: Finding[]; statuses: AnalyzerStatusRecord[] } {
  const start = performance.now();
  const findings: Finding[] = [];
  const analyzerBuckets = new Map<string, { category: string; count: number }>();

  for (const rule of STATIC_RULES) {
    if (!analyzerBuckets.has(rule.analyzerId)) {
      analyzerBuckets.set(rule.analyzerId, { category: rule.category, count: 0 });
    }
  }

  for (const comp of bundle.components) {
    const content = bundle.rawFiles.get(comp.path);
    if (content === undefined) continue;
    const lines = content.split(/\r?\n/);

    // 1. Line-by-line regex rules
    for (const rule of STATIC_RULES) {
      if (rule.fileTypes && !rule.fileTypes.includes(comp.type)) continue;

      lines.forEach((line, idx) => {
        const match = rule.regex.exec(line);
        if (!match) return;

        if (rule.skipProhibitionInDocs && comp.type === "markdown" && isProhibitionContext(line)) {
          return;
        }

        const f = createFinding({
          id: rule.id,
          category: rule.category,
          pattern: rule.pattern,
          severity: rule.severity,
          confidence: rule.confidence,
          file: comp.path,
          startLine: idx + 1,
          startColumn: match.index + 1,
          endColumn: match.index + match[0].length + 1,
          finding: match[0],
          explanation: rule.explanation,
          remediation: rule.remediation,
          fileContent: content,
        });
        findings.push(f);
        analyzerBuckets.get(rule.analyzerId)!.count++;
      });
    }

    // 2. Scan decoded obfuscated payloads (Base64 / Hex / Unicode Tag / HTML Comments)
    const deobf = deobfuscationByFile.get(comp.path);
    if (deobf) {
      for (const ev of deobf.events) {
        if (ev.kind === "unicode_tag" || ev.kind === "bidi_override") {
          findings.push(
            createFinding({
              id: "P2",
              category: "Prompt Injection",
              pattern: "Hidden Instructions (Invisible Unicode)",
              severity: "HIGH",
              confidence: 0.94,
              file: comp.path,
              startLine: ev.line,
              finding: ev.decoded_preview ?? ev.summary,
              explanation: `${ev.summary}. Attackers use invisible codepoints to smuggle directives past human code review.`,
              remediation: "Strip all invisible Unicode tag and bidirectional override characters from the file.",
              fileContent: content,
              evidence: { obfuscation_kind: ev.kind, decoded_preview: ev.decoded_preview },
            }),
          );
          analyzerBuckets.get("static_patterns_prompt_injection")!.count++;
        } else if (ev.kind === "whitespace_padding") {
          findings.push(
            createFinding({
              id: "P9",
              category: "Prompt Injection",
              pattern: "Whitespace Padding Concealment",
              severity: "MEDIUM",
              confidence: 0.82,
              file: comp.path,
              startLine: ev.line,
              finding: ev.decoded_preview ?? "Off-screen padded content",
              explanation: "Large horizontal whitespace padding pushes text beyond normal editor viewports to hide instructions.",
              remediation: "Remove excessive horizontal padding and place all instructions visibly.",
              fileContent: content,
            }),
          );
          analyzerBuckets.get("static_patterns_prompt_injection")!.count++;
        }
      }

      for (const payload of deobf.decodedPayloads) {
        for (const rule of STATIC_RULES) {
          if (!["P1", "P3", "P4", "P5", "AR1", "AR3", "SC2", "E2", "E3"].includes(rule.id)) continue;
          const m = rule.regex.exec(payload.decoded);
          if (m) {
            findings.push(
              createFinding({
                id: payload.encoding === "html_comment" ? "P2" : rule.id,
                category: rule.category,
                pattern: `${rule.pattern} (Hidden in ${payload.encoding})`,
                severity: rule.severity === "MEDIUM" ? "HIGH" : rule.severity,
                confidence: 0.95,
                file: comp.path,
                startLine: payload.line,
                finding: `[${payload.encoding}] ${m[0]}`,
                explanation: `Decoded ${payload.encoding} block revealed hidden malicious pattern: ${rule.explanation}`,
                remediation: rule.remediation,
                fileContent: content,
                evidence: { encoding: payload.encoding, decoded: payload.decoded.slice(0, 200) },
              }),
            );
            analyzerBuckets.get(rule.analyzerId)!.count++;
          }
        }
      }
    }

    // 3. Supply-chain manifest checks: SC1 (Unpinned), SC5 (Abandoned), SC6 (Typosquatting)
    if (comp.path.endsWith("requirements.txt")) {
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) return;
        const pkgMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*(.*)$/);
        if (!pkgMatch) return;
        const pkg = pkgMatch[1]!;
        const spec = pkgMatch[2]!.trim();

        const abandonedNote = ABANDONED_OR_SABOTAGED_PACKAGES.get(pkg.toLowerCase());
        if (abandonedNote) {
          findings.push(
            createFinding({
              id: "SC5",
              category: "Supply Chain",
              pattern: "Abandoned / Deprecated Dependency",
              severity: "MEDIUM",
              confidence: 0.86,
              file: comp.path,
              startLine: idx + 1,
              finding: pkg,
              explanation: abandonedNote,
              remediation: "Replace the unmaintained dependency with an actively supported package.",
              fileContent: content,
            }),
          );
          analyzerBuckets.get("static_patterns_supply_chain")!.count++;
        }

        const typoTarget = checkTyposquat(pkg, POPULAR_PYPI);
        if (typoTarget) {
          findings.push(
            createFinding({
              id: "SC6",
              category: "Supply Chain",
              pattern: "Suspected Typosquatted Package",
              severity: "HIGH",
              confidence: 0.89,
              file: comp.path,
              startLine: idx + 1,
              finding: `${pkg} (looks like '${typoTarget}')`,
              explanation: `Package '${pkg}' is 1 edit away from popular PyPI package '${typoTarget}', a primary indicator of typosquatting malware.`,
              remediation: `Verify the package spelling ('${typoTarget}') before installing dependencies.`,
              fileContent: content,
            }),
          );
          analyzerBuckets.get("static_patterns_supply_chain")!.count++;
        } else if (!spec || (!spec.includes("==") && !spec.includes(">=") && !spec.includes("~="))) {
          findings.push(
            createFinding({
              id: "SC1",
              category: "Supply Chain",
              pattern: "Unpinned Dependency Version",
              severity: "LOW",
              confidence: 0.75,
              file: comp.path,
              startLine: idx + 1,
              finding: trimmed,
              explanation: `Dependency '${pkg}' has no version constraint, allowing silent upstream supply-chain drift.`,
              remediation: "Pin exact dependency versions (e.g., `package==1.2.3`) or include a lockfile.",
              fileContent: content,
            }),
          );
          analyzerBuckets.get("static_patterns_supply_chain")!.count++;
        }
      });
    }

    if (comp.path.endsWith("package.json")) {
      try {
        const pkgJson = JSON.parse(content) as Record<string, unknown>;
        const sections = ["dependencies", "devDependencies", "optionalDependencies"] as const;
        for (const sec of sections) {
          const deps = pkgJson[sec];
          if (!deps || typeof deps !== "object") continue;
          for (const [depName, ver] of Object.entries(deps as Record<string, unknown>)) {
            const lineIdx = lines.findIndex((l) => l.includes(`"${depName}"`));
            const lineNo = lineIdx >= 0 ? lineIdx + 1 : 1;

            const abandonedNote = ABANDONED_OR_SABOTAGED_PACKAGES.get(depName.toLowerCase());
            if (abandonedNote) {
              findings.push(
                createFinding({
                  id: "SC5",
                  category: "Supply Chain",
                  pattern: "Abandoned / Compromised npm Package",
                  severity: "MEDIUM",
                  confidence: 0.88,
                  file: comp.path,
                  startLine: lineNo,
                  finding: depName,
                  explanation: abandonedNote,
                  remediation: "Migrate away from deprecated or historically compromised npm packages.",
                  fileContent: content,
                }),
              );
              analyzerBuckets.get("static_patterns_supply_chain")!.count++;
            }

            const typoTarget = checkTyposquat(depName, POPULAR_NPM);
            if (typoTarget) {
              findings.push(
                createFinding({
                  id: "SC6",
                  category: "Supply Chain",
                  pattern: "Suspected Typosquatted npm Package",
                  severity: "HIGH",
                  confidence: 0.89,
                  file: comp.path,
                  startLine: lineNo,
                  finding: `${depName} (looks like '${typoTarget}')`,
                  explanation: `Package '${depName}' is 1 edit away from popular npm package '${typoTarget}'.`,
                  remediation: `Verify whether '${typoTarget}' was intended.`,
                  fileContent: content,
                }),
              );
              analyzerBuckets.get("static_patterns_supply_chain")!.count++;
            } else if (ver === "*" || ver === "latest") {
              findings.push(
                createFinding({
                  id: "SC1",
                  category: "Supply Chain",
                  pattern: "Wildcard Dependency Version",
                  severity: "LOW",
                  confidence: 0.8,
                  file: comp.path,
                  startLine: lineNo,
                  finding: `"${depName}": "${String(ver)}"`,
                  explanation: `Dependency '${depName}' uses '${String(ver)}', pulling arbitrary future versions.`,
                  remediation: "Pin a concrete semver version and commit a lockfile.",
                  fileContent: content,
                }),
              );
              analyzerBuckets.get("static_patterns_supply_chain")!.count++;
            }
          }
        }
      } catch {
        // Invalid JSON handled safely
      }
    }
  }

  // 4. Bundle-level artifact integrity checks (SC8 bytecode & SC9 concealed binaries)
  for (const pyc of bundle.shippedBytecodeFiles) {
    findings.push({
      id: "SC8",
      finding_id: `finding-sc8-${pyc}`,
      category: "Supply Chain",
      pattern: "Shipped Python Bytecode (.pyc)",
      severity: "HIGH",
      confidence: 0.92,
      location: { file: pyc, start_line: 1, end_line: 1 },
      finding: pyc,
      explanation: "Pre-compiled Python bytecode can conceal malicious payloads that differ from readable .py source files.",
      remediation: "Delete `__pycache__/` and `.pyc` files; distribute human-auditable source code only.",
      code_snippet: pyc,
      surface: "code",
      tags: ["Supply Chain", "Artifact Integrity"],
      evidence: { artifact: pyc },
      match_fingerprint: `sc8:${pyc}`,
      occurrences: [{ file: pyc, start_line: 1, end_line: 1 }],
    });
    analyzerBuckets.get("static_patterns_supply_chain")!.count++;
  }

  for (const bin of bundle.concealedExecutables) {
    findings.push({
      id: "SC9",
      finding_id: `finding-sc9-${bin}`,
      category: "Supply Chain",
      pattern: "Bundled Native / Executable Binary",
      severity: "HIGH",
      confidence: 0.9,
      location: { file: bin, start_line: 1, end_line: 1 },
      finding: bin,
      explanation: "Bundled native binary cannot be verified via source inspection and may contain hidden trojans.",
      remediation: "Remove precompiled binaries from the skill bundle and use transparent scripts or verified system tools.",
      code_snippet: bin,
      surface: "code",
      tags: ["Supply Chain", "Artifact Integrity"],
      evidence: { artifact: bin },
      match_fingerprint: `sc9:${bin}`,
      occurrences: [{ file: bin, start_line: 1, end_line: 1 }],
    });
    analyzerBuckets.get("static_patterns_supply_chain")!.count++;
  }

  // 5. Trigger Abuse (TR1–TR3) on frontmatter triggers
  if (bundle.frontmatter?.triggers && bundle.manifestPath) {
    const manifestText = bundle.rawFiles.get(bundle.manifestPath) ?? "";
    const triggerList = Array.isArray(bundle.frontmatter.triggers)
      ? bundle.frontmatter.triggers.map(String)
      : String(bundle.frontmatter.triggers).split(",").map((s) => s.trim());

    const GENERIC_WORDS = new Set(["*", "all", "help", "run", "code", "fix", "test", "the", "a", "file"]);
    const SHADOW_COMMANDS = new Set(["/help", "/clear", "/compact", "/login", "/logout", "/config", "/init", "/plan"]);

    if (triggerList.length >= 12) {
      findings.push(
        createFinding({
          id: "TR3",
          category: "Trigger Abuse",
          pattern: "Keyword-Baiting Trigger Stuffing",
          severity: "MEDIUM",
          confidence: 0.8,
          file: bundle.manifestPath,
          startLine: 1,
          finding: `${triggerList.length} triggers declared`,
          explanation: "Declares an unusually large list of generic triggers designed to maximize activation frequency across unrelated tasks.",
          remediation: "Keep triggers concise (3–6 specific phrases) aligned to the skill's exact domain.",
          fileContent: manifestText,
        }),
      );
    }

    for (const trig of triggerList) {
      const lower = trig.toLowerCase().trim();
      if (!lower) continue;
      if (SHADOW_COMMANDS.has(lower)) {
        findings.push(
          createFinding({
            id: "TR2",
            category: "Trigger Abuse",
            pattern: "Built-in Slash Command Shadowing",
            severity: "HIGH",
            confidence: 0.9,
            file: bundle.manifestPath,
            startLine: 1,
            finding: `trigger: ${trig}`,
            explanation: `Skill registers '${trig}', shadowing a built-in host CLI slash command to hijack user workflows.`,
            remediation: "Choose a distinct, domain-specific trigger name that does not collide with built-in commands.",
            fileContent: manifestText,
          }),
        );
      } else if (GENERIC_WORDS.has(lower) || lower.length <= 1) {
        findings.push(
          createFinding({
            id: "TR1",
            category: "Trigger Abuse",
            pattern: "Overly Broad Activation Trigger",
            severity: "MEDIUM",
            confidence: 0.82,
            file: bundle.manifestPath,
            startLine: 1,
            finding: `trigger: ${trig}`,
            explanation: `Trigger '${trig}' matches everyday words or wildcards, forcing the skill active on unrelated prompts.`,
            remediation: "Use specific multi-word or domain-scoped triggers.",
            fileContent: manifestText,
          }),
        );
      }
    }
  }

  const elapsed = Math.round((performance.now() - start) * 100) / 100;
  const perAnalyzerMs = Math.max(0.1, Math.round((elapsed / analyzerBuckets.size) * 100) / 100);
  const statuses: AnalyzerStatusRecord[] = Array.from(analyzerBuckets.entries()).map(([id, info]) => ({
    analyzer_id: id,
    category: info.category,
    status: "completed",
    planned_work: bundle.rawFiles.size,
    completed: bundle.rawFiles.size,
    findings_count: info.count,
    duration_ms: perAnalyzerMs,
  }));

  return { findings, statuses };
}
