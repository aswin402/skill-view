import { readFile } from "node:fs/promises";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import pkgJson from "../package.json";
import type { BaselineDocument, Finding, SuppressedFinding } from "./types";
import { globMatch } from "./utils";

export const SKILLSPECTATOR_VERSION = pkgJson.version;

export function parseBaselineYamlString(raw: string): BaselineDocument {
  const parsed = (parseYaml(raw) ?? {}) as Partial<BaselineDocument>;
  return {
    version: parsed.version ?? 2,
    scanner_version: parsed.scanner_version ?? SKILLSPECTATOR_VERSION,
    rules: Array.isArray(parsed.rules) ? parsed.rules : [],
    fingerprints: Array.isArray(parsed.fingerprints) ? parsed.fingerprints : [],
  };
}

export async function loadBaselineFile(filePath: string): Promise<BaselineDocument> {
  const raw = await readFile(filePath, "utf-8");
  return parseBaselineYamlString(raw);
}

export function buildBaselineFromFindings(
  findings: Finding[],
  reason = "Accepted finding (auto-generated baseline)",
): BaselineDocument {
  return {
    version: 2,
    scanner_version: SKILLSPECTATOR_VERSION,
    rules: [],
    fingerprints: findings.map((f) => ({
      hash: `sha256:${f.match_fingerprint}`,
      rule_id: f.id,
      file: f.location.file,
      reason,
    })),
  };
}

export function serializeBaselineYaml(doc: BaselineDocument): string {
  const header = [
    "# SkillSpectator baseline — findings listed here are suppressed on future scans.",
    "# Edit 'reason' fields and add glob 'rules' as needed.",
    "",
  ].join("\n");
  return `${header}${stringifyYaml(doc)}`;
}

export function applyBaselineSuppression(
  findings: Finding[],
  baseline?: BaselineDocument,
): { active: Finding[]; suppressed: SuppressedFinding[] } {
  if (!baseline) {
    return { active: findings, suppressed: [] };
  }

  const fpMap = new Map<string, string>();
  for (const fp of baseline.fingerprints ?? []) {
    const normalizedHash = fp.hash.replace(/^sha256:/, "");
    fpMap.set(normalizedHash, fp.reason || "Suppressed by fingerprint baseline");
  }

  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];

  for (const f of findings) {
    const fpReason = fpMap.get(f.match_fingerprint);
    if (fpReason !== undefined) {
      suppressed.push({ ...f, suppression_reason: fpReason });
      continue;
    }

    const matchedRule = (baseline.rules ?? []).find((r) => {
      const idMatches = !r.rule_id || r.rule_id === "*" || r.rule_id === f.id;
      const fileMatches = !r.file_glob || globMatch(r.file_glob, f.location.file);
      return idMatches && fileMatches;
    });

    if (matchedRule) {
      suppressed.push({
        ...f,
        suppression_reason: matchedRule.reason || "Suppressed by baseline rule",
      });
      continue;
    }

    active.push(f);
  }

  return { active, suppressed };
}
