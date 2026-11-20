import type { DeobfuscationEvent } from "./types";

// Common Cyrillic/Greek/Fullwidth confusable characters mapped to ASCII lookalikes
const CONFUSABLES_MAP: Record<string, { ascii: string; script: string; code: string }> = {
  "\u0430": { ascii: "a", script: "Cyrillic Small Letter A", code: "U+0430" },
  "\u0435": { ascii: "e", script: "Cyrillic Small Letter Ie", code: "U+0435" },
  "\u043E": { ascii: "o", script: "Cyrillic Small Letter O", code: "U+043E" },
  "\u0440": { ascii: "p", script: "Cyrillic Small Letter Er", code: "U+0440" },
  "\u0441": { ascii: "c", script: "Cyrillic Small Letter Es", code: "U+0441" },
  "\u0443": { ascii: "y", script: "Cyrillic Small Letter U", code: "U+0443" },
  "\u0445": { ascii: "x", script: "Cyrillic Small Letter Ha", code: "U+0445" },
  "\u0456": { ascii: "i", script: "Cyrillic Small Letter Byelorussian-Ukrainian I", code: "U+0456" },
  "\u0455": { ascii: "s", script: "Cyrillic Small Letter Dze", code: "U+0455" },
  "\u0458": { ascii: "j", script: "Cyrillic Small Letter Je", code: "U+0458" },
  "\u04CF": { ascii: "l", script: "Cyrillic Small Letter Palochka", code: "U+04CF" },
  "\u0410": { ascii: "A", script: "Cyrillic Capital Letter A", code: "U+0410" },
  "\u0412": { ascii: "B", script: "Cyrillic Capital Letter Ve", code: "U+0412" },
  "\u0415": { ascii: "E", script: "Cyrillic Capital Letter Ie", code: "U+0415" },
  "\u041A": { ascii: "K", script: "Cyrillic Capital Letter Ka", code: "U+041A" },
  "\u041C": { ascii: "M", script: "Cyrillic Capital Letter Em", code: "U+041C" },
  "\u041D": { ascii: "H", script: "Cyrillic Capital Letter En", code: "U+041D" },
  "\u041E": { ascii: "O", script: "Cyrillic Capital Letter O", code: "U+041E" },
  "\u0420": { ascii: "P", script: "Cyrillic Capital Letter Er", code: "U+0420" },
  "\u0421": { ascii: "C", script: "Cyrillic Capital Letter Es", code: "U+0421" },
  "\u0422": { ascii: "T", script: "Cyrillic Capital Letter Te", code: "U+0422" },
  "\u0425": { ascii: "X", script: "Cyrillic Capital Letter Ha", code: "U+0425" },
  "\u03B1": { ascii: "a", script: "Greek Small Letter Alpha", code: "U+03B1" },
  "\u03BF": { ascii: "o", script: "Greek Small Letter Omicron", code: "U+03BF" },
  "\u03C1": { ascii: "p", script: "Greek Small Letter Rho", code: "U+03C1" },
  "\u03BD": { ascii: "v", script: "Greek Small Letter Nu", code: "U+03BD" },
};

const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\u2060\u180E\uFEFF]/g;
const BIDI_OVERRIDE_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

export interface HomoglyphHit {
  char: string;
  index: number;
  ascii: string;
  script: string;
  code: string;
}

export function detectHomoglyphsInIdentifier(identifier: string): HomoglyphHit[] {
  const hasAscii = /[a-zA-Z0-9_]/.test(identifier);
  if (!hasAscii) return [];

  const hits: HomoglyphHit[] = [];
  for (let i = 0; i < identifier.length; i++) {
    const ch = identifier[i];
    if (!ch) continue;
    const match = CONFUSABLES_MAP[ch];
    if (match) {
      hits.push({
        char: ch,
        index: i,
        ...match,
      });
    }
  }
  return hits;
}

export interface FileDeobfuscationResult {
  events: DeobfuscationEvent[];
  decodedPayloads: Array<{
    line: number;
    encoding: "base64" | "hex" | "unicode_tag" | "html_comment";
    raw: string;
    decoded: string;
  }>;
}

function tryDecodeBase64Printable(candidate: string): string | null {
  if (candidate.length < 24 || candidate.length % 4 !== 0) return null;
  // Ignore URLs/paths with many slashes or hashes that happen to match base64 charset
  if (/^(https?|file|\/[a-zA-Z0-9_.-]+\/)/.test(candidate)) return null;
  // Ignore hex SHA256 hashes (only 0-9a-f)
  if (/^[0-9a-fA-F]{32,128}$/.test(candidate)) return null;

  try {
    const bytes = Buffer.from(candidate, "base64");
    if (bytes.length < 12) return null;
    const decoded = bytes.toString("utf-8");
    // Ensure high printable ASCII ratio so we don't flag random binary/hashes
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
        printable++;
      }
    }
    if (printable / decoded.length < 0.88) return null;
    if (!/[a-zA-Z]{3,}/.test(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

function decodeUnicodeTags(line: string): string | null {
  const chars: string[] = [];
  for (const cp of line) {
    const code = cp.codePointAt(0);
    if (code !== undefined && code >= 0xe0020 && code <= 0xe007e) {
      chars.push(String.fromCharCode(code - 0xe0000));
    }
  }
  return chars.length >= 3 ? chars.join("") : null;
}

export function analyzeFileObfuscation(filePath: string, content: string): FileDeobfuscationResult {
  const events: DeobfuscationEvent[] = [];
  const decodedPayloads: FileDeobfuscationResult["decodedPayloads"] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;

    // 1. Zero-width characters (ignore leading BOM on line 1 col 0)
    const cleanLine = idx === 0 && line.startsWith("\uFEFF") ? line.slice(1) : line;
    const zwMatches = cleanLine.match(ZERO_WIDTH_REGEX);
    if (zwMatches && zwMatches.length > 0) {
      events.push({
        file: filePath,
        line: lineNum,
        kind: "zero_width",
        summary: `${zwMatches.length} invisible zero-width character(s) detected`,
      });
    }

    // 2. Bidirectional Trojan-Source overrides
    const bidiMatches = line.match(BIDI_OVERRIDE_REGEX);
    if (bidiMatches && bidiMatches.length > 0) {
      events.push({
        file: filePath,
        line: lineNum,
        kind: "bidi_override",
        summary: `Bidirectional Unicode override (${bidiMatches.length}) capable of visually reordering code/instructions`,
      });
    }

    // 3. Invisible Unicode Tag characters (U+E0000..U+E007F)
    const tagDecoded = decodeUnicodeTags(line);
    if (tagDecoded) {
      events.push({
        file: filePath,
        line: lineNum,
        kind: "unicode_tag",
        summary: "Hidden Unicode Tag block smuggling invisible ASCII instructions",
        decoded_preview: tagDecoded.slice(0, 140),
      });
      decodedPayloads.push({
        line: lineNum,
        encoding: "unicode_tag",
        raw: "[Unicode Tag Sequence]",
        decoded: tagDecoded,
      });
    }

    // 4. Mixed-script homoglyphs inside word tokens
    const words = line.match(/[\p{L}\p{N}_-]{3,}/gu) ?? [];
    for (const word of words) {
      const hits = detectHomoglyphsInIdentifier(word);
      if (hits.length > 0) {
        const first = hits[0]!;
        events.push({
          file: filePath,
          line: lineNum,
          kind: "homoglyph",
          summary: `Mixed-script homoglyph in '${word}': ${first.code} (${first.script}) impersonating '${first.ascii}'`,
        });
        break;
      }
    }

    // 5. Whitespace padding hiding text far off-screen (>80 spaces followed by directives)
    const padMatch = line.match(/^(.*?[^\s])?\s{80,}(\S.+)$/);
    if (padMatch && padMatch[2]) {
      events.push({
        file: filePath,
        line: lineNum,
        kind: "whitespace_padding",
        summary: "Excessive horizontal whitespace padding hiding off-screen text",
        decoded_preview: padMatch[2].slice(0, 120),
      });
    }

    // 6. Base64-encoded text payloads
    const b64Candidates = line.match(/[A-Za-z0-9+/]{28,}={0,2}/g) ?? [];
    for (const cand of b64Candidates) {
      const decoded = tryDecodeBase64Printable(cand);
      if (decoded) {
        events.push({
          file: filePath,
          line: lineNum,
          kind: "base64_payload",
          summary: "Decoded printable Base64 text payload for deep inspection",
          decoded_preview: decoded.slice(0, 140),
        });
        decodedPayloads.push({
          line: lineNum,
          encoding: "base64",
          raw: cand.slice(0, 48),
          decoded,
        });
      }
    }

    // 7. Hex-escaped payloads (\x69\x67\x6e...)
    const hexEscapeMatch = line.match(/(?:\\x[0-9a-fA-F]{2}){8,}/g);
    if (hexEscapeMatch) {
      for (const seq of hexEscapeMatch) {
        const hexStr = seq.replace(/\\x/g, "");
        const decoded = Buffer.from(hexStr, "hex").toString("utf-8");
        if (/[a-zA-Z]{3,}/.test(decoded)) {
          events.push({
            file: filePath,
            line: lineNum,
            kind: "hex_payload",
            summary: "Decoded hex-escaped payload for deep inspection",
            decoded_preview: decoded.slice(0, 140),
          });
          decodedPayloads.push({
            line: lineNum,
            encoding: "hex",
            raw: seq.slice(0, 48),
            decoded,
          });
        }
      }
    }
  });

  // 8. Multi-line HTML comments in Markdown files
  if (filePath.endsWith(".md") || filePath.endsWith(".mdx") || filePath.endsWith(".html")) {
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let match: RegExpExecArray | null;
    while ((match = commentRegex.exec(content)) !== null) {
      const inner = (match[1] ?? "").trim();
      if (!inner || /^slide$/i.test(inner)) continue;
      const before = content.slice(0, match.index);
      const lineNum = before.split(/\r?\n/).length;
      events.push({
        file: filePath,
        line: lineNum,
        kind: "html_comment",
        summary: "HTML comment in instruction/markdown file inspected for hidden directives",
        decoded_preview: inner.slice(0, 140),
      });
      decodedPayloads.push({
        line: lineNum,
        encoding: "html_comment",
        raw: match[0].slice(0, 60),
        decoded: inner,
      });
    }
  }

  return { events, decodedPayloads };
}
