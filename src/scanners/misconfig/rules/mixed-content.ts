import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-CFG-002',
  title: 'Mixed Content (HTTP in HTTPS Context)',
  description:
    'Loading resources over HTTP on an HTTPS page creates mixed content, allowing man-in-the-middle attacks on those resources.',
  severity: 'medium',
  category: 'misconfig',
  cwe: 'CWE-311',
  remediation:
    'Use HTTPS URLs for all external resources, or use protocol-relative URLs (//) when appropriate.',
};

const ATTR_HTTP_RE = /(?:src|href|action)\s*=\s*['"]http:\/\//i;
const FETCH_HTTP_RE = /fetch\s*\(\s*['"`]http:\/\//;

const SKIP_RE = /http:\/\/localhost|http:\/\/127\.0\.0\.1|http:\/\/0\.0\.0\.0|http:\/\/\[::1\]/;

export function check(file: FileContent): RuleHit[] {
  const hits: RuleHit[] = [];

  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i];
    const lineNum = i + 1;

    if (SKIP_RE.test(line)) continue;

    let match: RegExpExecArray | null;

    ATTR_HTTP_RE.lastIndex = 0;
    match = ATTR_HTTP_RE.exec(line);
    if (match) {
      hits.push({ line: lineNum, column: match.index + 1 });
      continue;
    }

    FETCH_HTTP_RE.lastIndex = 0;
    match = FETCH_HTTP_RE.exec(line);
    if (match) {
      hits.push({ line: lineNum, column: match.index + 1 });
    }
  }

  return hits;
}
