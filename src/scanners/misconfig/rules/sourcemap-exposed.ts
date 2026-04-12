import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-CFG-001',
  title: 'Source Map Exposed in Production',
  description:
    'Source maps expose original source code, making it easier for attackers to find vulnerabilities in your application.',
  severity: 'medium',
  category: 'misconfig',
  cwe: 'CWE-540',
  remediation:
    'Disable source maps in production builds. Set devtool to false or "hidden-source-map" in webpack, and sourceMap to false in build configs.',
};

const SOURCEMAP_URL_RE = /sourceMappingURL\s*=/;
const DEVTOOL_SOURCE_MAP_RE = /devtool\s*:\s*['"`](?:eval-)?source-map['"`]/;
const SOURCEMAP_TRUE_RE = /sourceMap\s*:\s*true/;

export function check(file: FileContent): RuleHit[] {
  const hits: RuleHit[] = [];

  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i];
    const lineNum = i + 1;

    if (SOURCEMAP_URL_RE.test(line)) {
      hits.push({ line: lineNum, column: line.search(SOURCEMAP_URL_RE) + 1 });
    } else if (DEVTOOL_SOURCE_MAP_RE.test(line)) {
      hits.push({ line: lineNum, column: line.search(DEVTOOL_SOURCE_MAP_RE) + 1 });
    } else if (SOURCEMAP_TRUE_RE.test(line)) {
      hits.push({ line: lineNum, column: line.search(SOURCEMAP_TRUE_RE) + 1 });
    }
  }

  return hits;
}
