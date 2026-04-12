import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-CFG-003',
  title: 'CDN Resource Without Integrity Check',
  description:
    'External script or stylesheet loaded from a CDN without a Subresource Integrity (SRI) attribute. If the CDN is compromised, malicious code could be injected.',
  severity: 'low',
  category: 'misconfig',
  cwe: 'CWE-353',
  remediation:
    'Add an integrity attribute with a valid hash and a crossorigin="anonymous" attribute to all external script and link tags.',
};

const CDN_TAG_RE = /<(?:script|link)\b[^>]*(?:src|href)\s*=\s*['"]https?:\/\/(?:cdn|unpkg|cdnjs|jsdelivr|ajax\.googleapis|stackpath|maxcdn|fastly|cloudflare)[^>]*/i;
const INTEGRITY_RE = /integrity\s*=/i;

export function check(file: FileContent): RuleHit[] {
  const hits: RuleHit[] = [];

  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i];
    const lineNum = i + 1;

    if (!CDN_TAG_RE.test(line)) continue;
    if (INTEGRITY_RE.test(line)) continue;

    const match = CDN_TAG_RE.exec(line);
    if (match) {
      hits.push({ line: lineNum, column: match.index + 1 });
    }
  }

  return hits;
}
