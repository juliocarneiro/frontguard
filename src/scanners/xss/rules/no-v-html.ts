import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-005',
  title: 'Vue v-html Directive Usage',
  description:
    'The v-html directive renders raw HTML and can lead to XSS if bound to unsanitized user input.',
  severity: 'high',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Use text interpolation {{ }} instead of v-html. If raw HTML is required, sanitize it with DOMPurify before binding.',
};

const V_HTML_PATTERN = /v-html\s*=/g;

export function check(file: FileContent): RuleHit[] {
  const hits: RuleHit[] = [];

  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i];
    V_HTML_PATTERN.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = V_HTML_PATTERN.exec(line)) !== null) {
      hits.push({ line: i + 1, column: match.index + 1 });
    }
  }

  return hits;
}
