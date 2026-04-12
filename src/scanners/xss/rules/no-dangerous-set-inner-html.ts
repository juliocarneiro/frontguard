import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-004',
  title: 'React dangerouslySetInnerHTML Usage',
  description:
    'dangerouslySetInnerHTML bypasses React DOM escaping and can introduce XSS vulnerabilities if the HTML is not properly sanitized.',
  severity: 'high',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Avoid dangerouslySetInnerHTML. If raw HTML rendering is unavoidable, sanitize with DOMPurify before passing to __html.',
};

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    JSXAttribute(path) {
      if (
        path.node.name.type === 'JSXIdentifier' &&
        path.node.name.name === 'dangerouslySetInnerHTML'
      ) {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },
  });

  return hits;
}
