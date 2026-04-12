import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-001',
  title: 'Unsafe innerHTML Assignment',
  description:
    'Direct innerHTML assignment can lead to XSS if the value contains unsanitized user input.',
  severity: 'high',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Use textContent or innerText for plain text. If HTML is required, sanitize with DOMPurify or a similar library.',
};

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    AssignmentExpression(path) {
      const { left } = path.node;
      if (
        left.type === 'MemberExpression' &&
        left.property.type === 'Identifier' &&
        left.property.name === 'innerHTML'
      ) {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },
  });

  return hits;
}
