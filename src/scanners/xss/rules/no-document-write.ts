import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-003',
  title: 'Use of document.write() or document.writeln()',
  description:
    'document.write() and document.writeln() inject raw HTML into the page and are a common XSS vector.',
  severity: 'high',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Use DOM manipulation methods like createElement and appendChild, or use a framework rendering system.',
};

const DANGEROUS_METHODS = new Set(['write', 'writeln']);

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    CallExpression(path) {
      const { callee } = path.node;

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'document' &&
        callee.property.type === 'Identifier' &&
        DANGEROUS_METHODS.has(callee.property.name)
      ) {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },
  });

  return hits;
}
