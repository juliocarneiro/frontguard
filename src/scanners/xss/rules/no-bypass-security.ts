import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-006',
  title: 'Angular Security Bypass (bypassSecurityTrust*)',
  description:
    'Angular DomSanitizer bypass methods disable built-in XSS protection and should only be used with fully trusted content.',
  severity: 'critical',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Avoid bypassSecurityTrust* methods. Let Angular sanitize values automatically, or use a custom Pipe with DOMPurify for controlled sanitization.',
};

const BYPASS_METHODS = new Set([
  'bypassSecurityTrustHtml',
  'bypassSecurityTrustScript',
  'bypassSecurityTrustUrl',
  'bypassSecurityTrustResourceUrl',
  'bypassSecurityTrustStyle',
]);

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    CallExpression(path) {
      const { callee } = path.node;

      if (
        callee.type === 'MemberExpression' &&
        callee.property.type === 'Identifier' &&
        BYPASS_METHODS.has(callee.property.name)
      ) {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },
  });

  return hits;
}
