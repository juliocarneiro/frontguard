import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-008',
  title: 'Unsafe javascript: URL Scheme',
  description:
    'javascript: URLs execute code when navigated to and are a common XSS vector in href, src, and other URL attributes.',
  severity: 'medium',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Never use javascript: URLs. Use event handlers for interactivity and validate/sanitize all user-provided URLs against an allowlist of safe schemes (https:, mailto:).',
};

const JS_URL_PATTERN = /javascript\s*:/i;
const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formAction', 'formaction']);

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    StringLiteral(path) {
      const val = path.node.value.trim();
      if (/^javascript\s*:\S/i.test(val) && val.length < 200) {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },

    TemplateLiteral(path) {
      for (const quasis of path.node.quasis) {
        if (JS_URL_PATTERN.test(quasis.value.raw)) {
          const loc = path.node.loc;
          if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
          break;
        }
      }
    },

    JSXAttribute(path) {
      if (
        path.node.name.type === 'JSXIdentifier' &&
        URL_ATTRIBUTES.has(path.node.name.name) &&
        path.node.value?.type === 'StringLiteral' &&
        JS_URL_PATTERN.test(path.node.value.value)
      ) {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },
  });

  return hits;
}
