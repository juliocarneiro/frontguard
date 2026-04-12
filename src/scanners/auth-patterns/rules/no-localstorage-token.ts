import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-AUTH-001',
  title: 'Token Stored in Web Storage',
  description:
    'Storing authentication tokens in localStorage or sessionStorage exposes them to XSS attacks. Any script running on the page can read these values.',
  severity: 'high',
  category: 'auth-patterns',
  cwe: 'CWE-922',
  owasp: 'A02:2021',
  remediation:
    'Use httpOnly cookies for storing authentication tokens. If client-side access is needed, consider in-memory storage with short-lived tokens.',
};

const STORAGE_OBJECTS = new Set(['localStorage', 'sessionStorage']);
const SENSITIVE_KEY_RE = /\b(token|jwt|auth|session|access.?token|refresh.?token|id.?token)\b/i;

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if (
        callee.type !== 'MemberExpression' ||
        callee.object.type !== 'Identifier' ||
        !STORAGE_OBJECTS.has(callee.object.name) ||
        callee.property.type !== 'Identifier' ||
        callee.property.name !== 'setItem'
      ) {
        return;
      }

      if (args.length < 1) return;

      const keyArg = args[0];
      let keyValue: string | null = null;

      if (keyArg.type === 'StringLiteral') {
        keyValue = keyArg.value;
      } else if (
        keyArg.type === 'TemplateLiteral' &&
        keyArg.quasis.length === 1
      ) {
        keyValue = keyArg.quasis[0].value.raw;
      }

      if (keyValue && SENSITIVE_KEY_RE.test(keyValue)) {
        const loc = path.node.loc;
        if (loc) {
          hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        }
      }
    },
  });

  return hits;
}
