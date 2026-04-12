import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-AUTH-002',
  title: 'Token Passed in URL',
  description:
    'Passing authentication tokens or API keys in URL query parameters exposes them in browser history, server logs, and referrer headers.',
  severity: 'high',
  category: 'auth-patterns',
  cwe: 'CWE-598',
  owasp: 'A02:2021',
  remediation:
    'Send tokens in the Authorization header or request body instead of URL query parameters.',
};

const URL_TOKEN_RE = /[?&](token|api_key|apikey|api-key|auth|jwt|access_token|secret|key|password)=/i;

function checkStringValue(value: string): boolean {
  return URL_TOKEN_RE.test(value);
}

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    StringLiteral(path) {
      if (checkStringValue(path.node.value)) {
        const loc = path.node.loc;
        if (loc) {
          hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        }
      }
    },

    TemplateLiteral(path) {
      for (const quasi of path.node.quasis) {
        if (checkStringValue(quasi.value.raw)) {
          const loc = path.node.loc;
          if (loc) {
            hits.push({ line: loc.start.line, column: loc.start.column + 1 });
          }
          break;
        }
      }
    },
  });

  return hits;
}
