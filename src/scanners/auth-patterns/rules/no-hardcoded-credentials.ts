import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-AUTH-003',
  title: 'Hardcoded Credentials',
  description:
    'Hardcoded passwords, secrets, or credentials in source code can be easily extracted and lead to unauthorized access.',
  severity: 'critical',
  category: 'auth-patterns',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  remediation:
    'Remove hardcoded credentials and use environment variables or a secrets manager instead.',
};

const CREDENTIAL_NAMES = new Set([
  'password',
  'passwd',
  'pwd',
  'secret',
  'secretkey',
  'secret_key',
  'secretKey',
  'apiSecret',
  'api_secret',
  'privateKey',
  'private_key',
]);

function isCredentialName(name: string): boolean {
  return CREDENTIAL_NAMES.has(name);
}

function isNonEmptyString(node: { type: string; value?: string }): boolean {
  if (node.type === 'StringLiteral' && node.value) {
    return node.value.trim().length > 0;
  }
  return false;
}

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (
        id.type === 'Identifier' &&
        isCredentialName(id.name) &&
        init &&
        isNonEmptyString(init as { type: string; value?: string })
      ) {
        const loc = path.node.loc;
        if (loc) {
          hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        }
      }
    },

    AssignmentExpression(path) {
      const { left, right } = path.node;

      if (
        left.type === 'Identifier' &&
        isCredentialName(left.name) &&
        isNonEmptyString(right as { type: string; value?: string })
      ) {
        const loc = path.node.loc;
        if (loc) {
          hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        }
        return;
      }

      if (
        left.type === 'MemberExpression' &&
        left.property.type === 'Identifier' &&
        isCredentialName(left.property.name) &&
        isNonEmptyString(right as { type: string; value?: string })
      ) {
        const loc = path.node.loc;
        if (loc) {
          hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        }
      }
    },

    ObjectProperty(path) {
      const { key, value } = path.node;
      const name =
        key.type === 'Identifier'
          ? key.name
          : key.type === 'StringLiteral'
            ? key.value
            : null;

      if (
        name &&
        isCredentialName(name) &&
        isNonEmptyString(value as { type: string; value?: string })
      ) {
        const loc = path.node.loc;
        if (loc) {
          hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        }
      }
    },
  });

  return hits;
}
