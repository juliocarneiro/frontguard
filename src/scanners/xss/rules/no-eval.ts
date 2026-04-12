import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';
import { parseFile, traverse } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-002',
  title: 'Use of eval() or Similar Dynamic Code Execution',
  description:
    'eval(), new Function(), and setTimeout/setInterval with string arguments execute arbitrary code and can lead to code injection.',
  severity: 'critical',
  category: 'xss',
  cwe: 'CWE-95',
  owasp: 'A03:2021 - Injection',
  remediation:
    'Avoid eval() and new Function(). Use JSON.parse() for data, and pass function references to setTimeout/setInterval instead of strings.',
};

const DANGEROUS_TIMER_FUNCTIONS = new Set(['setTimeout', 'setInterval']);

function isStringArg(node: { type: string }): boolean {
  return node.type === 'StringLiteral' || node.type === 'TemplateLiteral';
}

export function check(file: FileContent): RuleHit[] {
  const ast = parseFile(file.content);
  if (!ast) return [];

  const hits: RuleHit[] = [];

  traverse(ast, {
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      const loc = path.node.loc;
      if (!loc) return;

      if (callee.type === 'Identifier' && callee.name === 'eval') {
        hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        return;
      }

      if (
        callee.type === 'Identifier' &&
        DANGEROUS_TIMER_FUNCTIONS.has(callee.name) &&
        args.length > 0 &&
        isStringArg(args[0])
      ) {
        hits.push({ line: loc.start.line, column: loc.start.column + 1 });
        return;
      }

      if (
        callee.type === 'MemberExpression' &&
        callee.object.type === 'Identifier' &&
        callee.object.name === 'window' &&
        callee.property.type === 'Identifier' &&
        DANGEROUS_TIMER_FUNCTIONS.has(callee.property.name) &&
        args.length > 0 &&
        isStringArg(args[0])
      ) {
        hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },

    NewExpression(path) {
      const { callee } = path.node;
      if (callee.type === 'Identifier' && callee.name === 'Function') {
        const loc = path.node.loc;
        if (loc) hits.push({ line: loc.start.line, column: loc.start.column + 1 });
      }
    },
  });

  return hits;
}
