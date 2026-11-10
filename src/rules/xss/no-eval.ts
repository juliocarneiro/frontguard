import { defineRule, locOf } from '../../core/rule.ts';
import { calleeName, isStringLike } from '../ast-utils.ts';
import { XSS } from './meta.ts';

const TIMERS = new Set(['setTimeout', 'setInterval', 'setImmediate', 'execScript']);

export const noEval = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-002',
    name: 'no-eval',
    title: 'Dynamic code execution',
    description:
      'eval(), new Function() and string arguments to setTimeout/setInterval compile strings as code, turning any injected value into code execution.',
    severity: 'critical',
    cwe: 'CWE-95',
    remediation:
      'Remove eval and new Function. Parse data with JSON.parse and pass functions, not strings, to timers.',
  },
  create: (context) => ({
    CallExpression({ node }) {
      const name = calleeName(node.callee);
      if (!name) return;
      const isEval = name === 'eval' || name === 'Function';
      const isStringTimer = TIMERS.has(name) && isStringLike(node.arguments[0]);
      if (!isEval && !isStringTimer) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: `${name}()` });
    },
    NewExpression({ node }) {
      if (calleeName(node.callee) !== 'Function') return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: 'new Function()' });
    },
  }),
});
