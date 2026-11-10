import { defineRule, locOf } from '../../core/rule.ts';
import { isStaticString, propertyName } from '../ast-utils.ts';
import { XSS } from './meta.ts';

const SINKS = new Set(['innerHTML', 'outerHTML']);

export const noInnerHtml = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-001',
    name: 'no-inner-html',
    title: 'Dynamic innerHTML/outerHTML assignment',
    description:
      'Assigning a dynamic value to innerHTML or outerHTML parses it as HTML, which executes injected markup and scripts.',
    severity: 'high',
    remediation:
      'Use textContent for text. If you must render HTML, sanitize it first (e.g. DOMPurify.sanitize) or use the Trusted Types API.',
  },
  create: (context) => ({
    AssignmentExpression({ node }) {
      const name = propertyName(node.left);
      if (!name || !SINKS.has(name) || isStaticString(node.right)) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: name });
    },
  }),
});
