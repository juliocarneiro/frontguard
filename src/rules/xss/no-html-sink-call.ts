import { defineRule, locOf } from '../../core/rule.ts';
import { isStaticString, propertyName } from '../ast-utils.ts';
import { XSS } from './meta.ts';

const SINKS = new Set(['insertAdjacentHTML', 'createContextualFragment', 'setHTMLUnsafe']);

export const noHtmlSinkCall = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-007',
    name: 'no-html-sink-call',
    title: 'Dynamic HTML passed to a parsing API',
    description:
      'insertAdjacentHTML, Range.createContextualFragment and setHTMLUnsafe parse their argument as HTML, executing injected markup.',
    severity: 'high',
    remediation:
      'Insert text with insertAdjacentText/textContent, or sanitize the HTML with DOMPurify (or Element.setHTML) first.',
  },
  create: (context) => ({
    CallExpression({ node }) {
      const name = propertyName(node.callee);
      if (!name || !SINKS.has(name)) return;
      const htmlArg = node.arguments[name === 'insertAdjacentHTML' ? 1 : 0];
      if (!htmlArg || isStaticString(htmlArg)) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: `${name}()` });
    },
  }),
});
