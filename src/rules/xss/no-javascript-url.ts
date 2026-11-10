import type { Node } from '@babel/types';
import { defineRule, locOf } from '../../core/rule.ts';
import { XSS } from './meta.ts';

// Code follows the colon directly in real payloads (`javascript:alert(1)`); prose such as
// "javascript: URLs are dangerous" is not a URL.
const JS_URL_RE = /^\s*javascript:(?!\s)/i;
const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formAction', 'formaction', 'xlinkHref']);

export const noJavascriptUrl = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-008',
    name: 'no-javascript-url',
    title: 'javascript: URL',
    description:
      'javascript: URLs run code when followed. They are a common XSS vector in href, src and form actions.',
    severity: 'medium',
    remediation:
      'Use event handlers for behaviour, and validate user-supplied URLs against an allowlist of schemes (https:, mailto:).',
  },
  create(context) {
    const reportNode = (node: Node) => {
      const loc = locOf(node);
      if (loc) context.report(loc);
    };
    return {
      StringLiteral({ node, parent }) {
        if (parent.type === 'JSXAttribute') return;
        if (node.value.length < 300 && JS_URL_RE.test(node.value)) reportNode(node);
      },
      TemplateLiteral({ node }) {
        if (JS_URL_RE.test(node.quasis[0]?.value.cooked ?? '')) reportNode(node);
      },
      JSXAttribute({ node }) {
        if (node.name.type !== 'JSXIdentifier' || !URL_ATTRIBUTES.has(node.name.name)) return;
        if (node.value?.type === 'StringLiteral' && JS_URL_RE.test(node.value.value)) {
          reportNode(node);
        }
      },
    };
  },
});
