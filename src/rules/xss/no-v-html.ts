import { defineRule, matchLines } from '../../core/rule.ts';
import { XSS } from './meta.ts';

const V_HTML_RE = /(?:^|\s)v-html\s*=/g;

export const noVHtml = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-005',
    name: 'no-v-html',
    title: 'Vue v-html directive',
    description: 'v-html renders raw HTML and executes any markup injected into the bound value.',
    severity: 'high',
    remediation:
      'Use text interpolation ({{ }}). If raw HTML is required, sanitize it with DOMPurify before binding.',
  },
  create(context) {
    if (!/\.(vue|html?)$/i.test(context.filename)) return undefined;
    for (const { line, column, match } of matchLines(context.lines, V_HTML_RE)) {
      context.report({ line, column: column + match[0].indexOf('v-html') });
    }
    return undefined;
  },
});
