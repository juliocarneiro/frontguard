import { defineRule, matchLines } from '../../core/rule.ts';
import { XSS } from './meta.ts';

export const noSvelteHtml = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-009',
    name: 'no-svelte-html',
    title: 'Svelte {@html} tag',
    description: '{@html ...} inserts raw HTML without escaping and executes injected markup.',
    severity: 'high',
    remediation:
      'Render values with normal {expressions}. If raw HTML is required, sanitize it with DOMPurify first.',
  },
  create(context) {
    if (!context.filename.endsWith('.svelte')) return undefined;
    for (const { line, column } of matchLines(context.lines, /\{@html\s/g)) {
      context.report({ line, column });
    }
    return undefined;
  },
});
