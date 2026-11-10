import { defineRule, locOf } from '../../core/rule.ts';
import { objectName, propertyName } from '../ast-utils.ts';
import { XSS } from './meta.ts';

export const noDocumentWrite = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-003',
    name: 'no-document-write',
    title: 'document.write() call',
    description:
      'document.write() and document.writeln() inject raw HTML into the page and are a classic XSS sink.',
    severity: 'high',
    remediation: 'Build DOM nodes with createElement/append or let your framework render them.',
  },
  create: (context) => ({
    CallExpression({ node }) {
      const method = propertyName(node.callee);
      if ((method !== 'write' && method !== 'writeln') || objectName(node.callee) !== 'document') {
        return;
      }
      const loc = locOf(node);
      if (loc) context.report(loc);
    },
  }),
});
