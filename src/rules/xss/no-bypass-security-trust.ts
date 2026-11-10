import { defineRule, locOf } from '../../core/rule.ts';
import { propertyName } from '../ast-utils.ts';
import { XSS } from './meta.ts';

export const noBypassSecurityTrust = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-006',
    name: 'no-bypass-security-trust',
    title: 'Angular sanitizer bypass',
    description:
      'DomSanitizer.bypassSecurityTrust* disables the built-in Angular XSS protection for that value.',
    severity: 'critical',
    remediation:
      'Let Angular sanitize bindings automatically. If you must trust a value, sanitize it with DOMPurify first and keep the bypass in one audited place.',
  },
  create: (context) => ({
    CallExpression({ node }) {
      const name = propertyName(node.callee);
      if (!name?.startsWith('bypassSecurityTrust')) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: name });
    },
  }),
});
