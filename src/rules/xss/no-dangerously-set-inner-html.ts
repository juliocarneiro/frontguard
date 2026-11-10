import { defineRule, locOf } from '../../core/rule.ts';
import { XSS } from './meta.ts';

const PROP = 'dangerouslySetInnerHTML';

export const noDangerouslySetInnerHtml = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-004',
    name: 'no-dangerously-set-inner-html',
    title: 'React dangerouslySetInnerHTML',
    description:
      'dangerouslySetInnerHTML bypasses React escaping. Any untrusted data that reaches __html is executed as markup.',
    severity: 'high',
    remediation:
      'Render text through JSX. If raw HTML is unavoidable, pass it through DOMPurify.sanitize before setting __html.',
  },
  create: (context) => ({
    JSXAttribute({ node }) {
      if (node.name.type !== 'JSXIdentifier' || node.name.name !== PROP) return;
      const loc = locOf(node);
      if (loc) context.report(loc);
    },
    ObjectProperty({ node }) {
      const { key } = node;
      const name =
        key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : null;
      if (name !== PROP) return;
      const loc = locOf(node);
      if (loc) context.report(loc);
    },
  }),
});
