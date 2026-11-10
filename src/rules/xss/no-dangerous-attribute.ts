import type { Node } from '@babel/types';
import { defineRule, locOf } from '../../core/rule.ts';
import { isStaticString, isStringLike, propertyName, stringValue } from '../ast-utils.ts';
import { isUrlTainted } from '../taint.ts';
import { XSS } from './meta.ts';

const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formaction', 'xlink:href', 'data']);

/** A string built at runtime: template with expressions, or concatenation involving a string literal. */
function isDynamicString(node: Node): boolean {
  if (node.type === 'TemplateLiteral') return node.expressions.length > 0;
  if (node.type !== 'BinaryExpression' || node.operator !== '+') return false;
  const { left, right } = node;
  return isStringLike(left) || isStringLike(right) || isDynamicString(left);
}

export const noDangerousAttribute = defineRule({
  meta: {
    ...XSS,
    id: 'FG-XSS-011',
    name: 'no-dangerous-attribute',
    title: 'Code-executing attribute set from a dynamic value',
    description:
      'Event-handler attributes (onclick, onerror...) are compiled as JavaScript and iframe srcdoc is parsed as a full HTML document, so a dynamic value there executes injected code. URL attributes fed from the page address accept javascript: URLs.',
    severity: 'high',
    remediation:
      'Attach handlers with addEventListener and a function, render iframe content from a sanitized string (DOMPurify) or a separate URL, and validate URLs against an allow-list of protocols (https:, mailto:).',
  },
  create: (context) => ({
    CallExpression(path) {
      const { node } = path;
      if (propertyName(node.callee) !== 'setAttribute') return;
      const attribute = stringValue(node.arguments[0])?.toLowerCase();
      const value = node.arguments[1];
      if (!attribute || !value) return;
      const executes = attribute.startsWith('on') || attribute === 'srcdoc';
      const flagged = executes
        ? !isStaticString(value)
        : URL_ATTRIBUTES.has(attribute) && isUrlTainted(value, path.scope);
      if (!flagged) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: `setAttribute("${attribute}")` });
    },
    AssignmentExpression(path) {
      const { node } = path;
      const name = propertyName(node.left);
      if (!name || node.operator !== '=') return;
      // el.onclick = "doThing(" + id + ")" compiles the string as code.
      const handlerString = /^on[a-z]+$/.test(name) && isDynamicString(node.right);
      const srcdoc = name === 'srcdoc' && !isStaticString(node.right);
      if (!handlerString && !srcdoc) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: name });
    },
    JSXAttribute({ node }) {
      if (node.name.type !== 'JSXIdentifier' || node.name.name.toLowerCase() !== 'srcdoc') return;
      const { value } = node;
      if (!value || value.type === 'StringLiteral') return;
      if (value.type === 'JSXExpressionContainer' && isStaticString(value.expression)) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: 'srcDoc' });
    },
  }),
});
