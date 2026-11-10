import type { Node } from '@babel/types';
import { defineRule, locOf } from '../../core/rule.ts';
import { calleeName, propertyName } from '../ast-utils.ts';
import { isUrlTainted } from '../taint.ts';

const LOCATION_HOSTS = ['window', 'document', 'globalThis', 'self', 'top', 'parent'];

/** `location`, `window.location`, `location.href`, `window.location.href`... */
function isLocationTarget(node: Node): boolean {
  if (node.type === 'Identifier') return node.name === 'location';
  const name = propertyName(node);
  if (name === 'location') {
    return (
      node.type === 'MemberExpression' &&
      node.object.type === 'Identifier' &&
      LOCATION_HOSTS.includes(node.object.name)
    );
  }
  if (name === 'href' && node.type === 'MemberExpression') return isLocationTarget(node.object);
  return false;
}

export const noOpenRedirect = defineRule({
  meta: {
    id: 'FG-XSS-010',
    name: 'no-open-redirect',
    title: 'Navigation to a URL taken from the page address',
    description:
      'A value read from location.search/hash, URLSearchParams, document.referrer or window.name is used as a navigation target. Attackers craft links that redirect victims to phishing pages, or run code with a javascript: URL (DOM-based XSS).',
    severity: 'high',
    category: 'xss',
    cwe: 'CWE-601',
    owasp: 'A01:2021 - Broken Access Control',
    remediation:
      'Only redirect to relative paths you validate (e.g. must start with "/" and not "//"), or to an allow-list of origins checked with new URL(value, location.origin).origin.',
  },
  create: (context) => ({
    AssignmentExpression(path) {
      const { node } = path;
      if (node.operator !== '=' || !isLocationTarget(node.left)) return;
      if (!isUrlTainted(node.right, path.scope)) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: 'location assignment' });
    },
    CallExpression(path) {
      const { node } = path;
      const { callee } = node;
      const name = propertyName(callee);
      let sink: string | null = null;
      if (
        (name === 'assign' || name === 'replace') &&
        callee.type === 'MemberExpression' &&
        isLocationTarget(callee.object)
      ) {
        sink = `location.${name}()`;
      } else if (callee.type === 'MemberExpression' && calleeName(callee) === 'open') {
        // window.open() / globalThis.open() only; a local open() helper is not a sink.
        sink = 'window.open()';
      }
      if (!sink || !isUrlTainted(node.arguments[0], path.scope)) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: sink });
    },
  }),
});
