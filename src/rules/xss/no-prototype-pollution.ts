import type { NodePath } from '@babel/traverse';
import type { Function as FunctionNode, Node } from '@babel/types';
import { defineRule, locOf } from '../../core/rule.ts';
import { propertyName } from '../ast-utils.ts';

const MERGE_NAME_RE = /merge|extend|assign|deep|clone|defaults|mixin|setpath|setvalue|^set$|copy/i;
/** Any of these in the function means the author already handles the dangerous keys. */
const GUARD_RE =
  /__proto__|['"`]constructor['"`]|['"`]prototype['"`]|hasOwn|hasOwnProperty|Object\.create\(\s*null\s*\)|isSafeKey|isPrototypePolluted|new Map\b/;

function functionName(path: NodePath<FunctionNode>): string | null {
  const { node, parent } = path;
  if ('id' in node && node.id) return node.id.name;
  if (parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier')
    return parent.id.name;
  if (
    (parent.type === 'ObjectProperty' || parent.type === 'ClassMethod') &&
    parent.key.type === 'Identifier'
  ) {
    return parent.key.name;
  }
  if (node.type === 'ObjectMethod' || node.type === 'ClassMethod') {
    return node.key.type === 'Identifier' ? node.key.name : null;
  }
  return null;
}

/** Name bound to the key in `for (k in obj)`, `for (const k of Object.keys(obj))`, `for (const [k, v] of Object.entries(obj))`. */
function loopKey(node: Node): string | null {
  if (node.type !== 'ForInStatement' && node.type !== 'ForOfStatement') return null;
  if (node.type === 'ForOfStatement') {
    const iterable = node.right;
    const fn = iterable.type === 'CallExpression' ? propertyName(iterable.callee) : null;
    if (fn !== 'keys' && fn !== 'entries') return null;
  }
  const left = node.left;
  const target = left.type === 'VariableDeclaration' ? left.declarations[0]?.id : left;
  if (!target) return null;
  if (target.type === 'Identifier') return target.name;
  if (target.type === 'ArrayPattern' && target.elements[0]?.type === 'Identifier')
    return target.elements[0].name;
  return null;
}

export const noPrototypePollution = defineRule({
  meta: {
    id: 'FG-XSS-012',
    name: 'no-prototype-pollution',
    title: 'Prototype pollution in object merge',
    description:
      'A merge/extend/set helper copies attacker-controllable keys onto an object without rejecting "__proto__", "constructor" and "prototype". A payload such as {"__proto__": {...}} then adds properties to every object on the page, which turns into DOM XSS through sanitizers and templating (DOMPurify CVE-2026-41238) or code execution on the server (React2Shell, CVE-2025-55182).',
    severity: 'high',
    category: 'xss',
    cwe: 'CWE-1321',
    owasp: 'A08:2021 - Software and Data Integrity Failures',
    remediation:
      'Skip "__proto__", "constructor" and "prototype" keys (or check Object.hasOwn(source, key)), merge into Object.create(null) or a Map, or use structuredClone / a maintained library such as lodash.merge >= 4.6.2.',
  },
  create(context) {
    const reported = new Set<Node>();
    return {
      AssignmentExpression(path) {
        const { node } = path;
        const left = node.left;
        if (left.type !== 'MemberExpression') return;
        // obj.__proto__.isAdmin = ... / obj['__proto__'] = ...
        if (propertyName(left) === '__proto__' || propertyName(left.object) === '__proto__') {
          const loc = locOf(node);
          if (loc) context.report({ ...loc, message: 'write through __proto__' });
          return;
        }
        if (!left.computed || left.property.type !== 'Identifier') return;
        const key = left.property.name;
        const loop = path.findParent((p) => loopKey(p.node) === key);
        if (!loop) return;
        const fn = loop.getFunctionParent();
        if (!fn || reported.has(fn.node)) return;
        const { start, end } = fn.node;
        if (start == null || end == null) return;
        const body = context.text.slice(start, end);
        const name = functionName(fn);
        const inner = context.text.slice(fn.node.body.start ?? start, end);
        const recursive =
          name !== null &&
          new RegExp(String.raw`(?:^|[^\w$])${name.replaceAll('$', '\\$')}\s*\(`).test(inner);
        if (!recursive && !(name && MERGE_NAME_RE.test(name))) return;
        if (GUARD_RE.test(body)) return;
        reported.add(fn.node);
        const loc = locOf(node);
        if (loc) context.report({ ...loc, message: name ? `${name}()` : 'merge loop' });
      },
    };
  },
});
