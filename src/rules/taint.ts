import type { Scope } from '@babel/traverse';
import type { Node } from '@babel/types';
import { objectName, propertyName } from './ast-utils.ts';

/**
 * Lightweight, intra-file taint tracking for DOM-based bugs: does an expression carry a value
 * an attacker controls through the page URL (or window.name / referrer)? It follows
 * concatenation, template literals, decoding calls and up to a few `const`/`let` bindings.
 * It is deliberately conservative: unknown values are untainted, so findings stay precise.
 */

const LOCATION_PARTS = new Set(['search', 'hash', 'href', 'pathname']);
const DOCUMENT_SOURCES = new Set(['URL', 'documentURI', 'referrer', 'baseURI']);
const PASSTHROUGH_CALLS = new Set([
  'decodeURIComponent',
  'decodeURI',
  'unescape',
  'atob',
  'String',
  'substring',
  'substr',
  'slice',
  'trim',
  'replace',
  'toString',
]);

function isLocation(node: Node): boolean {
  if (node.type === 'Identifier') return node.name === 'location';
  const name = propertyName(node);
  return (
    name === 'location' &&
    ['window', 'document', 'globalThis', 'self'].includes(objectName(node) ?? '')
  );
}

/** `location.search`, `window.location.hash`, `document.referrer`, `window.name`... */
function isDirectSource(node: Node): boolean {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return false;
  const name = propertyName(node);
  if (!name) return false;
  if (LOCATION_PARTS.has(name) && isLocation(node.object)) return true;
  if (
    DOCUMENT_SOURCES.has(name) &&
    node.object.type === 'Identifier' &&
    node.object.name === 'document'
  ) {
    return true;
  }
  return name === 'name' && node.object.type === 'Identifier' && node.object.name === 'window';
}

/** Expressions that produce a URLSearchParams: `new URLSearchParams(...)`, `url.searchParams`, `useSearchParams()`. */
function isSearchParams(node: Node, scope: Scope, depth: number): boolean {
  if (node.type === 'NewExpression') {
    return node.callee.type === 'Identifier' && node.callee.name === 'URLSearchParams';
  }
  if (propertyName(node) === 'searchParams') return true;
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
    return node.callee.name === 'useSearchParams';
  }
  if (node.type === 'Identifier' && depth > 0) {
    const init = bindingInit(node.name, scope);
    return init ? isSearchParams(init, scope, depth - 1) : false;
  }
  return false;
}

function bindingInit(name: string, scope: Scope): Node | null {
  const binding = scope.getBinding(name);
  if (!binding || binding.kind === 'param' || binding.kind === 'module') return null;
  const declarator = binding.path.node;
  if (declarator.type !== 'VariableDeclarator') return null;
  // `const [params] = useSearchParams()` (React Router)
  if (declarator.id.type === 'ArrayPattern' && declarator.init) return declarator.init;
  return declarator.id.type === 'Identifier' ? (declarator.init ?? null) : null;
}

export function isUrlTainted(node: Node | null | undefined, scope: Scope, depth = 3): boolean {
  if (!node) return false;
  switch (node.type) {
    case 'Identifier': {
      if (depth <= 0) return false;
      return isUrlTainted(bindingInit(node.name, scope), scope, depth - 1);
    }
    case 'MemberExpression':
    case 'OptionalMemberExpression':
      if (isDirectSource(node)) return true;
      // `params.next` where `params` came from Object.fromEntries(searchParams) etc. is not tracked.
      return false;
    case 'TemplateLiteral':
      return node.expressions.some((e) => isUrlTainted(e, scope, depth));
    case 'BinaryExpression':
      return (
        node.operator === '+' &&
        (isUrlTainted(node.left, scope, depth) || isUrlTainted(node.right, scope, depth))
      );
    case 'LogicalExpression':
      return isUrlTainted(node.left, scope, depth) || isUrlTainted(node.right, scope, depth);
    case 'ConditionalExpression':
      return (
        isUrlTainted(node.consequent, scope, depth) || isUrlTainted(node.alternate, scope, depth)
      );
    case 'TSAsExpression':
    case 'TSNonNullExpression':
    case 'ParenthesizedExpression':
      return isUrlTainted(node.expression, scope, depth);
    case 'CallExpression':
    case 'OptionalCallExpression': {
      const { callee } = node;
      const name = callee.type === 'Identifier' ? callee.name : propertyName(callee);
      if (!name) return false;
      // searchParams.get('next'), new URLSearchParams(location.search).get('url')
      if (
        name === 'get' &&
        (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
      ) {
        return isSearchParams(callee.object, scope, depth);
      }
      if (!PASSTHROUGH_CALLS.has(name)) return false;
      if (callee.type === 'Identifier') return isUrlTainted(node.arguments[0], scope, depth);
      if (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') {
        return isUrlTainted(callee.object, scope, depth);
      }
      return false;
    }
    default:
      return false;
  }
}
