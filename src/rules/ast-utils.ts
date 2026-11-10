import type { Expression, Node } from '@babel/types';

/** Property name of `obj.prop` or `obj['prop']`; `null` for dynamic access. */
export function propertyName(node: Node): string | null {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return null;
  const { property, computed } = node;
  if (!computed && property.type === 'Identifier') return property.name;
  if (computed && property.type === 'StringLiteral') return property.value;
  return null;
}

/** Name of the object in `obj.prop`, unwrapping `window.obj.prop` / `globalThis.obj.prop`. */
export function objectName(node: Node): string | null {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return null;
  const { object } = node;
  if (object.type === 'Identifier') return object.name;
  const inner = propertyName(object);
  if (
    inner &&
    (object.type === 'MemberExpression' || object.type === 'OptionalMemberExpression') &&
    object.object.type === 'Identifier' &&
    ['window', 'globalThis', 'self'].includes(object.object.name)
  ) {
    return inner;
  }
  return null;
}

/** Name of a called function: `eval(...)`, `window.eval(...)`, `globalThis.setTimeout(...)`. */
export function calleeName(node: Node): string | null {
  if (node.type === 'Identifier') return node.name;
  const name = propertyName(node);
  if (!name || (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression')) {
    return null;
  }
  const { object } = node;
  return object.type === 'Identifier' && ['window', 'globalThis', 'self'].includes(object.name)
    ? name
    : null;
}

/** A string whose value is known at build time, so it cannot carry user input. */
export function isStaticString(node: Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type === 'StringLiteral') return true;
  if (node.type === 'TemplateLiteral') return node.expressions.length === 0;
  return false;
}

export function stringValue(node: Node | null | undefined): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.quasis.length === 1) {
    return node.quasis[0]!.value.cooked ?? node.quasis[0]!.value.raw;
  }
  return null;
}

export function isStringLike(node: Expression | Node | undefined): boolean {
  return node?.type === 'StringLiteral' || node?.type === 'TemplateLiteral';
}

/** Splits an identifier into lower-case words: `authToken` -> [auth, token], `API_KEY` -> [api, key]. */
export function identifierWords(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
}
