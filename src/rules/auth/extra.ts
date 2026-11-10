import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import { defineRule, locOf } from '../../core/rule.ts';
import { identifierWords, objectName, propertyName } from '../ast-utils.ts';

const SECURITY_WORDS = new Set([
  'token',
  'secret',
  'nonce',
  'password',
  'passwd',
  'otp',
  'salt',
  'csrf',
  'xsrf',
  'session',
  'sid',
  'verifier',
  'challenge',
  'apikey',
  'iv',
]);

function nameOf(node: Node | null | undefined): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  return propertyName(node);
}

/** The name the random value ends up in: `const token = ...`, `obj.nonce = ...`, `{ csrf: ... }`, `function makeToken()`. */
function destinationName(path: NodePath): string | null {
  for (const current of path.getAncestry().slice(1)) {
    const { node } = current;
    switch (node.type) {
      case 'VariableDeclarator':
        return nameOf(node.id);
      case 'AssignmentExpression':
        return nameOf(node.left);
      case 'ObjectProperty':
      case 'ClassProperty':
        return nameOf(node.key);
      case 'FunctionDeclaration':
        return node.id?.name ?? null;
      case 'ArrowFunctionExpression':
      case 'FunctionExpression': {
        const parent = current.parent;
        if (parent.type === 'VariableDeclarator') return nameOf(parent.id);
        if (parent.type === 'ObjectProperty') return nameOf(parent.key);
        // Callback (`.map(() => Math.random())`): keep climbing to where the result is stored.
        break;
      }
      case 'ClassMethod':
      case 'ObjectMethod':
        return nameOf(node.key);
      case 'Program':
        return null;
      default:
        break;
    }
  }
  return null;
}

export const noInsecureRandom = defineRule({
  meta: {
    id: 'FG-AUTH-004',
    name: 'no-insecure-random',
    title: 'Math.random() used for a security value',
    description:
      'Math.random() is not cryptographically secure: its output can be predicted from a few samples. Tokens, nonces, OAuth state, PKCE verifiers, salts or passwords generated with it can be guessed.',
    severity: 'medium',
    category: 'auth',
    cwe: 'CWE-338',
    owasp: 'A02:2021 - Cryptographic Failures',
    remediation:
      'Use crypto.getRandomValues() or crypto.randomUUID() (available in every browser and in Node), e.g. crypto.getRandomValues(new Uint8Array(32)).',
  },
  create: (context) => ({
    CallExpression(path) {
      const { node } = path;
      if (propertyName(node.callee) !== 'random' || objectName(node.callee) !== 'Math') return;
      const name = destinationName(path);
      if (!name) return;
      const words = identifierWords(name);
      if (!words.some((word) => SECURITY_WORDS.has(word))) return;
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: name });
    },
  }),
});

const AUTH_COOKIE_RE =
  /(?:^|[_-])(?:token|jwt|session|sess|sid|auth|access|refresh|csrf|xsrf|remember)(?:$|[_-])|^(?:connect\.sid|PHPSESSID|JSESSIONID)$/i;

/** Static text of a cookie string: the literal, or the template's first chunk. */
function cookieText(node: Node): string | null {
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral')
    return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join('\u0000');
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = cookieText(node.left);
    const right = node.right.type === 'StringLiteral' ? node.right.value : '\u0000';
    return left === null ? null : left + right;
  }
  return null;
}

export const noInsecureCookie = defineRule({
  meta: {
    id: 'FG-AUTH-005',
    name: 'no-insecure-cookie',
    title: 'Auth cookie written from JavaScript',
    description:
      'A session or token cookie is set through document.cookie. Cookies written by JavaScript can never be httpOnly, so any XSS can read them, and without Secure and SameSite they also travel over plain HTTP and cross-site requests.',
    severity: 'medium',
    category: 'auth',
    cwe: 'CWE-1004',
    owasp: 'A05:2021 - Security Misconfiguration',
    remediation:
      'Let the server set auth cookies with Set-Cookie: name=value; HttpOnly; Secure; SameSite=Lax (or Strict). If a cookie must be set in JS, add "; Secure; SameSite=Strict" and keep secrets out of it.',
  },
  create: (context) => ({
    AssignmentExpression({ node }) {
      if (propertyName(node.left) !== 'cookie' || objectName(node.left) !== 'document') return;
      const text = cookieText(node.right);
      if (!text) return;
      const name = text.split('=')[0]?.trim() ?? '';
      if (!name || name.includes('\u0000') || !AUTH_COOKIE_RE.test(name)) return;
      const secure = /;\s*secure\b/i.test(text) && /;\s*samesite=(?:lax|strict)/i.test(text);
      const loc = locOf(node);
      if (loc)
        context.report({
          ...loc,
          message: secure ? `"${name}" (not httpOnly)` : `"${name}" without Secure/SameSite`,
        });
    },
  }),
});
