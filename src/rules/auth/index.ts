import type { Node } from '@babel/types';
import { defineRule, locOf } from '../../core/rule.ts';
import type { Rule } from '../../types.ts';
import { identifierWords, objectName, propertyName, stringValue } from '../ast-utils.ts';
import { looksLikeRealSecret } from '../secrets/heuristics.ts';
import { noInsecureCookie, noInsecureRandom } from './extra.ts';

const STORAGE = new Set(['localStorage', 'sessionStorage']);
const TOKEN_WORDS = new Set([
  'token',
  'jwt',
  'bearer',
  'auth',
  'credential',
  'credentials',
  'password',
  'secret',
  'session',
  'sid',
  'apikey',
]);

function isSensitiveKey(key: string): boolean {
  const words = identifierWords(key);
  return words.some((word) => TOKEN_WORDS.has(word)) || /api.?key/i.test(key);
}

const noTokenInWebStorage = defineRule({
  meta: {
    id: 'FG-AUTH-001',
    name: 'no-token-in-web-storage',
    title: 'Auth token stored in Web Storage',
    description:
      'localStorage and sessionStorage are readable by any script on the page, so a single XSS bug leaks every token stored there.',
    severity: 'high',
    category: 'auth',
    cwe: 'CWE-922',
    owasp: 'A04:2021 - Insecure Design',
    remediation:
      'Keep session tokens in httpOnly, Secure, SameSite cookies. If the token must live in JS, keep it in memory and make it short-lived.',
  },
  create(context) {
    const reportAt = (node: Node, key: string) => {
      const loc = locOf(node);
      if (loc) context.report({ ...loc, message: `key "${key}"` });
    };
    return {
      CallExpression({ node }) {
        if (propertyName(node.callee) !== 'setItem') return;
        if (!STORAGE.has(objectName(node.callee) ?? '')) return;
        const key = stringValue(node.arguments[0]);
        if (key && isSensitiveKey(key)) reportAt(node, key);
      },
      AssignmentExpression({ node }) {
        const key = propertyName(node.left);
        if (!key || !STORAGE.has(objectName(node.left) ?? '')) return;
        if (isSensitiveKey(key)) reportAt(node, key);
      },
    };
  },
});

const URL_TOKEN_RE =
  /[?&#](?:token|access_token|id_token|refresh_token|api_key|apikey|api-key|auth|jwt|secret|password|session_id|sessionid)=/i;

const noTokenInUrl = defineRule({
  meta: {
    id: 'FG-AUTH-002',
    name: 'no-token-in-url',
    title: 'Credential passed in a URL',
    description:
      'Tokens in query strings end up in browser history, server and proxy logs, and Referer headers.',
    severity: 'high',
    category: 'auth',
    cwe: 'CWE-598',
    owasp: 'A04:2021 - Insecure Design',
    remediation: 'Send credentials in the Authorization header or in the request body.',
  },
  create: (context) => ({
    StringLiteral({ node }) {
      if (!URL_TOKEN_RE.test(node.value)) return;
      const loc = locOf(node);
      if (loc) context.report(loc);
    },
    TemplateLiteral({ node }) {
      if (!node.quasis.some((q) => URL_TOKEN_RE.test(q.value.raw))) return;
      const loc = locOf(node);
      if (loc) context.report(loc);
    },
  }),
});

const CREDENTIAL_WORDS = [
  ['password'],
  ['passwd'],
  ['pwd'],
  ['secret'],
  ['private', 'key'],
  ['client', 'secret'],
  ['api', 'secret'],
  ['secret', 'key'],
];

function isCredentialName(name: string): boolean {
  const words = identifierWords(name);
  return CREDENTIAL_WORDS.some((needle) =>
    words.some((_, i) => needle.every((word, j) => words[i + j] === word)),
  );
}

const noHardcodedCredentials = defineRule({
  meta: {
    id: 'FG-AUTH-003',
    name: 'no-hardcoded-credentials',
    title: 'Hardcoded credential',
    description:
      'A password or secret is assigned as a string literal. Everything in frontend code ships to the browser and can be read by anyone.',
    severity: 'critical',
    category: 'auth',
    cwe: 'CWE-798',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    remediation:
      'Remove the credential. Authenticate through your backend and load server-side secrets from the environment.',
  },
  create(context) {
    const check = (nameNode: Node, valueNode: Node | null | undefined, at: Node) => {
      const name =
        nameNode.type === 'Identifier'
          ? nameNode.name
          : nameNode.type === 'StringLiteral'
            ? nameNode.value
            : propertyName(nameNode);
      if (!name || !isCredentialName(name)) return;
      const value = stringValue(valueNode);
      if (!value || !looksLikeRealSecret(value)) return;
      const loc = locOf(at);
      if (loc) context.report({ ...loc, message: name, redact: value });
    };
    return {
      VariableDeclarator({ node }) {
        check(node.id, node.init, node);
      },
      AssignmentExpression({ node }) {
        check(node.left, node.right, node);
      },
      ObjectProperty({ node }) {
        check(node.key, node.value, node);
      },
      ClassProperty({ node }) {
        check(node.key, node.value, node);
      },
    };
  },
});

export const authRules: Rule[] = [
  noTokenInWebStorage,
  noTokenInUrl,
  noHardcodedCredentials,
  noInsecureRandom,
  noInsecureCookie,
];
