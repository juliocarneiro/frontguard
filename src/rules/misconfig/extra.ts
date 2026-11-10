import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import { defineRule, locOf, matchLines, positionAt } from '../../core/rule.ts';
import { propertyName, stringValue } from '../ast-utils.ts';

const GLOBAL_TARGETS = new Set(['window', 'globalThis', 'top', 'parent']);
const WORKER_FILE_RE = /(?:^|[/.-])(?:worker|sw|service-worker)[^/]*\.[cm]?[jt]sx?$/i;

/** Resolves the handler to a function node: inline, or a function declared in the same file. */
function handlerFunction(node: Node | undefined, path: NodePath): Node | null {
  if (!node) return null;
  if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') return node;
  if (node.type !== 'Identifier') return null;
  const binding = path.scope.getBinding(node.name);
  const declared = binding?.path.node;
  if (declared?.type === 'FunctionDeclaration') return declared;
  if (declared?.type === 'VariableDeclarator') {
    const init = declared.init;
    if (init?.type === 'ArrowFunctionExpression' || init?.type === 'FunctionExpression')
      return init;
  }
  return null;
}

export const requireMessageOriginCheck = defineRule({
  meta: {
    id: 'FG-CFG-005',
    name: 'require-message-origin-check',
    title: 'message event handler without an origin check',
    description:
      'A window "message" listener reads the event without checking event.origin. Any site that can open or frame your page can post messages to it, so the data must be treated as attacker-controlled (DOM XSS, token theft, CSRF-style actions).',
    severity: 'medium',
    category: 'misconfig',
    cwe: 'CWE-346',
    owasp: 'A01:2021 - Broken Access Control',
    remediation:
      'Return early unless event.origin matches the exact origin you expect (if (event.origin !== "https://app.example.com") return;), and validate the shape of event.data before using it.',
  },
  create(context) {
    if (WORKER_FILE_RE.test(context.filename)) return undefined;
    const check = (handler: Node | null, at: Node) => {
      if (!handler || !('params' in handler) || handler.params.length === 0) return;
      const { start, end } = handler;
      if (start == null || end == null) return;
      if (/\borigin\b/.test(context.text.slice(start, end))) return;
      const loc = locOf(at);
      if (loc) context.report(loc);
    };
    return {
      CallExpression(path) {
        const { node } = path;
        const { callee } = node;
        if (stringValue(node.arguments[0]) !== 'message') return;
        const isGlobal =
          (callee.type === 'Identifier' && callee.name === 'addEventListener') ||
          (callee.type === 'MemberExpression' &&
            propertyName(callee) === 'addEventListener' &&
            callee.object.type === 'Identifier' &&
            GLOBAL_TARGETS.has(callee.object.name));
        if (!isGlobal) return;
        check(handlerFunction(node.arguments[1], path), node);
      },
      AssignmentExpression(path) {
        const { node } = path;
        const left = node.left;
        if (propertyName(left) !== 'onmessage' || left.type !== 'MemberExpression') return;
        if (left.object.type !== 'Identifier' || !GLOBAL_TARGETS.has(left.object.name)) return;
        check(handlerFunction(node.right, path), node);
      },
    };
  },
});

const DEV_SERVER_CONFIG_RE =
  /(?:^|\/)(?:vite|vitest|webpack|rspack|rsbuild|astro|nuxt|svelte|quasar)\.config\.[cm]?[jt]s$|(?:^|\/)webpack\.[a-z.]*\.?[cm]?js$/;

const DEV_SERVER_PATTERNS: [RegExp, string][] = [
  [/\ballowedHosts\s*:\s*(?:true\b|['"`]all['"`])/, 'allowedHosts accepts any Host header'],
  [/\bdisableHostCheck\s*:\s*true\b/, 'disableHostCheck: true'],
  [/\bcors\s*:\s*true\b/, 'cors: true'],
  [/\borigin\s*:\s*['"`]\*['"`]/, 'CORS origin "*"'],
];

const FS_NOT_STRICT_RE = /\bfs\s*:\s*\{[^{}]*?\bstrict\s*:\s*false\b/g;

export const noExposedDevServer = defineRule({
  meta: {
    id: 'FG-CFG-006',
    name: 'no-exposed-dev-server',
    title: 'Dev server protections disabled',
    description:
      'The dev server accepts any Host header, any CORS origin or serves files outside the project. Any website you visit can then read your source and files such as .env through your local dev server (DNS rebinding and cross-origin reads, as in the Vite file-read CVEs CVE-2025-30208, CVE-2025-31125 and CVE-2025-24010).',
    severity: 'medium',
    category: 'misconfig',
    cwe: 'CWE-942',
    owasp: 'A05:2021 - Security Misconfiguration',
    remediation:
      'Keep the defaults: list exact hostnames in server.allowedHosts, leave server.fs.strict enabled and cors restricted to known origins. Keep Vite and webpack-dev-server up to date.',
  },
  create(context) {
    if (!DEV_SERVER_CONFIG_RE.test(context.filename)) return undefined;
    for (const [pattern, label] of DEV_SERVER_PATTERNS) {
      for (const { line, column } of matchLines(context.lines, pattern)) {
        context.report({ line, column, message: label });
      }
    }
    // `strict: false` only counts inside an `fs` block (TypeScript has its own `strict`).
    for (const match of context.text.matchAll(FS_NOT_STRICT_RE)) {
      const offset = match.index + match[0].lastIndexOf('strict');
      context.report({ ...positionAt(context.text, offset), message: 'server.fs.strict: false' });
    }
    return undefined;
  },
});
