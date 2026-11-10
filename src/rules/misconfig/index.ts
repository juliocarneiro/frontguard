import { defineRule, locOf, matchLines, positionAt } from '../../core/rule.ts';
import type { Rule } from '../../types.ts';
import { propertyName, stringValue } from '../ast-utils.ts';

const BUILD_CONFIG_RE =
  /(?:^|\/)(?:vite|vitest|webpack|rollup|rolldown|rspack|rsbuild|next|nuxt|svelte|astro|tsdown|tsup|vue|quasar|craco)\.config\.[cm]?[jt]s$/;

const SOURCEMAP_PATTERNS: [RegExp, string][] = [
  [/\bdevtool\s*:\s*['"`](?:inline-|eval-)?(?:cheap-)?(?:module-)?source-map['"`]/, 'devtool'],
  [/\bsourcemap\s*:\s*(?:true|['"`]inline['"`])/i, 'build.sourcemap'],
  [/\bproductionBrowserSourceMaps\s*:\s*true/, 'productionBrowserSourceMaps'],
];

const noPublicSourcemaps = defineRule({
  meta: {
    id: 'FG-CFG-001',
    name: 'no-public-sourcemaps',
    title: 'Public source maps in build config',
    description:
      'Publishing source maps exposes your original source code, comments and internal paths to anyone.',
    severity: 'medium',
    category: 'misconfig',
    cwe: 'CWE-540',
    owasp: 'A05:2021 - Security Misconfiguration',
    remediation:
      'Use "hidden" source maps (uploaded to your error tracker but not served), or disable them for production builds.',
  },
  create(context) {
    if (!BUILD_CONFIG_RE.test(context.filename)) return undefined;
    for (const [index, line] of context.lines.entries()) {
      for (const [pattern, label] of SOURCEMAP_PATTERNS) {
        const match = pattern.exec(line);
        if (match) context.report({ line: index + 1, column: match.index + 1, message: label });
      }
    }
    return undefined;
  },
});

const LOCAL_HOST_RE =
  /^(?:https?|wss?):\/\/(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\])(?:[:/]|$)/i;
const RESOURCE_ATTR_RE = /\b(?:src|action|formaction|poster|data)\s*=\s*["'](http:\/\/[^"'\s]+)/gi;
const LINK_HREF_RE = /<link\b[^>]*\bhref\s*=\s*["'](http:\/\/[^"'\s]+)/gi;
const REQUEST_FNS = new Set(['fetch', 'get', 'post', 'put', 'patch', 'delete', 'request', 'open']);

const noMixedContent = defineRule({
  meta: {
    id: 'FG-CFG-002',
    name: 'no-mixed-content',
    title: 'Insecure http:// or ws:// resource',
    description:
      'Loading scripts, data or sockets over plain HTTP/WS lets anyone on the network read or tamper with them, and browsers block it on HTTPS pages.',
    severity: 'medium',
    category: 'misconfig',
    cwe: 'CWE-319',
    owasp: 'A02:2021 - Cryptographic Failures',
    remediation: 'Use https:// and wss:// URLs for every resource and API endpoint.',
  },
  create(context) {
    for (const re of [RESOURCE_ATTR_RE, LINK_HREF_RE]) {
      for (const { line, column, match } of matchLines(context.lines, re)) {
        const url = match[1]!;
        if (!LOCAL_HOST_RE.test(url)) context.report({ line, column, message: url });
      }
    }
    return {
      CallExpression({ node }) {
        const callee = node.callee;
        const name = callee.type === 'Identifier' ? callee.name : propertyName(callee);
        if (!name || !REQUEST_FNS.has(name)) return;
        const urlArg = name === 'open' ? node.arguments[1] : node.arguments[0];
        const url = stringValue(urlArg) ?? '';
        if (!/^http:\/\//i.test(url) || LOCAL_HOST_RE.test(url)) return;
        const loc = locOf(node);
        if (loc) context.report({ ...loc, message: url });
      },
      NewExpression({ node }) {
        if (node.callee.type !== 'Identifier' || node.callee.name !== 'WebSocket') return;
        const url = stringValue(node.arguments[0]) ?? '';
        if (!/^ws:\/\//i.test(url) || LOCAL_HOST_RE.test(url)) return;
        const loc = locOf(node);
        if (loc) context.report({ ...loc, message: url });
      },
    };
  },
});

const EXTERNAL_TAG_RE =
  /<(script|link)\b([^>]*?)\b(src|href)\s*=\s*["']((?:https?:)?\/\/[^"']+)["']([^>]*)>/gi;

const requireSri = defineRule({
  meta: {
    id: 'FG-CFG-003',
    name: 'require-sri',
    title: 'Third-party resource without Subresource Integrity',
    description:
      'A script or stylesheet is loaded from another origin without an integrity hash. If that host is compromised, its code runs on your page.',
    severity: 'low',
    category: 'misconfig',
    cwe: 'CWE-353',
    owasp: 'A08:2021 - Software and Data Integrity Failures',
    remediation:
      'Add integrity="sha384-..." and crossorigin="anonymous" to the tag, or self-host the file.',
  },
  create(context) {
    for (const match of context.text.matchAll(EXTERNAL_TAG_RE)) {
      const [, tag, before = '', , url = '', after = ''] = match;
      const attrs = `${before} ${after}`;
      if (/\bintegrity\s*=/i.test(attrs)) continue;
      if (
        tag?.toLowerCase() === 'link' &&
        !/\brel\s*=\s*["']?(?:stylesheet|modulepreload|preload)/i.test(attrs)
      ) {
        continue;
      }
      context.report({ ...positionAt(context.text, match.index), message: url });
    }
    return undefined;
  },
});

const noWildcardPostMessage = defineRule({
  meta: {
    id: 'FG-CFG-004',
    name: 'no-wildcard-postmessage',
    title: 'postMessage with "*" target origin',
    description:
      'postMessage(data, "*") delivers the message to whatever origin the target window currently has, leaking data to attacker-controlled frames.',
    severity: 'medium',
    category: 'misconfig',
    cwe: 'CWE-345',
    owasp: 'A01:2021 - Broken Access Control',
    remediation:
      'Pass the exact origin you expect, e.g. postMessage(data, "https://app.example.com").',
  },
  create: (context) => ({
    CallExpression({ node }) {
      if (propertyName(node.callee) !== 'postMessage') return;
      if (stringValue(node.arguments[1]) !== '*') return;
      const loc = locOf(node);
      if (loc) context.report(loc);
    },
  }),
});

export const misconfigRules: Rule[] = [
  noPublicSourcemaps,
  noMixedContent,
  requireSri,
  noWildcardPostMessage,
];
