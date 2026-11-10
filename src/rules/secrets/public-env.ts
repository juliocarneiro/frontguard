// frontguard-ignore-file FG-SEC-007 (the description names example variables)
import { defineRule, matchLines } from '../../core/rule.ts';

/**
 * Prefixes that frameworks inline into the client bundle. Anything behind them is public by
 * design, so a secret-looking name means a server secret is being shipped to every visitor.
 */
const PUBLIC_ENV_RE =
  /\b((NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|EXPO_PUBLIC|GATSBY|VUE_APP|PUBLIC|SNOWPACK_PUBLIC|STORYBOOK)_([A-Z0-9_]+))\b/g;

const SECRET_WORD_GROUPS: string[][] = [
  ['secret'],
  ['private'],
  ['password'],
  ['passwd'],
  ['service', 'role'],
  ['service', 'key'],
  ['admin', 'key'],
  ['master', 'key'],
  ['database', 'url'],
  ['db', 'url'],
  ['db', 'password'],
  ['postgres', 'url'],
  ['mongodb', 'uri'],
  ['webhook', 'secret'],
  ['signing', 'key'],
  ['encryption', 'key'],
];

function looksSecret(name: string): boolean {
  const words = name.toLowerCase().split('_');
  return SECRET_WORD_GROUPS.some((group) =>
    words.some((_, i) => group.every((word, j) => words[i + j] === word)),
  );
}

export const noSecretInPublicEnv = defineRule({
  meta: {
    id: 'FG-SEC-007',
    name: 'no-secret-in-public-env',
    title: 'Server secret exposed through a public env variable',
    description:
      'Variables prefixed with NEXT_PUBLIC_, VITE_, REACT_APP_, NUXT_PUBLIC_, PUBLIC_, EXPO_PUBLIC_... are inlined into the JavaScript sent to the browser. A name like VITE_SUPABASE_SERVICE_ROLE_KEY or NEXT_PUBLIC_STRIPE_SECRET means a server secret is readable by every visitor.',
    severity: 'high',
    category: 'secrets',
    cwe: 'CWE-200',
    owasp: 'A01:2021 - Broken Access Control',
    remediation:
      'Rename the variable without the public prefix, read it only in server code (API routes, server actions, load functions), and rotate the secret: it is already in your deployed bundles.',
  },
  create(context) {
    const seen = new Set<string>();
    for (const { line, column, match } of matchLines(context.lines, PUBLIC_ENV_RE)) {
      const name = match[1]!;
      if (!looksSecret(match[3]!) || seen.has(`${line}:${name}`)) continue;
      seen.add(`${line}:${name}`);
      context.report({ line, column, message: name });
    }
    return undefined;
  },
});
