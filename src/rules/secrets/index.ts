import { defineRule } from '../../core/rule.ts';
import type { Rule, RuleMeta } from '../../types.ts';
import { isHighEntropy } from './entropy.ts';
import {
  extractAssignedValue,
  isNoisyLine,
  isSafeEntropyContext,
  looksLikeRealSecret,
} from './heuristics.ts';
import { secretPatterns, type SecretPattern } from './patterns.ts';
import { noSecretInPublicEnv } from './public-env.ts';

const base = {
  category: 'secrets',
  cwe: 'CWE-798',
  owasp: 'A07:2021 - Identification and Authentication Failures',
} as const;

const metas: RuleMeta[] = [
  {
    ...base,
    id: 'FG-SEC-001',
    name: 'no-aws-credentials',
    title: 'AWS credentials exposed',
    description:
      'AWS access keys or secret keys were found in source code. They grant direct access to AWS services and can lead to full account compromise.',
    severity: 'critical',
    remediation:
      'Remove the credentials, rotate them in the AWS console and load them at runtime from a secrets manager. Never ship AWS credentials to the browser.',
  },
  {
    ...base,
    id: 'FG-SEC-002',
    name: 'no-api-tokens',
    title: 'API key or token exposed',
    description:
      'A provider API key or token was found hardcoded in source code. Anything bundled into frontend code is readable by every visitor.',
    severity: 'high',
    remediation:
      'Remove the key, rotate it in the provider dashboard and call the provider from your backend instead. Browser-safe keys (e.g. Google Maps) must be restricted by HTTP referrer.',
  },
  {
    ...base,
    id: 'FG-SEC-003',
    name: 'no-private-keys',
    title: 'Private key exposed',
    description: 'A private cryptographic key (RSA, EC, DSA, PGP or OpenSSH) was found.',
    severity: 'critical',
    cwe: 'CWE-321',
    owasp: 'A02:2021 - Cryptographic Failures',
    remediation:
      'Remove the key from version control, revoke and regenerate it, and keep it in a vault.',
  },
  {
    ...base,
    id: 'FG-SEC-004',
    name: 'no-hardcoded-jwt',
    title: 'Hardcoded JWT',
    description:
      'A JSON Web Token was found in source code. JWTs carry identity claims and are often still valid when leaked.',
    severity: 'high',
    remediation:
      'Remove the token. Obtain tokens at runtime through your authentication flow and keep them in httpOnly cookies.',
  },
  {
    ...base,
    id: 'FG-SEC-005',
    name: 'no-connection-strings',
    title: 'Database connection string exposed',
    description: 'A database URL containing credentials was found in source code.',
    severity: 'critical',
    remediation:
      'Remove the connection string, rotate the password and keep database access on the server.',
  },
];

const ENTROPY_META: RuleMeta = {
  ...base,
  id: 'FG-SEC-006',
  name: 'no-high-entropy-strings',
  title: 'High-entropy string',
  description:
    'A long random-looking string was found. It may be a credential; review it and suppress the finding if it is not.',
  severity: 'medium',
  remediation:
    'If the string is a credential, move it out of the code. Otherwise add `// frontguard-ignore-next-line FG-SEC-006` above it.',
};

function isGeneric(pattern: SecretPattern): boolean {
  return pattern.id.startsWith('generic-');
}

const MAX_PEM_LINES = 100;

/** Key material lines after a `-----BEGIN ... KEY-----` header, up to the END line. */
function pemBody(lines: readonly string[], headerIndex: number): string[] {
  const body: string[] = [];
  for (let i = headerIndex + 1; i < lines.length && i <= headerIndex + MAX_PEM_LINES; i++) {
    const text = lines[i]!.trim();
    if (text.startsWith('-----END')) break;
    const material = /[A-Za-z0-9+/=]{8,}/.exec(text)?.[0];
    if (material) body.push(material);
  }
  return body;
}

function createPatternRule(meta: RuleMeta, patterns: SecretPattern[]): Rule {
  return defineRule({
    meta,
    create(context) {
      for (const [index, line] of context.lines.entries()) {
        const noisy = isNoisyLine(line);
        for (const pattern of patterns) {
          const generic = isGeneric(pattern);
          if (generic && noisy) continue;

          const match = pattern.regex.exec(line);
          if (!match) continue;

          // A capture group holds the secret itself, without surrounding delimiters.
          let secret = match[1] ?? match[0];
          let column = match.index + (match[1] ? match[0].indexOf(match[1]) : 0) + 1;
          if (generic) {
            const value = extractAssignedValue(line, match.index);
            if (!value || !looksLikeRealSecret(value)) continue;
            secret = value;
            column = match.index + 1;
          }

          const redact = [secret.trim()];
          // PEM blocks: the key material is on the following lines, mask all of it.
          if (meta.id === 'FG-SEC-003') redact.push(...pemBody(context.lines, index));

          context.report({
            line: index + 1,
            column,
            message: pattern.name,
            severity: pattern.severity,
            redact,
          });
        }
      }
      return undefined;
    },
  });
}

const HIGH_ENTROPY_QUOTED_RE = /['"`]([A-Za-z0-9+/=_.-]{20,})['"`]/g;

/** Tokens that are designed to be shipped to browsers. */
const PUBLIC_TOKEN_RE = /^(?:pk_(?:live|test)_|pk\.ey|sb_publishable_|phc_|NEXT_PUBLIC_)/;

const highEntropyRule = defineRule({
  meta: ENTROPY_META,
  create(context) {
    for (const [index, line] of context.lines.entries()) {
      if (isNoisyLine(line) || isSafeEntropyContext(line)) continue;
      for (const match of line.matchAll(HIGH_ENTROPY_QUOTED_RE)) {
        const candidate = match[1]!;
        if (PUBLIC_TOKEN_RE.test(candidate) || !isHighEntropy(candidate)) continue;
        context.report({ line: index + 1, column: match.index + 1, redact: candidate });
      }
    }
    return undefined;
  },
});

export const secretsRules: Rule[] = [
  ...metas.map((meta) =>
    createPatternRule(
      meta,
      secretPatterns.filter((p) => p.ruleId === meta.id),
    ),
  ),
  highEntropyRule,
  noSecretInPublicEnv,
];
