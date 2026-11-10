import { z } from 'zod';
import type { Rule } from '../types.ts';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const CATEGORIES = ['xss', 'secrets', 'auth', 'misconfig', 'dependencies'] as const;
export const REPORTERS = ['console', 'json', 'sarif', 'html'] as const;

export type ReporterName = (typeof REPORTERS)[number];

const severity = z.enum(SEVERITIES);

const ruleShape = z.custom<Rule>(
  (value) =>
    typeof value === 'object' &&
    value !== null &&
    'meta' in value &&
    'create' in value &&
    typeof (value as Rule).create === 'function',
  { message: 'Expected a rule created with defineRule()' },
);

const configSchema = z.strictObject({
  /** Glob patterns (relative to the scan root) of files to scan. */
  include: z
    .array(z.string())
    .default(['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts,vue,svelte,html,htm,astro}']),
  /** Glob patterns to skip. Added on top of the built-in ignores unless `noDefaultExclude` is set. */
  exclude: z.array(z.string()).default([]),
  /** Disables the built-in exclude list (node_modules, build output, tests, fixtures...). */
  noDefaultExclude: z.boolean().default(false),
  /** Files larger than this (in bytes) are skipped. Large files are almost always generated. */
  maxFileSize: z
    .number()
    .int()
    .positive()
    .default(1024 * 1024),
  /** Enable or disable whole rule categories. */
  categories: z
    .partialRecord(z.enum(CATEGORIES), z.boolean())
    .default({})
    .transform((value) => ({
      xss: true,
      secrets: true,
      auth: true,
      misconfig: true,
      dependencies: true,
      ...value,
    })),
  /** Per-rule level, keyed by rule id (`FG-XSS-001`) or name (`no-inner-html`). */
  rules: z.record(z.string(), z.enum(['off', 'warn', 'error'])).default({}),
  /** Additional rules created with `defineRule()`. */
  customRules: z.array(ruleShape).default([]),
  /** Lowest severity that makes the scan fail (exit code 1). `none` never fails. */
  failOn: z.union([severity, z.literal('none')]).default('high'),
  /** Reporters to run. `console` prints to stdout; the others write files into `outputDir`. */
  reporters: z.array(z.enum(REPORTERS)).default(['console']),
  /** Directory for json/sarif/html reports, relative to the scan root. */
  outputDir: z.string().default('frontguard-report'),
  dependencies: z
    .strictObject({
      /** Also audit devDependencies. */
      includeDev: z.boolean().default(false),
      /** Skip the OSV network lookup entirely. */
      offline: z.boolean().default(false),
      /** Timeout for each OSV request, in milliseconds. */
      timeoutMs: z.number().int().positive().default(15_000),
    })
    .default({ includeDev: false, offline: false, timeoutMs: 15_000 }),
});

/** Config as written by users: every field optional. */
export type UserConfig = z.input<typeof configSchema>;
/** Config after defaults are applied. */
export type ResolvedConfig = z.output<typeof configSchema>;

export const DEFAULT_EXCLUDE = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/coverage/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/.output/**',
  '**/.svelte-kit/**',
  '**/.astro/**',
  '**/.vercel/**',
  '**/.turbo/**',
  '**/storybook-static/**',
  '**/frontguard-report/**',
  '**/*.min.{js,css}',
  '**/*.d.ts',
  '**/*.{test,spec}.*',
  '**/{test,tests,__tests__,__mocks__,fixtures,__fixtures__}/**',
];

export function resolveConfig(input: UserConfig = {}): ResolvedConfig {
  const result = configSchema.safeParse(input);
  if (!result.success) {
    throw new ConfigError(`Invalid configuration:\n${z.prettifyError(result.error)}`);
  }
  return result.data;
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}
