import { resolve } from 'node:path';
import { resolveConfig, type ResolvedConfig, type UserConfig } from '../config/schema.ts';
import { auditDependencies, DEPENDENCY_RULE } from '../dependencies/audit.ts';
import { builtinRules } from '../rules/index.ts';
import type { Finding, Rule, RuleLevel, ScanResult } from '../types.ts';
import { analyzeFile, type ActiveRule } from './analyze.ts';
import { discoverFiles, readSourceFile } from './files.ts';
import { bySeverity } from './severity.ts';

export interface ScanOptions {
  /** Directory to scan. Defaults to `process.cwd()`. */
  cwd?: string;
  /** Raw (user) config or an already resolved one. */
  config?: UserConfig | ResolvedConfig;
  /** Overrides `fetch`, mainly for tests. */
  fetch?: typeof globalThis.fetch;
}

const READ_CONCURRENCY = 32;

function levelFor(rule: Rule, levels: Record<string, RuleLevel>): RuleLevel {
  return levels[rule.meta.id] ?? levels[rule.meta.name] ?? 'error';
}

function selectRules(config: ResolvedConfig): ActiveRule[] {
  const active: ActiveRule[] = [];
  for (const rule of [...builtinRules, ...config.customRules]) {
    if (!config.categories[rule.meta.category]) continue;
    const level = levelFor(rule, config.rules);
    if (level !== 'off') active.push({ rule, level });
  }
  return active;
}

/** Scans a directory and returns every finding. Never writes to disk or stdout. */
export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const started = performance.now();
  const startedAt = new Date().toISOString();
  const root = resolve(options.cwd ?? process.cwd());
  const config = resolveConfig(options.config);
  const rules = selectRules(config);

  const files = await discoverFiles(root, config);
  const findings: Finding[] = [];
  const warnings: string[] = [];

  for (let i = 0; i < files.length; i += READ_CONCURRENCY) {
    const batch = files.slice(i, i + READ_CONCURRENCY);
    const outcomes = await Promise.all(
      batch.map(async (file) => {
        const read = await readSourceFile(resolve(root, file), config.maxFileSize);
        if (!read.ok) {
          return {
            findings: [],
            warnings:
              read.reason === 'unreadable' ? [`${file}: could not read (${read.detail})`] : [],
          };
        }
        return analyzeFile(file, read.text, rules);
      }),
    );
    for (const outcome of outcomes) {
      findings.push(...outcome.findings);
      warnings.push(...outcome.warnings);
    }
  }

  const ruleMetas = rules.map(({ rule }) => rule.meta);
  const depLevel =
    config.rules[DEPENDENCY_RULE.id] ?? config.rules[DEPENDENCY_RULE.name] ?? 'error';
  if (config.categories.dependencies && depLevel !== 'off') {
    ruleMetas.push(DEPENDENCY_RULE);
    const audit = await auditDependencies(root, config.dependencies, options.fetch);
    warnings.push(...audit.warnings);
    for (const finding of audit.findings) findings.push({ ...finding, level: depLevel });
  }

  findings.sort(
    (a, b) =>
      bySeverity(a, b) || a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column,
  );

  return {
    root,
    findings,
    warnings,
    filesScanned: files.length,
    durationMs: Math.round(performance.now() - started),
    startedAt,
    rules: ruleMetas,
  };
}
