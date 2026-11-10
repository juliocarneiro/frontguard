import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach } from 'vitest';
import { analyzeFile } from '../src/core/analyze.ts';
import { builtinRules } from '../src/rules/index.ts';
import type { Finding } from '../src/types.ts';

/** Runs all built-in rules on an in-memory file. */
export function analyze(code: string, filename = 'file.tsx'): Finding[] {
  return analyzeFile(
    filename,
    code,
    builtinRules.map((rule) => ({ rule, level: 'error' as const })),
  ).findings;
}

export function ruleIds(code: string, filename?: string): string[] {
  return analyze(code, filename).map((f) => f.ruleId);
}

const created: string[] = [];

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** Creates a temporary directory with the given files; removed after each test. */
export function tempProject(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'frontguard-'));
  created.push(root);
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

export const FIXTURE_PROJECT = join(import.meta.dirname, 'fixtures', 'project');
