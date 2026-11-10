import { describe, expect, it } from 'vitest';
import { scan } from '../src/core/scan.ts';
import { FIXTURE_PROJECT, tempProject } from './helpers.ts';

describe('scan()', () => {
  it('scans a mixed project end to end', async () => {
    const result = await scan({
      cwd: FIXTURE_PROJECT,
      config: { dependencies: { offline: true } },
    });

    const byFile = (file: string) =>
      result.findings.filter((f) => f.file === file).map((f) => f.ruleId);

    expect(byFile('src/Profile.vue').sort()).toEqual(['FG-AUTH-001', 'FG-XSS-005']);
    expect(byFile('src/Comment.svelte').sort()).toEqual(['FG-CFG-004', 'FG-XSS-009']);
    // lodash from jsDelivr and the http:// stylesheet lack integrity; React has it.
    expect(byFile('index.html').sort()).toEqual(['FG-CFG-002', 'FG-CFG-003', 'FG-CFG-003']);
    expect(byFile('vite.config.ts')).toEqual(['FG-CFG-001']);
    expect(byFile('src/safe.ts')).toEqual([]);
    expect(byFile('src/xss-vulnerable.tsx')).toEqual(
      expect.arrayContaining([
        'FG-XSS-001',
        'FG-XSS-002',
        'FG-XSS-003',
        'FG-XSS-004',
        'FG-XSS-008',
      ]),
    );
    expect(result.filesScanned).toBe(8);
    expect(result.findings.every((f) => !f.file.includes('\\'))).toBe(true);
  });

  it('sorts findings by severity, then file and line', async () => {
    const result = await scan({
      cwd: FIXTURE_PROJECT,
      config: { dependencies: { offline: true } },
    });
    const ranks = result.findings.map((f) =>
      ['info', 'low', 'medium', 'high', 'critical'].indexOf(f.severity),
    );
    expect(ranks).toEqual([...ranks].sort((a, b) => b - a));
  });

  it('honours categories, rule levels and excludes', async () => {
    const root = tempProject({
      'src/a.ts': 'eval(x);\nel.innerHTML = y;\nlocalStorage.setItem("token", t);',
      'src/generated/b.ts': 'eval(z);',
    });
    const result = await scan({
      cwd: root,
      config: {
        categories: { auth: false, dependencies: false },
        rules: { 'no-inner-html': 'off', 'FG-XSS-002': 'warn' },
        exclude: ['src/generated/**'],
      },
    });
    expect(result.findings.map((f) => [f.ruleId, f.level])).toEqual([['FG-XSS-002', 'warn']]);
  });

  it('skips the default excludes and oversized files', async () => {
    const root = tempProject({
      'node_modules/lib/index.js': 'eval(x)',
      'dist/app.js': 'eval(x)',
      'src/app.test.ts': 'eval(x)',
      'src/big.js': `eval(x);${' '.repeat(2048)}`,
    });
    const result = await scan({
      cwd: root,
      config: { maxFileSize: 1024, dependencies: { offline: true } },
    });
    expect(result.findings).toEqual([]);
  });
});
