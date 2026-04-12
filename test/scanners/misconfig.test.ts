import { describe, it, expect, beforeAll } from 'vitest';
import { MisconfigScanner } from '../../src/scanners/misconfig/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

const createFile = (content: string, path = 'test.ts'): FileContent => ({
  path,
  content,
  lines: content.split('\n'),
});

describe('MisconfigScanner', () => {
  const scanner = new MisconfigScanner();
  let config: FrontGuardConfig;

  beforeAll(() => {
    scanner.init();
    config = getDefaultConfig();
  });

  it('detects sourceMappingURL comment', () => {
    const file = createFile(
      `//# sourceMappingURL = bundle.js.map`,
      'dist/bundle.js',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-001');
  });

  it('detects devtool source-map in webpack config', () => {
    const file = createFile(
      `module.exports = { devtool: 'source-map' };`,
      'webpack.config.js',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-001');
  });

  it('detects sourceMap: true in config', () => {
    const file = createFile(
      `const config = { sourceMap: true };`,
      'build.config.ts',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-001');
  });

  it('detects mixed content via HTTP src attribute', () => {
    const file = createFile(
      `<script src="http://cdn.example.com/lib.js"></script>`,
      'index.html',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-002');
  });

  it('detects mixed content via fetch with HTTP URL', () => {
    const file = createFile(
      `fetch("http://api.external.com/data");`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-002');
  });

  it('does not flag localhost HTTP as mixed content', () => {
    const file = createFile(
      `fetch("http://localhost:3000/api/health");`,
    );
    const findings = scanner.scanFile(file, config);
    const mixedContentFindings = findings.filter(f => f.ruleId === 'FG-CFG-002');
    expect(mixedContentFindings).toHaveLength(0);
  });

  it('detects CDN script without integrity attribute', () => {
    const file = createFile(
      `<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>`,
      'index.html',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-003');
  });

  it('detects CDN link without integrity attribute', () => {
    const file = createFile(
      `<link href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css" rel="stylesheet">`,
      'index.html',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CFG-003');
  });

  it('does not flag CDN resource with integrity attribute', () => {
    const file = createFile(
      `<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" integrity="sha384-abc123" crossorigin="anonymous"></script>`,
      'index.html',
    );
    const findings = scanner.scanFile(file, config);
    const cdnFindings = findings.filter(f => f.ruleId === 'FG-CFG-003');
    expect(cdnFindings).toHaveLength(0);
  });

  it('produces no findings for safe code', () => {
    const file = createFile(`
import React from 'react';

export const App = () => {
  return <div>Safe application</div>;
};
`);
    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('reports correct line numbers', () => {
    const file = createFile(
      `const a = 1;\nconst b = 2;\nsourceMap: true`,
      'config.js',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].line).toBe(3);
  });

  it('detects multiple misconfigurations in one file', () => {
    const file = createFile(
      `//# sourceMappingURL = app.js.map\n<script src="http://cdn.example.com/lib.js"></script>\n<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>`,
      'index.html',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });
});
