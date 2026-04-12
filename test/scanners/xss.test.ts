import { describe, it, expect, beforeAll } from 'vitest';
import { XSSScanner } from '../../src/scanners/xss/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

const createFile = (content: string, path = 'test.tsx'): FileContent => ({
  path,
  content,
  lines: content.split('\n'),
});

describe('XSSScanner', () => {
  const scanner = new XSSScanner();
  let config: FrontGuardConfig;

  beforeAll(() => {
    scanner.init();
    config = getDefaultConfig();
  });

  it('detects innerHTML assignment', () => {
    const file = createFile(
      `const el = document.getElementById('app');\nel.innerHTML = userInput;`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-001');
  });

  it('detects eval() call', () => {
    const file = createFile(`const result = eval(userCode);`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-002');
  });

  it('detects new Function() constructor', () => {
    const file = createFile(`const fn = new Function('return ' + expr);`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-002');
  });

  it('detects setTimeout with string argument', () => {
    const file = createFile(`setTimeout('alert(1)', 100);`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-002');
  });

  it('detects document.write()', () => {
    const file = createFile(`document.write('<h1>' + title + '</h1>');`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-003');
  });

  it('detects document.writeln()', () => {
    const file = createFile(`document.writeln(htmlContent);`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-003');
  });

  it('detects React dangerouslySetInnerHTML', () => {
    const file = createFile(
      `const Component = () => <div dangerouslySetInnerHTML={{ __html: data }} />;`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-004');
  });

  it('detects Vue v-html directive', () => {
    const file = createFile(
      `<template>\n  <div v-html="rawHtml"></div>\n</template>`,
      'component.vue',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-005');
  });

  it('detects Angular bypassSecurityTrustHtml', () => {
    const file = createFile(
      `const safe = this.sanitizer.bypassSecurityTrustHtml(userInput);`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-006');
  });

  it('detects Angular bypassSecurityTrustUrl', () => {
    const file = createFile(
      `const url = this.sanitizer.bypassSecurityTrustUrl(untrustedUrl);`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-006');
  });

  it('detects outerHTML assignment', () => {
    const file = createFile(
      `const el = document.querySelector('.target');\nel.outerHTML = markup;`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-007');
  });

  it('detects javascript: URL in string', () => {
    const file = createFile(
      `const link = "javascript:alert('xss')";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-008');
  });

  it('detects javascript: URL in JSX href', () => {
    const file = createFile(
      `const el = <a href="javascript:void(0)">Click</a>;`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'FG-XSS-008')).toBe(true);
  });

  it('produces no findings for safe code', () => {
    const file = createFile(`
import React from 'react';

const App = () => {
  const text = 'Hello, world!';
  return <div>{text}</div>;
};

export default App;
`);
    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('detects multiple vulnerabilities in one file', () => {
    const file = createFile(`
const el = document.getElementById('x');
el.innerHTML = input;
eval(code);
document.write(html);
`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThanOrEqual(3);
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).toContain('FG-XSS-001');
    expect(ruleIds).toContain('FG-XSS-002');
    expect(ruleIds).toContain('FG-XSS-003');
  });

  it('reports correct file path in findings', () => {
    const file = createFile(
      `el.innerHTML = data;`,
      'src/components/Widget.tsx',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings[0].file).toBe('src/components/Widget.tsx');
  });
});
