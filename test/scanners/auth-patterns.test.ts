import { describe, it, expect, beforeAll } from 'vitest';
import { AuthPatternsScanner } from '../../src/scanners/auth-patterns/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

const createFile = (content: string, path = 'test.ts'): FileContent => ({
  path,
  content,
  lines: content.split('\n'),
});

describe('AuthPatternsScanner', () => {
  const scanner = new AuthPatternsScanner();
  let config: FrontGuardConfig;

  beforeAll(() => {
    scanner.init();
    config = getDefaultConfig();
  });

  it('detects localStorage.setItem with token key', () => {
    const file = createFile(`localStorage.setItem('token', authResponse.jwt);`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-001');
  });

  it('detects sessionStorage.setItem with jwt key', () => {
    const file = createFile(
      `sessionStorage.setItem('jwt', response.token);`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-001');
  });

  it('detects localStorage.setItem with access_token key', () => {
    const file = createFile(
      `localStorage.setItem('access_token', data.accessToken);`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-001');
  });

  it('detects token in URL query parameter', () => {
    const file = createFile(
      `const url = "https://api.example.com/data?token=abc123";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-002');
  });

  it('detects api_key in URL query parameter', () => {
    const file = createFile(
      `fetch("https://api.service.com/v1/users?api_key=mykey123");`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-002');
  });

  it('detects token in template literal URL', () => {
    const file = createFile(
      'const endpoint = `https://api.example.com?access_token=${token}`;',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-002');
  });

  it('detects hardcoded password variable', () => {
    const file = createFile(`const password = "supersecret123";`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-003');
  });

  it('detects hardcoded secret in object property', () => {
    const file = createFile(`const config = { secret: "myAppSecret" };`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-003');
  });

  it('detects hardcoded secretKey assignment', () => {
    const file = createFile(`const secretKey = "abcdef123456";`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-AUTH-003');
  });

  it('produces no findings for safe code', () => {
    const file = createFile(`
import { getToken } from './auth';

const token = getToken();
const headers = { Authorization: \`Bearer \${token}\` };

fetch('https://api.example.com/data', { headers });
`);
    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('does not flag non-sensitive localStorage keys', () => {
    const file = createFile(
      `localStorage.setItem('theme', 'dark');`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('reports correct severity for hardcoded credentials', () => {
    const file = createFile(`const password = "secret";`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('critical');
  });
});
