import { describe, it, expect, beforeAll } from 'vitest';
import { SecretsScanner } from '../../src/scanners/secrets/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

const createFile = (content: string, path = 'test.ts'): FileContent => ({
  path,
  content,
  lines: content.split('\n'),
});

// Runtime-constructed tokens to avoid triggering GitHub push protection
const FAKE_GHP = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
const FAKE_GHP_SHORT = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh';
const FAKE_STRIPE = ['sk', 'test', '0'.repeat(22) + 'FG'].join('_');
const FAKE_SLACK = ['xoxb', '0000000000', '0000000000', 'FrontGuardExampleTokenXX'].join('-');
const FAKE_SK_LIVE = 'sk_' + 'live_super_secret_key_value_here_1234';

describe('SecretsScanner', () => {
  const scanner = new SecretsScanner();
  let config: FrontGuardConfig;

  beforeAll(() => {
    scanner.init();
    config = getDefaultConfig();
  });

  it('detects AWS access key', () => {
    const file = createFile(`const key = "AKIAIOSFODNN7EXAMPLE";`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-SEC-001');
  });

  it('detects AWS secret access key', () => {
    const file = createFile(
      `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-SEC-001');
  });

  it('detects GitHub personal access token', () => {
    const file = createFile(
      `const token = "${FAKE_GHP}";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'FG-SEC-002')).toBe(true);
  });

  it('detects Stripe secret key', () => {
    const file = createFile(
      `const stripe = "${FAKE_STRIPE}";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-SEC-002');
  });

  it('detects Slack bot token', () => {
    const file = createFile(
      `const slack = "${FAKE_SLACK}";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-SEC-002');
  });

  it('detects generic API key pattern', () => {
    const file = createFile(
      `const apiKey = "${FAKE_SK_LIVE}";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects RSA private key', () => {
    const file = createFile(`const key = "-----BEGIN RSA PRIVATE KEY-----";`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-SEC-003');
  });

  it('detects OpenSSH private key', () => {
    const file = createFile(
      `const pk = "-----BEGIN OPENSSH PRIVATE KEY-----";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-SEC-003');
  });

  it('detects hardcoded JWT token', () => {
    const file = createFile(
      `const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'FG-SEC-004')).toBe(true);
  });

  it('detects PostgreSQL connection string', () => {
    const file = createFile(
      `const db = "postgresql://admin:password123@db.example.com/mydb";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'FG-SEC-005')).toBe(true);
  });

  it('detects MongoDB connection string', () => {
    const file = createFile(
      `const mongo = "mongodb+srv://user:pass@cluster.mongodb.net/app";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'FG-SEC-005')).toBe(true);
  });

  it('detects high-entropy strings', () => {
    const file = createFile(
      `const token = "a8K3mZ9xR2vL5nQ7wE1tY4uI6oP0sD3fGhJkBnMcXzV";`,
    );
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.ruleId === 'FG-SEC-006')).toBe(true);
  });

  it('produces no findings for safe code', () => {
    const file = createFile(`
const greeting = 'Hello, world!';
const count = 42;
const items = ['apple', 'banana', 'cherry'];
const config = { debug: false, verbose: true };
export function add(a: number, b: number): number {
  return a + b;
}
`);
    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('skips binary/asset file extensions', () => {
    const file = createFile(
      `AKIAIOSFODNN7EXAMPLE`,
      'assets/image.png',
    );
    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('detects multiple secrets in one file', () => {
    const file = createFile(`
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const ghToken = "${FAKE_GHP_SHORT}";
const pk = "-----BEGIN RSA PRIVATE KEY-----";
`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThanOrEqual(3);
  });

  it('reports correct line numbers', () => {
    const file = createFile(`const x = 1;\nconst y = 2;\nconst key = "AKIAIOSFODNN7EXAMPLE";`);
    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].line).toBe(3);
  });
});
