import { describe, expect, it } from 'vitest';
import { analyze, ruleIds } from '../helpers.ts';

// Split literals so the repository itself does not contain scannable secrets.
const AWS_KEY = 'AKIA' + 'Q3EGRDKFHJ7LXNP4';
const GH_TOKEN = 'ghp_' + 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5';
const STRIPE_LIVE = 'sk_live_' + '51Hx3kQ2eZvKYlo2C9dLs8mPq';
const JWT =
  'eyJhbGciOiJIUzI1NiJ9' +
  '.eyJzdWIiOiIxMjM0NTY3ODkwIn0' +
  '.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
const PG_URL = 'postgres://admin:' + 'Pa55w0rd' + '@db.internal:5432/app';
const RSA_HEADER = '-----BEGIN RSA ' + 'PRIVATE KEY-----';

describe('secrets rules', () => {
  it('detects provider tokens', () => {
    expect(ruleIds(`const k = "${AWS_KEY}";`, 'a.ts')).toEqual(['FG-SEC-001']);
    expect(ruleIds(`const t = "${GH_TOKEN}";`, 'a.ts')).toEqual(['FG-SEC-002']);
    expect(analyze(`const s = "${STRIPE_LIVE}";`, 'a.ts')[0]).toMatchObject({
      ruleId: 'FG-SEC-002',
      message: 'API key or token exposed: Stripe Secret Key (Live)',
    });
  });

  it('detects private keys, JWTs and connection strings', () => {
    expect(ruleIds(`const k = \`${RSA_HEADER}\`;`, 'a.ts')).toContain('FG-SEC-003');
    expect(ruleIds(`const t = "${JWT}";`, 'a.ts')).toEqual(['FG-SEC-004']);
    expect(ruleIds(`const db = "${PG_URL}";`, 'a.ts')).toEqual(['FG-SEC-005']);
  });

  it('still reports provider tokens inside comments', () => {
    expect(ruleIds(`// old key: ${GH_TOKEN}`, 'a.ts')).toEqual(['FG-SEC-002']);
  });

  it('does not report browser-safe keys or placeholders', () => {
    expect(ruleIds('const pk = "pk_live_51HxxxxPublishableKeyThatIsSafeToShip";', 'a.ts')).toEqual(
      [],
    );
    expect(ruleIds('const password = "your-password-here";', 'a.ts')).toEqual([]);
    expect(ruleIds('const apiKey = process.env.API_KEY;', 'a.ts')).toEqual([]);
  });

  it('reports Google browser keys as low severity', () => {
    const key = 'AIza' + 'SyD3kF9xQ2mN7pL4rT8vW1yZ5bC6eH0jK2s';
    expect(analyze(`const maps = "${key}";`, 'a.ts')[0]?.severity).toBe('low');
  });

  it('masks secrets in every snippet, including context lines', () => {
    const code = `const a = "${GH_TOKEN}";\nconst b = "${STRIPE_LIVE}";`;
    const findings = analyze(code, 'a.ts');
    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.snippet).not.toContain(GH_TOKEN);
      expect(finding.snippet).not.toContain(STRIPE_LIVE);
    }
  });

  it('masks the secret without eating delimiters and points at its first character', () => {
    const [finding] = analyze(`const k = "${AWS_KEY}";`, 'a.ts');
    expect(finding).toMatchObject({ column: 12 });
    expect(finding!.snippet).toMatch(/const k = "AKIA\*+";$/);
  });

  it('masks the body of PEM private keys', () => {
    const body = 'MIIBogIBAAJBALRiMLAHudeSA' + 'x3hB2f2NRkJLA0EXAMPLE';
    const code = `const k = \`${RSA_HEADER}\n${body}\n-----END RSA PRIVATE KEY-----\`;`;
    const [finding] = analyze(code, 'a.ts');
    expect(finding?.ruleId).toBe('FG-SEC-003');
    expect(finding!.snippet).not.toContain(body);
  });

  it('drops the entropy finding when a specific secret rule already fired on the line', () => {
    expect(ruleIds(`const s = "${STRIPE_LIVE}";`, 'a.ts')).toEqual(['FG-SEC-002']);
  });

  it('reports unknown high-entropy strings', () => {
    expect(ruleIds('const blob = "q8ZtR2vX9mK4pL7wN3sB6yH1cF5jD0gA";', 'a.ts')).toEqual([
      'FG-SEC-006',
    ]);
    expect(ruleIds('<div className="q8ZtR2vX9mK4pL7wN3sB6yH1cF5jD0gA" />')).toEqual([]);
  });
});
