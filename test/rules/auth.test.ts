import { describe, expect, it } from 'vitest';
import { analyze, ruleIds } from '../helpers.ts';

describe('FG-AUTH-001 no-token-in-web-storage', () => {
  it.each([
    'localStorage.setItem("token", t)',
    'localStorage.setItem("authToken", t)',
    'sessionStorage.setItem("refresh_token", t)',
    'window.localStorage.setItem(`jwt`, t)',
    'localStorage.accessToken = t',
    'localStorage["id-token"] = t',
  ])('reports %s', (code) => {
    expect(ruleIds(code, 'a.ts')).toEqual(['FG-AUTH-001']);
  });

  it('ignores non-sensitive keys', () => {
    expect(ruleIds('localStorage.setItem("theme", "dark")', 'a.ts')).toEqual([]);
    expect(ruleIds('localStorage.setItem("tokenizerMode", "x")', 'a.ts')).toEqual([]);
  });
});

describe('FG-AUTH-002 no-token-in-url', () => {
  it('reports credentials in query strings', () => {
    expect(ruleIds('fetch(`/api?token=${t}`)', 'a.ts')).toEqual(['FG-AUTH-002']);
    expect(ruleIds('const u = "https://x.io/a?api_key=" + k;', 'a.ts')).toEqual(['FG-AUTH-002']);
    expect(ruleIds('const u = "https://maps.example.com/?key=public";', 'a.ts')).toEqual([]);
  });
});

describe('FG-AUTH-003 no-hardcoded-credentials', () => {
  it('reports hardcoded passwords and secrets', () => {
    // Split so the repository does not contain a scannable password assignment.
    const secret = 'Xk9#' + 'mQ2$vL7p';
    const findings = analyze(`const dbPassword = "${secret}";`, 'a.ts');
    expect(findings.map((f) => f.ruleId)).toContain('FG-AUTH-003');
    expect(findings.find((f) => f.ruleId === 'FG-AUTH-003')?.snippet).not.toContain(secret);
    expect(ruleIds('const cfg = { clientSecret: "aZ3kQ9mX2vL8pW4t" };', 'a.ts')).toContain(
      'FG-AUTH-003',
    );
  });

  it('ignores labels, placeholders and env lookups', () => {
    expect(ruleIds('const passwordLabel = "Enter your password";', 'a.ts')).toEqual([]);
    expect(ruleIds('const password = "";', 'a.ts')).toEqual([]);
    expect(ruleIds('const cfg = { password: process.env.PW };', 'a.ts')).toEqual([]);
  });
});
