import { describe, expect, it, vi } from 'vitest';
import { auditDependencies } from '../../src/dependencies/audit.ts';
import { cvss3BaseScore } from '../../src/dependencies/cvss.ts';
import { fixedVersionFor, severityOf } from '../../src/dependencies/osv.ts';
import { compareVersions } from '../../src/dependencies/semver.ts';
import { tempProject } from '../helpers.ts';

const OPTIONS = { includeDev: false, offline: false, timeoutMs: 1000 };

const LODASH_ADVISORY = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { severity: 'HIGH' },
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
    },
  ],
};

function mockOsv(vulnsByPackage: Record<string, string[]>) {
  return vi.fn((url: string | URL | Request, init?: RequestInit) => {
    const href = url instanceof Request ? url.url : url.toString();
    if (href.endsWith('/querybatch')) {
      const body = JSON.parse(init?.body as string) as { queries: { package: { name: string } }[] };
      return Promise.resolve(
        Response.json({
          results: body.queries.map((q) => ({
            vulns: (vulnsByPackage[q.package.name] ?? []).map((id) => ({ id })),
          })),
        }),
      );
    }
    return Promise.resolve(Response.json(LODASH_ADVISORY));
  });
}

describe('auditDependencies', () => {
  const project = () =>
    tempProject({
      'package.json': JSON.stringify({
        dependencies: { lodash: '4.17.15' },
        devDependencies: { tool: '1.0.0' },
      }),
      'package-lock.json': JSON.stringify(
        {
          lockfileVersion: 3,
          packages: {
            '': {},
            'node_modules/lodash': { version: '4.17.15' },
            'node_modules/tool': { version: '1.0.0', dev: true },
          },
        },
        null,
        2,
      ),
    });

  it('reports advisories with severity, CVE and fixed version', async () => {
    const fetch = mockOsv({ lodash: ['GHSA-35jh-r3h4-6jhm'], tool: ['GHSA-35jh-r3h4-6jhm'] });
    const { findings, warnings } = await auditDependencies(project(), OPTIONS, fetch);
    expect(warnings).toEqual([]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'FG-DEP-001',
      severity: 'high',
      file: 'package-lock.json',
      line: 5,
      message: 'lodash@4.17.15: Command Injection in lodash (GHSA-35jh-r3h4-6jhm, CVE-2021-23337)',
      data: { fixedIn: '4.17.21' },
    });
    const queried = JSON.parse(fetch.mock.calls[0]![1]?.body as string) as { queries: unknown[] };
    expect(queried.queries).toHaveLength(1);
  });

  it('includes devDependencies on request', async () => {
    const fetch = mockOsv({ tool: ['GHSA-35jh-r3h4-6jhm'] });
    const { findings } = await auditDependencies(
      project(),
      { ...OPTIONS, includeDev: true },
      fetch,
    );
    expect(findings.map((f) => f.data?.package)).toEqual(['tool']);
  });

  it('turns network failures into a warning', async () => {
    const fetch = vi.fn(() => Promise.reject(new Error('getaddrinfo ENOTFOUND')));
    const { findings, warnings } = await auditDependencies(project(), OPTIONS, fetch);
    expect(findings).toEqual([]);
    expect(warnings[0]).toMatch(/OSV\.dev request failed/);
  });

  it('does nothing offline', async () => {
    const fetch = vi.fn();
    await auditDependencies(project(), { ...OPTIONS, offline: true }, fetch);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('OSV helpers', () => {
  it('derives severity from GHSA labels or CVSS vectors', () => {
    expect(severityOf({ id: 'x', database_specific: { severity: 'MODERATE' } })).toBe('medium');
    expect(
      severityOf({
        id: 'x',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      }),
    ).toBe('critical');
    expect(severityOf({ id: 'x' })).toBe('medium');
  });

  it('picks the fix of the range containing the version', () => {
    const vuln = {
      id: 'x',
      affected: [
        {
          package: { name: 'p', ecosystem: 'npm' },
          ranges: [
            {
              type: 'SEMVER',
              events: [
                { introduced: '0' },
                { fixed: '1.5.0' },
                { introduced: '2.0.0' },
                { fixed: '2.3.1' },
              ],
            },
          ],
        },
      ],
    };
    expect(fixedVersionFor(vuln, 'p', '1.2.0')).toBe('1.5.0');
    expect(fixedVersionFor(vuln, 'p', '2.1.0')).toBe('2.3.1');
    expect(fixedVersionFor(vuln, 'p', '1.7.0')).toBeUndefined();
  });

  it('computes CVSS 3.x base scores', () => {
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(6.1);
    expect(cvss3BaseScore('CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N')).toBe(0);
    expect(cvss3BaseScore('CVSS:4.0/AV:N')).toBeNull();
  });

  it('compares versions with SemVer precedence', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBe(1);
    expect(compareVersions('1.0.0-beta.2', '1.0.0-beta.10')).toBe(-1);
    expect(compareVersions('1.0.0-rc.1', '1.0.0')).toBe(-1);
    expect(compareVersions('2.0.0', '2.0.0')).toBe(0);
  });
});
