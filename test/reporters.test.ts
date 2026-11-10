import { describe, expect, it } from 'vitest';
import { scan } from '../src/core/scan.ts';
import { toConsole, toHtml, toJson, toSarif } from '../src/reporters/index.ts';
import type { ScanResult } from '../src/types.ts';
import { tempProject } from './helpers.ts';

async function scanCode(files: Record<string, string>): Promise<ScanResult> {
  const root = tempProject(files);
  return scan({ cwd: root, config: { dependencies: { offline: true } } });
}

describe('reporters', () => {
  it('HTML report cannot be broken out of by scanned code', async () => {
    const payload = '</script><img src=x onerror=alert(1)>';
    const result = await scanCode({ 'src/a.js': `const s = "${payload}";\nel.innerHTML = s;` });
    const html = toHtml(result);
    expect(result.findings).toHaveLength(1);
    expect(html).not.toContain(payload);
    expect(html.match(/<\/script>/g)).toHaveLength(1);
  });

  it('SARIF uses relative URIs, rule indexes and GitHub security-severity', async () => {
    const result = await scanCode({ 'src/nested/a.ts': 'eval(x)' });
    const sarif = JSON.parse(toSarif(result));
    const run = sarif.runs[0];
    const [res] = run.results;
    expect(sarif.version).toBe('2.1.0');
    expect(res.locations[0].physicalLocation.artifactLocation).toEqual({
      uri: 'src/nested/a.ts',
      uriBaseId: 'SRCROOT',
    });
    expect(run.tool.driver.rules[res.ruleIndex].id).toBe('FG-XSS-002');
    expect(res.properties['security-severity']).toBe('9.5');
    expect(res.partialFingerprints['frontguard/v1']).toMatch(/^[0-9a-f]{32}$/);
  });

  it('JSON has a versioned schema and summary', async () => {
    const result = await scanCode({ 'a.ts': 'eval(x)' });
    const json = JSON.parse(toJson(result));
    expect(json.schemaVersion).toBe(1);
    expect(json.summary).toEqual({
      total: 1,
      bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    });
  });

  it('console output has no ANSI codes when color is off', async () => {
    const result = await scanCode({ 'a.ts': 'eval(x)' });
    const text = toConsole(result, { color: false });
    expect(text).toContain('a.ts:1:1');
    expect(text).toContain('✖ 1 issue (1 critical)');
    // eslint-disable-next-line no-control-regex
    expect(text).not.toMatch(/\u001b\[/);
  });
});
