import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { EXIT, run, type CliIO } from '../src/cli/index.ts';
import { tempProject } from './helpers.ts';

function io(cwd: string) {
  const out: string[] = [];
  const err: string[] = [];
  const value: CliIO = {
    cwd,
    color: false,
    interactive: false,
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
  };
  return { io: value, out, err, stdout: () => out.join('\n'), stderr: () => err.join('\n') };
}

const VULNERABLE = { 'src/a.ts': 'eval(userCode);' };

describe('cli', () => {
  it('exits 1 when findings meet the threshold, 0 otherwise', async () => {
    const root = tempProject(VULNERABLE);
    const t = io(root);
    expect(await run(['--offline'], t.io)).toBe(EXIT.findings);
    expect(t.stdout()).toContain('src/a.ts:1:1');
    expect(await run(['--offline', '--fail-on', 'none'], io(root).io)).toBe(EXIT.ok);
  });

  it('treats warn-level rules as non-failing', async () => {
    const root = tempProject({
      ...VULNERABLE,
      '.frontguardrc.json': '{ "rules": { "no-eval": "warn" } }',
    });
    expect(await run(['--offline'], io(root).io)).toBe(EXIT.ok);
  });

  it('scans a target directory and writes reports', async () => {
    const root = tempProject({ 'app/src/a.ts': 'eval(x)' });
    const t = io(root);
    const code = await run(['scan', 'app', '--offline', '-r', 'json,sarif', '-o', 'reports'], t.io);
    expect(code).toBe(EXIT.findings);
    expect(existsSync(join(root, 'reports', 'frontguard-report.json'))).toBe(true);
    const sarif = JSON.parse(
      readFileSync(join(root, 'reports', 'frontguard-report.sarif'), 'utf8'),
    );
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
      'src/a.ts',
    );
    expect(t.stdout()).toBe('');
  });

  it('exits 2 on usage and config errors', async () => {
    const root = tempProject({ '.frontguardrc.json': '{ "failOn": "urgent" }' });
    const t = io(root);
    expect(await run(['--offline'], t.io)).toBe(EXIT.error);
    expect(t.stderr()).toContain('failOn');

    expect(await run(['-r', 'pdf'], io(root).io)).toBe(EXIT.error);
    expect(await run(['missing-dir'], io(root).io)).toBe(EXIT.error);
  });

  it('init sets up a project non-interactively', async () => {
    const root = tempProject({
      'package.json': '{\n    "name": "app",\n    "scripts": { "build": "vite build" }\n}\n',
      'pnpm-lock.yaml': "lockfileVersion: '9.0'\n",
      '.gitignore': 'node_modules',
      '.git/HEAD': 'ref: refs/heads/main',
    });
    const t = io(root);
    const exec = vi.fn(() => Promise.resolve(0));
    t.io.init = { stdout: t.io.stdout, stderr: t.io.stderr, confirm: vi.fn(), exec };

    expect(await run(['init'], t.io)).toBe(EXIT.ok);
    expect(exec).toHaveBeenCalledWith(
      'pnpm',
      ['add', '--save-dev', '@juliocarneiro/frontguard'],
      root,
    );

    const pkg = readFileSync(join(root, 'package.json'), 'utf8');
    expect(JSON.parse(pkg).scripts).toEqual({ build: 'vite build', security: 'frontguard' });
    expect(pkg).toContain('\n    "name"');
    expect(readFileSync(join(root, 'frontguard.config.ts'), 'utf8')).toContain('defineConfig');
    expect(readFileSync(join(root, '.gitignore'), 'utf8')).toBe(
      'node_modules\nfrontguard-report/\n',
    );
    const workflow = readFileSync(join(root, '.github/workflows/frontguard.yml'), 'utf8');
    expect(workflow).toContain('pnpm exec frontguard --reporter console,sarif');
    expect(workflow).toContain('upload-sarif');
    expect(t.stdout()).toContain('Next: run `pnpm security`');

    // Second run is idempotent and keeps existing files.
    const again = io(root);
    again.io.init = { ...t.io.init, stdout: again.io.stdout };
    expect(await run(['init', '--no-install'], again.io)).toBe(EXIT.ok);
    expect(again.stdout()).toContain('already exists');
  });

  it('init without a package.json writes a JSON config and uses npx', async () => {
    const root = tempProject({});
    const t = io(root);
    const exec = vi.fn(() => Promise.resolve(0));
    t.io.init = { stdout: t.io.stdout, stderr: t.io.stderr, confirm: vi.fn(), exec };
    expect(await run(['init', '--no-ci'], t.io)).toBe(EXIT.ok);
    expect(exec).not.toHaveBeenCalled();
    expect(existsSync(join(root, '.frontguardrc.json'))).toBe(true);
    expect(t.stdout()).toContain('npx @juliocarneiro/frontguard');
  });

  it('init asks before each step when interactive', async () => {
    const root = tempProject({ 'package.json': '{}', '.git/HEAD': '' });
    const t = io(root);
    t.io.interactive = true;
    const confirm = vi.fn(() => Promise.resolve(false));
    const exec = vi.fn(() => Promise.resolve(0));
    t.io.init = { stdout: t.io.stdout, stderr: t.io.stderr, confirm, exec };
    expect(await run(['init'], t.io)).toBe(EXIT.ok);
    expect(confirm).toHaveBeenCalledTimes(3);
    expect(exec).not.toHaveBeenCalled();
    expect(existsSync(join(root, '.github'))).toBe(false);
  });

  it('lists rules and prints the version', async () => {
    const t = io(tempProject({}));
    expect(await run(['rules', '--json'], t.io)).toBe(EXIT.ok);
    const ids = (JSON.parse(t.stdout()) as { id: string }[]).map((r) => r.id);
    expect(ids).toContain('FG-XSS-001');
    expect(ids).toContain('FG-DEP-001');

    const v = io(tempProject({}));
    expect(await run(['--version'], v.io)).toBe(EXIT.ok);
    expect(v.stdout()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
