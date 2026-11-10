/**
 * Publish step of the release workflow (`pnpm release`), replacing `changeset publish`.
 *
 * `changeset publish` shells out to `pnpm publish`, which does not perform the npm trusted
 * publishing (OIDC) token exchange, so the registry rejects the upload as anonymous (E404 on
 * PUT). Instead, each package is packed with `pnpm pack` (which rewrites `workspace:` ranges)
 * and the tarball is published with the npm CLI (>= 11.5.1), which handles OIDC and attaches
 * provenance automatically. Versions already on the registry are skipped, so re-running a
 * failed release is safe. `changeset tag` then creates the git tags; its "New tag:" lines are
 * what changesets/action reads to push tags and create GitHub releases.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Dependencies first: create-frontguard depends on frontguard.
const PACKAGE_DIRS = ['.', 'packages/create-frontguard'];

const run = (cmd: string, args: string[], cwd = '.') =>
  execFileSync(cmd, args, { cwd, stdio: 'inherit', shell: process.platform === 'win32' });

function isPublished(name: string, version: string): boolean {
  try {
    const out = execFileSync('npm', ['view', `${name}@${version}`, 'version'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      shell: process.platform === 'win32',
    });
    return out.trim() === version;
  } catch {
    return false;
  }
}

const outDir = mkdtempSync(join(tmpdir(), 'frontguard-publish-'));

for (const dir of PACKAGE_DIRS) {
  const { name, version } = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
    name: string;
    version: string;
  };
  if (isPublished(name, version)) {
    console.log(`${name}@${version} is already on npm, skipping`);
    continue;
  }
  const before = new Set(readdirSync(outDir));
  run('pnpm', ['pack', '--pack-destination', outDir], dir);
  const tarball = readdirSync(outDir).find((file) => !before.has(file));
  if (!tarball) throw new Error(`pnpm pack produced no tarball for ${name}`);
  run('npm', ['publish', join(outDir, tarball), '--access', 'public', '--provenance']);
}

run('pnpm', ['changeset', 'tag']);
