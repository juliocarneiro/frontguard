#!/usr/bin/env node
// `npm create frontguard` / `pnpm create frontguard` / `yarn create frontguard` / `bun create frontguard`
// Runs `frontguard init` in the current directory, forwarding any flags (e.g. --yes, --no-ci).
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const pkgPath = require.resolve('frontguard/package.json');
const { bin } = require(pkgPath);
const cli = join(dirname(pkgPath), typeof bin === 'string' ? bin : bin.frontguard);

const { status } = spawnSync(process.execPath, [cli, 'init', ...process.argv.slice(2)], {
  stdio: 'inherit',
});
process.exitCode = status ?? 1;
