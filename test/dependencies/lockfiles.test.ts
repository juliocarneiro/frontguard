import { describe, expect, it } from 'vitest';
import {
  findPackageLine,
  packagesFromManifest,
  readLockfile,
} from '../../src/dependencies/lockfiles.ts';
import { tempProject } from '../helpers.ts';

const manifest = {
  dependencies: { app: '^1.0.0' },
  devDependencies: { tool: '^2.0.0' },
};

function summary(root: string) {
  const lock = readLockfile(root, manifest)!;
  return Object.fromEntries(lock.packages.map((p) => [`${p.name}@${p.version}`, p.dev]));
}

describe('lockfile parsers', () => {
  it('npm v3', () => {
    const root = tempProject({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'x' },
          'node_modules/app': { version: '1.2.0' },
          'node_modules/app/node_modules/shared': { version: '1.0.0' },
          'node_modules/tool': { version: '2.1.0', dev: true },
          'node_modules/@scope/pkg': { version: '3.0.0', devOptional: true },
          'packages/local': { version: '0.0.1', link: true },
        },
      }),
    });
    expect(summary(root)).toEqual({
      'app@1.2.0': false,
      'shared@1.0.0': false,
      'tool@2.1.0': true,
      '@scope/pkg@3.0.0': true,
    });
  });

  it('pnpm v9 follows the snapshot graph from importers', () => {
    const root = tempProject({
      'pnpm-lock.yaml': `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      app:
        specifier: ^1.0.0
        version: 1.2.0(react@19.0.0)
    devDependencies:
      tool:
        specifier: ^2.0.0
        version: 2.1.0
packages:
  app@1.2.0:
    resolution: {integrity: x}
snapshots:
  app@1.2.0(react@19.0.0):
    dependencies:
      shared: 1.0.0
  shared@1.0.0: {}
  tool@2.1.0:
    dependencies:
      shared: 1.0.0
      only-dev: 4.0.0
  only-dev@4.0.0: {}
`,
    });
    expect(summary(root)).toEqual({
      'app@1.2.0': false,
      'shared@1.0.0': false,
      'tool@2.1.0': true,
      'only-dev@4.0.0': true,
    });
  });

  it('yarn v1', () => {
    const root = tempProject({
      'yarn.lock': `# yarn lockfile v1

app@^1.0.0:
  version "1.2.0"
  resolved "https://registry.yarnpkg.com/app/-/app-1.2.0.tgz"
  dependencies:
    shared "^1.0.0"

"@scope/shared@^1.0.0", shared@^1.0.0:
  version "1.0.3"

tool@^2.0.0:
  version "2.1.0"
`,
    });
    expect(summary(root)).toEqual({
      'app@1.2.0': false,
      '@scope/shared@1.0.3': false,
      'tool@2.1.0': true,
    });
  });

  it('yarn berry', () => {
    const root = tempProject({
      'yarn.lock': `__metadata:
  version: 8

"app@npm:^1.0.0":
  version: 1.2.0
  dependencies:
    shared: "npm:^1.0.0"

"shared@npm:^1.0.0":
  version: 1.0.3

"tool@npm:^2.0.0":
  version: 2.1.0

"x@workspace:.":
  version: 0.0.0-use.local
`,
    });
    expect(summary(root)).toEqual({
      'app@1.2.0': false,
      'shared@1.0.3': false,
      'tool@2.1.0': true,
    });
  });

  it('bun.lock resolves nested keys', () => {
    const root = tempProject({
      'bun.lock': `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "x", "dependencies": { "app": "^1.0.0", }, "devDependencies": { "tool": "^2.0.0" } },
  },
  "packages": {
    "app": ["app@1.2.0", "", { "dependencies": { "shared": "^2.0.0" } }, "sha512-a"],
    "app/shared": ["shared@2.0.0", "", {}, "sha512-b"],
    "shared": ["shared@1.0.0", "", {}, "sha512-c"],
    "tool": ["tool@2.1.0", "", { "dependencies": { "shared": "^1.0.0" } }, "sha512-d"],
  },
}`,
    });
    expect(summary(root)).toEqual({
      'app@1.2.0': false,
      'shared@2.0.0': false,
      'shared@1.0.0': true,
      'tool@2.1.0': true,
    });
  });
});

describe('fallbacks', () => {
  it('uses package.json lower bounds without a lockfile', () => {
    expect(
      packagesFromManifest({
        dependencies: { a: '^1.2.3', b: 'workspace:*', c: '~2.0.0-beta.1' },
        devDependencies: { d: '>=3.0.0 <4' },
      }),
    ).toEqual([
      { name: 'a', version: '1.2.3', dev: false },
      { name: 'c', version: '2.0.0-beta.1', dev: false },
      { name: 'd', version: '3.0.0', dev: true },
    ]);
  });

  it('finds the declaring line', () => {
    const lines = ['{', '  "node_modules/app": {', '    "version": "1.2.0"'];
    expect(findPackageLine(lines, 'app', '1.2.0')).toBe(2);
    expect(findPackageLine(lines, 'missing', '1.0.0')).toBe(1);
  });
});
