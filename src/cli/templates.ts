import type { PackageManager } from './init.ts';

const TS_TEMPLATE = `import { defineConfig } from '@juliocarneiro/frontguard';

export default defineConfig({
  // Lowest severity that makes \`frontguard\` exit with code 1: critical | high | medium | low | info | none
  failOn: 'high',

  // Reporters: console (stdout), json, sarif, html (written to outputDir)
  reporters: ['console'],
  outputDir: 'frontguard-report',

  // Extra globs to skip, on top of node_modules, build output, tests and fixtures
  exclude: [],

  // Turn whole categories off
  categories: { xss: true, secrets: true, auth: true, misconfig: true, dependencies: true },

  // Per-rule levels by id or name: 'off' | 'warn' | 'error'
  rules: {
    // 'FG-SEC-006': 'warn',
  },

  dependencies: {
    includeDev: false,
    offline: false,
  },
});
`;

const JSON_TEMPLATE = `${JSON.stringify(
  {
    failOn: 'high',
    reporters: ['console'],
    exclude: [],
    rules: {},
    dependencies: { includeDev: false, offline: false },
  },
  null,
  2,
)}\n`;

export function configTemplate(format: 'ts' | 'json'): string {
  return format === 'ts' ? TS_TEMPLATE : JSON_TEMPLATE;
}

const SETUP: Record<PackageManager, string> = {
  npm: `      - uses: actions/setup-node@v5
        with:
          node-version: 22
          cache: npm
      - run: npm ci`,
  pnpm: `      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v5
        with:
          node-version: 22
          cache: pnpm
      - run: pnpm install --frozen-lockfile`,
  yarn: `      - uses: actions/setup-node@v5
        with:
          node-version: 22
          cache: yarn
      - run: yarn install --immutable`,
  bun: `      - uses: oven-sh/setup-bun@v2
      - run: bun install --frozen-lockfile`,
};

const EXEC: Record<PackageManager, string> = {
  npm: 'npx frontguard',
  pnpm: 'pnpm exec frontguard',
  yarn: 'yarn frontguard',
  bun: 'bunx frontguard',
};

/** GitHub Actions workflow: scans on push/PR and uploads SARIF to code scanning. */
export function workflowTemplate(pm: PackageManager, installed: boolean): string {
  const setup = installed
    ? SETUP[pm]
    : `      - uses: actions/setup-node@v5
        with:
          node-version: 22`;
  const command = installed ? EXEC[pm] : 'npx --yes @juliocarneiro/frontguard@latest';
  return `name: FrontGuard

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
${setup}
      - name: Scan
        run: ${command} --reporter console,sarif
      - name: Upload results to GitHub code scanning
        if: \${{ !cancelled() }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: frontguard-report/frontguard-report.sarif
          category: frontguard
`;
}
