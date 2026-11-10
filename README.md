# FrontGuard

[![npm](https://img.shields.io/npm/v/frontguard.svg)](https://www.npmjs.com/package/frontguard)
[![CI](https://github.com/juliocarneiro/frontguard/actions/workflows/ci.yml/badge.svg)](https://github.com/juliocarneiro/frontguard/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/frontguard.svg)](./LICENSE)
[![node](https://img.shields.io/node/v/frontguard.svg)](https://nodejs.org)

**Static security scanner for frontend code.** FrontGuard finds XSS sinks, leaked secrets, insecure
auth patterns, misconfigurations and vulnerable dependencies in React, Vue, Svelte, Angular and plain
JS/TS projects, and reports them in your terminal, as JSON, as an HTML dashboard or as SARIF for
GitHub code scanning.

```sh
npx frontguard
```

No install, no account, no code leaves your machine. The only network call is the optional
dependency lookup on [OSV.dev](https://osv.dev), which sends package names and versions only.

## Contents

- [Quick start](#quick-start)
- [What it finds](#what-it-finds)
- [CLI](#cli)
- [Configuration](#configuration)
- [Suppressing findings](#suppressing-findings)
- [CI / GitHub code scanning](#ci--github-code-scanning)
- [Programmatic API and custom rules](#programmatic-api-and-custom-rules)
- [How it works](#how-it-works)

## Quick start

| Goal                                           | Command                 |
| ---------------------------------------------- | ----------------------- |
| Scan the current directory, nothing to install | `npx frontguard`        |
| Set up a project (install, config, script, CI) | `npm create frontguard` |
| Same setup, from an existing install           | `npx frontguard init`   |

`npm create frontguard` (or `pnpm create`, `yarn create`, `bun create`) runs an interactive setup that:

1. installs `frontguard` as a devDependency with your package manager,
2. creates `frontguard.config.ts`,
3. adds a `security` script to `package.json`,
4. adds a GitHub Actions workflow that uploads results to the **Security** tab,
5. ignores `frontguard-report/` in `.gitignore`.

Every step asks first and is skipped if it is already done. Use `--yes` to accept the defaults.

Requires Node.js 22.18 or later.

## What it finds

| Category     | Examples                                                                                                                                                   |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XSS          | dynamic `innerHTML`, `eval` / `new Function`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `bypassSecurityTrust*`, `javascript:` URLs |
| Secrets      | 130+ provider token formats (AWS, GitHub, Stripe, OpenAI, Slack…), private keys, JWTs, database URLs, high-entropy strings                                 |
| Auth         | tokens in `localStorage`/`sessionStorage`, credentials in URLs, hardcoded passwords                                                                        |
| Misconfig    | public source maps in build configs, `http://`/`ws://` resources, third-party scripts without SRI, `postMessage(…, '*')`                                   |
| Dependencies | known advisories for the exact versions in your lockfile (npm, pnpm, yarn v1/berry, bun)                                                                   |

See [docs/rules.md](./docs/rules.md) for every rule, with severity, CWE/OWASP mapping and how to fix it.

FrontGuard is tuned for frontend code: keys that are public by design (Stripe publishable keys,
Sentry DSNs, Supabase anon keys…) are not reported, static assignments like `el.innerHTML = ''`
are ignored, and secrets are always masked in every report.

## CLI

```text
frontguard [scan] [dir]   scan a directory (default: .)
  -c, --config <path>       config file
  -r, --reporter <list>     console,json,sarif,html (default: console)
  -o, --output-dir <dir>    where json/sarif/html reports go (default: <dir>/frontguard-report)
      --fail-on <severity>  critical | high | medium | low | info | none (default: high)
      --categories <list>   only run xss,secrets,auth,misconfig,dependencies
      --include-dev         also audit devDependencies
      --offline             skip the OSV.dev lookup
  -q, --quiet               only warnings and the summary
      --open                write the HTML report and open it

frontguard init           interactive project setup (--yes, --json, --no-install, --no-ci, --pm)
frontguard rules [--json] list rules
frontguard report [dir]   open a generated HTML report
```

Exit codes: `0` no blocking findings, `1` findings at or above `--fail-on`, `2` usage or config error.

## Configuration

FrontGuard looks for `frontguard.config.ts`, `.mts`, `.js`, `.mjs` or `.frontguardrc.json` in the
scanned directory, then in the current directory. Configs are validated; typos and invalid values
fail with a clear message.

```ts
// frontguard.config.ts
import { defineConfig } from 'frontguard';

export default defineConfig({
  failOn: 'high',
  reporters: ['console', 'sarif'],
  exclude: ['src/legacy/**'],
  categories: { dependencies: true },
  rules: {
    'FG-SEC-006': 'warn', // by id...
    'no-javascript-url': 'off', // ...or by name
  },
  dependencies: { includeDev: false },
});
```

| Option             | Default                                                   | Description                                                                              |
| ------------------ | --------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `include`          | JS/TS, Vue, Svelte, HTML, Astro                           | globs to scan                                                                            |
| `exclude`          | `[]`                                                      | extra globs to skip, added to the defaults (node_modules, build output, tests, fixtures) |
| `noDefaultExclude` | `false`                                                   | drop the default excludes                                                                |
| `maxFileSize`      | `1048576`                                                 | bytes; larger files are skipped                                                          |
| `categories`       | all `true`                                                | enable/disable `xss`, `secrets`, `auth`, `misconfig`, `dependencies`                     |
| `rules`            | `{}`                                                      | `off` / `warn` / `error` by rule id or name; `warn` never fails the scan                 |
| `customRules`      | `[]`                                                      | rules created with `defineRule()`                                                        |
| `failOn`           | `'high'`                                                  | lowest severity that exits with `1`; `'none'` never fails                                |
| `reporters`        | `['console']`                                             | `console`, `json`, `sarif`, `html`                                                       |
| `outputDir`        | `'frontguard-report'`                                     | report directory, relative to the scanned directory                                      |
| `dependencies`     | `{ includeDev: false, offline: false, timeoutMs: 15000 }` | dependency audit options                                                                 |

TypeScript configs are loaded with Node's built-in type stripping, so they can use type annotations
but not `enum` or `namespace`.

## Suppressing findings

Comments work in any syntax (`//`, `/* */`, `<!-- -->`, `#`):

```js
// frontguard-ignore-next-line FG-XSS-001
el.innerHTML = trustedTemplate;

const hash = 'q8ZtR2vX9mK4pL7wN3sB6yH1'; // frontguard-ignore-line FG-SEC-006

/* frontguard-ignore-file no-eval */
```

Without a rule list, all rules are suppressed for that scope.

## CI / GitHub code scanning

`frontguard init` writes this workflow for you:

```yaml
name: FrontGuard
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: 22
      - run: npx --yes frontguard@latest --reporter console,sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: ${{ !cancelled() }}
        with:
          sarif_file: frontguard-report/frontguard-report.sarif
          category: frontguard
```

SARIF results use paths relative to the repository, stable fingerprints and GitHub's
`security-severity`, so alerts are deduplicated across runs and ranked correctly.

## Programmatic API and custom rules

```ts
import { defineRule, scan, toSarif } from 'frontguard';

const noAlert = defineRule({
  meta: {
    id: 'ACME-001',
    name: 'no-alert',
    title: 'alert() call',
    description: 'alert() blocks the UI thread.',
    remediation: 'Use the design-system dialog.',
    severity: 'low',
    category: 'misconfig',
  },
  // Return Babel visitors; all rules share a single parse and traversal per file.
  create: (context) => ({
    CallExpression({ node }) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'alert' && node.loc) {
        context.report({ line: node.loc.start.line, column: node.loc.start.column + 1 });
      }
    },
  }),
});

const result = await scan({ cwd: 'apps/web', config: { customRules: [noAlert] } });
console.log(result.findings.length, toSarif(result));
```

Rules can also inspect `context.text` / `context.lines` directly for non-JS patterns.

## How it works

- Files are discovered with fast globbing, read in parallel and parsed once with Babel. Vue,
  Svelte, Astro and HTML files have their `<script>` blocks extracted in place, so reported lines
  and columns always point at the original file.
- Every AST rule contributes visitors to a single merged traversal, ESLint style.
- Dependency versions come from your lockfile, including transitive packages; dev-only packages are
  classified by walking the dependency graph. Advisories, severities (GHSA or computed CVSS 3.x)
  and fixed versions come from OSV.dev.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security issues: see [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE)
