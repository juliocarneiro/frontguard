<div align="center">

# FrontGuard

**Static security scanner for frontend code.**

Finds XSS sinks, leaked secrets, insecure auth patterns, misconfigurations and vulnerable
dependencies in React, Vue, Svelte, Angular, Astro and plain JavaScript/TypeScript projects.

[![npm](https://img.shields.io/npm/v/@juliocarneiro/frontguard?color=1f6feb&logo=npm)](https://www.npmjs.com/package/@juliocarneiro/frontguard)
[![CI](https://github.com/juliocarneiro/frontguard/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/juliocarneiro/frontguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/juliocarneiro/frontguard)](./LICENSE)
[![Node](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fjuliocarneiro%2Ffrontguard%2Fmain%2Fpackage.json&query=%24.engines.node&label=node&color=339933)](https://nodejs.org)
[![Types](https://img.shields.io/badge/types-included-3178c6)](./src/index.ts)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-6e40c9)](#sarif)

```sh
npx @juliocarneiro/frontguard
```

</div>

FrontGuard reads your source files, parses them once, runs 23 security rules over them and reports
what it finds in the terminal, as JSON, as an HTML dashboard or as SARIF for GitHub code scanning.
It runs locally: no account, no upload, no telemetry. The only network request is the optional
dependency lookup on [OSV.dev](https://osv.dev), which sends package names and versions only.

```text
 CRITICAL  Dynamic code execution: eval() FG-XSS-002
  src/utils/parse.ts:12:10

    10 | export function parse(input: string) {
    11 |   // legacy format support
  > 12 |   return eval(`(${input})`);
    13 | }

  Fix: Remove eval and new Function. Parse data with JSON.parse and pass functions, not strings, to timers.
  CWE-95 · A03:2021 - Injection

✖ 33 issues (9 critical, 14 high, 8 medium, 2 low) · 8 files in 0.06s
```

---

## Contents

- [Why FrontGuard](#why-frontguard)
- [Installation](#installation)
- [Quick start](#quick-start)
- [What it detects](#what-it-detects)
  - [Rule catalog](#rule-catalog)
  - [Framework support](#framework-support)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
  - [Config files](#config-files)
  - [All options](#all-options)
  - [Severity, levels and exit codes](#severity-levels-and-exit-codes)
  - [Recipes per framework](#recipes-per-framework)
- [Suppressing findings](#suppressing-findings)
- [Reports](#reports)
  - [Console](#console)
  - [JSON](#json)
  - [SARIF](#sarif)
  - [HTML dashboard](#html-dashboard)
- [Dependency audit](#dependency-audit)
- [Secrets: what is and is not reported](#secrets-what-is-and-is-not-reported)
- [CI and git hooks](#ci-and-git-hooks)
- [Programmatic API](#programmatic-api)
- [Writing custom rules](#writing-custom-rules)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [FAQ](#faq)
- [Contributing, security and license](#contributing-security-and-license)

---

## Why FrontGuard

General-purpose linters and SAST tools are built for servers or for every language at once.
Frontend code has its own failure modes, and its own false positives:

- **Everything you bundle is public.** A secret in a React component is a leaked secret. But a
  Stripe publishable key or a Sentry DSN is _meant_ to be public, and a tool that flags them trains
  you to ignore it. FrontGuard knows the difference.
- **Frameworks hide code in templates.** `v-html`, `{@html}`, `dangerouslySetInnerHTML` and
  `bypassSecurityTrustHtml` are the XSS sinks that matter in modern apps. FrontGuard reads `.vue`,
  `.svelte`, `.astro` and `.html` files and reports the exact line and column in the original file.
- **Your lockfile is the truth.** `package.json` says `^4.17.0`; your users run whatever the lockfile
  pinned. FrontGuard audits the exact installed versions, transitive packages included.
- **Reports must not become the leak.** Every secret is masked in every output format.

It is fast (one parse per file, all rules in one traversal), has two runtime concepts to learn
(rules and config), and needs zero setup to try.

## Installation

Requires **Node.js 22.18 or later** (or 24.11+).

| Use case                  | Command                                                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Try it, nothing installed | `npx @juliocarneiro/frontguard`                                                                                            |
| Set up a project (guided) | `npm create @juliocarneiro/frontguard`                                                                                     |
| Add to a project manually | `npm install --save-dev @juliocarneiro/frontguard`                                                                         |
| pnpm / yarn / bun         | `pnpm add -D @juliocarneiro/frontguard` · `yarn add -D @juliocarneiro/frontguard` · `bun add -d @juliocarneiro/frontguard` |
| Global install            | `npm install --global @juliocarneiro/frontguard`                                                                           |

> The package is published under a scope, `@juliocarneiro/frontguard`, because npm reserves
> names too similar to existing packages. Once installed, the command is simply `frontguard`
> (`npx frontguard`, `"security": "frontguard"`, `pnpm exec frontguard`).

### Guided setup

`npm create @juliocarneiro/frontguard` (also `pnpm create @juliocarneiro/frontguard`, `yarn create @juliocarneiro/frontguard`,
`bun create @juliocarneiro/frontguard`) runs `frontguard init` in the current directory:

1. detects your package manager (lockfile, `packageManager` field, then the invoking tool);
2. installs `@juliocarneiro/frontguard` as a devDependency;
3. writes `frontguard.config.ts` (or `.frontguardrc.json` when the package is not installed locally);
4. adds `"security": "frontguard"` to your `package.json` scripts, keeping your indentation;
5. writes `.github/workflows/frontguard.yml`, which uploads results to the repository's **Security** tab;
6. adds `frontguard-report/` to `.gitignore`.

Every step asks first, defaults are sensible, and steps that are already done are skipped, so it is
safe to run again. Non-interactive: `npm create @juliocarneiro/frontguard -- --yes`. All flags are listed in the
[CLI reference](#frontguard-init).

## Quick start

```sh
# scan the current directory
npx @juliocarneiro/frontguard

# scan another directory
npx @juliocarneiro/frontguard apps/web

# only XSS and secrets, fail on medium or worse
npx @juliocarneiro/frontguard --categories xss,secrets --fail-on medium

# write an HTML dashboard and open it
npx @juliocarneiro/frontguard --open

# CI: SARIF for GitHub code scanning, no network
npx @juliocarneiro/frontguard --reporter console,sarif --offline
```

The process exits with `1` when at least one finding is at or above `--fail-on` (default `high`),
so it can gate a pull request without any extra tooling.

## What it detects

### Rule catalog

23 rules in 5 categories. Every rule has a stable id (never reused), a short name, a default
severity, a CWE mapping and a concrete fix. Full descriptions: [docs/rules.md](./docs/rules.md).

| ID                   | Name                            | Severity      | Catches                                                                                                                                             |
| -------------------- | ------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **XSS**              |                                 |               |                                                                                                                                                     |
| FG-XSS-001           | `no-inner-html`                 | high          | `el.innerHTML = value` / `outerHTML` with a dynamic value (static strings are ignored)                                                              |
| FG-XSS-002           | `no-eval`                       | critical      | `eval`, `new Function`, `Function()`, string arguments to `setTimeout`/`setInterval`                                                                |
| FG-XSS-003           | `no-document-write`             | high          | `document.write()` / `document.writeln()`                                                                                                           |
| FG-XSS-004           | `no-dangerously-set-inner-html` | high          | React `dangerouslySetInnerHTML`, in JSX or `createElement` props                                                                                    |
| FG-XSS-005           | `no-v-html`                     | high          | Vue `v-html` in templates                                                                                                                           |
| FG-XSS-006           | `no-bypass-security-trust`      | critical      | Angular `DomSanitizer.bypassSecurityTrust*()`                                                                                                       |
| FG-XSS-007           | `no-html-sink-call`             | high          | Dynamic HTML passed to `insertAdjacentHTML`, `createContextualFragment`, `setHTMLUnsafe`                                                            |
| FG-XSS-008           | `no-javascript-url`             | medium        | `javascript:` URLs in strings, templates and `href`/`src`/`action` attributes                                                                       |
| FG-XSS-009           | `no-svelte-html`                | high          | Svelte `{@html ...}`                                                                                                                                |
| **Secrets**          |                                 |               |                                                                                                                                                     |
| FG-SEC-001           | `no-aws-credentials`            | critical      | AWS access keys, secret keys, session tokens                                                                                                        |
| FG-SEC-002           | `no-api-tokens`                 | high          | 100+ provider token formats (GitHub, Stripe secret keys, OpenAI, Anthropic, Slack, GitLab, npm, Twilio, SendGrid…) and hardcoded passwords/API keys |
| FG-SEC-003           | `no-private-keys`               | critical      | PEM private keys (RSA, EC, DSA, OpenSSH, PGP, PKCS#8)                                                                                               |
| FG-SEC-004           | `no-hardcoded-jwt`              | high          | JSON Web Tokens in source                                                                                                                           |
| FG-SEC-005           | `no-connection-strings`         | critical      | Database URLs with credentials (Postgres, MySQL, MongoDB, Redis, MSSQL, JDBC)                                                                       |
| FG-SEC-006           | `no-high-entropy-strings`       | medium        | Long random-looking strings not matched by a specific pattern                                                                                       |
| **Auth**             |                                 |               |                                                                                                                                                     |
| FG-AUTH-001          | `no-token-in-web-storage`       | high          | Tokens/JWTs/session ids written to `localStorage` or `sessionStorage`                                                                               |
| FG-AUTH-002          | `no-token-in-url`               | high          | Credentials in query strings (`?token=`, `?api_key=`, `#access_token=`…)                                                                            |
| FG-AUTH-003          | `no-hardcoded-credentials`      | critical      | String literals assigned to `password`, `secret`, `clientSecret`, `privateKey`…                                                                     |
| **Misconfiguration** |                                 |               |                                                                                                                                                     |
| FG-CFG-001           | `no-public-sourcemaps`          | medium        | `sourcemap: true`, `devtool: 'source-map'`, `productionBrowserSourceMaps` in build configs                                                          |
| FG-CFG-002           | `no-mixed-content`              | medium        | `http://` scripts, styles, images, `fetch`/`axios` calls and `ws://` sockets (localhost excluded)                                                   |
| FG-CFG-003           | `require-sri`                   | low           | Third-party `<script>` and stylesheets without an `integrity` hash                                                                                  |
| FG-CFG-004           | `no-wildcard-postmessage`       | medium        | `postMessage(data, '*')`                                                                                                                            |
| **Dependencies**     |                                 |               |                                                                                                                                                     |
| FG-DEP-001           | `no-vulnerable-dependencies`    | from advisory | Installed versions with a published advisory on OSV.dev                                                                                             |

List them from the terminal with `frontguard rules` (or `frontguard rules --json`).

### Framework support

| File type                  | What is analyzed                                                                                                                                                           |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.js` `.mjs` `.cjs` `.jsx` | Whole file, parsed with JSX support                                                                                                                                        |
| `.ts` `.mts` `.cts`        | Whole file, TypeScript + decorators (Angular components, services)                                                                                                         |
| `.tsx`                     | Whole file, TypeScript + JSX (React, Solid, Preact…)                                                                                                                       |
| `.vue`                     | Every `<script>` / `<script setup>` block (`lang="ts"` respected) + `v-html` in the template                                                                               |
| `.svelte`                  | Every `<script>` block + `{@html}` in markup                                                                                                                               |
| `.astro`                   | `<script>` blocks                                                                                                                                                          |
| `.html` `.htm`             | Inline `<script>` blocks (JSON/template script types skipped), external `<script>`/`<link>` tags, resource URLs                                                            |
| Build configs              | `vite`, `webpack`, `rollup`, `rolldown`, `rspack`, `rsbuild`, `next`, `nuxt`, `svelte`, `astro`, `tsdown`, `tsup`, `vue`, `quasar`, `craco` configs for public source maps |
| Lockfiles                  | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 and berry), `bun.lock`                                                                       |

Script blocks are extracted **in place**: everything outside them is blanked while preserving line
breaks, so a finding at line 42 of a `.vue` file is at line 42 of that file.

## CLI reference

```text
frontguard [command] [options]
```

`scan` is the default command, so `frontguard` and `frontguard scan` are equivalent.

### `frontguard scan [dir]`

Scans `dir` (default: the current directory).

| Option                   | Description                                                                              | Default                   |
| ------------------------ | ---------------------------------------------------------------------------------------- | ------------------------- |
| `-c, --config <path>`    | Config file to use instead of auto-discovery                                             | auto                      |
| `-r, --reporter <list>`  | Comma-separated: `console`, `json`, `sarif`, `html`                                      | `console`                 |
| `-o, --output-dir <dir>` | Where `json`/`sarif`/`html` reports are written (relative to the current directory)      | `<dir>/frontguard-report` |
| `--fail-on <severity>`   | Lowest severity that exits with `1`: `critical`, `high`, `medium`, `low`, `info`, `none` | `high`                    |
| `--categories <list>`    | Only run these: `xss`, `secrets`, `auth`, `misconfig`, `dependencies`                    | all                       |
| `--include-dev`          | Also audit packages only reachable from `devDependencies`                                | off                       |
| `--offline`              | Skip the OSV.dev lookup (no network at all)                                              | off                       |
| `-q, --quiet`            | Print only warnings and the summary line                                                 | off                       |
| `--open`                 | Write the HTML report and open it in the browser                                         | off                       |
| `--no-color`             | Disable colors                                                                           | auto                      |

Report files are named `frontguard-report.json`, `frontguard-report.sarif` and
`frontguard-report.html`. CLI flags override the config file.

### `frontguard init`

Guided project setup (see [Guided setup](#guided-setup)).

| Option            | Description                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------ |
| `-y, --yes`       | Accept every default, no prompts (automatic outside an interactive terminal or when `CI` is set) |
| `--ts` / `--json` | Force `frontguard.config.ts` or `.frontguardrc.json`                                             |
| `--pm <name>`     | Package manager: `npm`, `pnpm`, `yarn`, `bun`                                                    |
| `--no-install`    | Do not install the package                                                                       |
| `--no-script`     | Do not add the `security` script                                                                 |
| `--no-ci`         | Do not create the GitHub Actions workflow                                                        |
| `-f, --force`     | Overwrite existing config/workflow files                                                         |

### `frontguard rules`

Prints every rule with id, severity, name and title. `--json` prints the full metadata.

### `frontguard report [dir]`

Opens `dir/frontguard-report.html` (default `frontguard-report/`) in the default browser.

### Global options and environment

|                 |                                                 |
| --------------- | ----------------------------------------------- |
| `-v, --version` | Print the version                               |
| `-h, --help`    | Help for any command (`frontguard scan --help`) |
| `NO_COLOR`      | Disable colors                                  |
| `FORCE_COLOR`   | Force colors even when stdout is not a TTY      |
| `CI`            | Disables the spinner and the `init` prompts     |

### Exit codes

| Code | Meaning                                                               |
| ---- | --------------------------------------------------------------------- |
| `0`  | No `error`-level finding at or above `failOn`                         |
| `1`  | At least one `error`-level finding at or above `failOn`               |
| `2`  | Usage error, invalid config, unreadable target, or unexpected failure |

## Configuration

Everything works without a config file. Add one to tune severity gates, rules and paths.

### Config files

FrontGuard looks in the **scanned directory**, then in the **current directory**, for the first of:

1. `frontguard.config.ts`
2. `frontguard.config.mts`
3. `frontguard.config.js`
4. `frontguard.config.mjs`
5. `.frontguardrc.json`

`--config <path>` skips discovery. Configs are validated against a schema: unknown keys, typos and
invalid values stop the scan with a precise message instead of being silently ignored.

```ts
// frontguard.config.ts
import { defineConfig } from '@juliocarneiro/frontguard';

export default defineConfig({
  failOn: 'high',
  reporters: ['console', 'sarif'],
  exclude: ['src/legacy/**', '**/*.stories.tsx'],
  rules: {
    'FG-SEC-006': 'warn', // by id
    'no-javascript-url': 'off', // or by name
  },
  dependencies: { includeDev: false },
});
```

```json
// .frontguardrc.json
{
  "failOn": "medium",
  "categories": { "dependencies": false },
  "rules": { "no-high-entropy-strings": "off" }
}
```

TypeScript configs are loaded with Node's built-in type stripping: type annotations, `satisfies`
and `import type` work; `enum` and `namespace` do not. A `.ts`/`.js` config that imports
`defineConfig` needs FrontGuard installed in the project; when you only run it through `npx`, use
`.frontguardrc.json` (this is what `frontguard init` picks automatically).

### All options

| Option                    | Type                                                            | Default                                                              | Description                                                          |
| ------------------------- | --------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `include`                 | `string[]`                                                      | `['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts,vue,svelte,html,htm,astro}']` | Globs, relative to the scanned directory                             |
| `exclude`                 | `string[]`                                                      | `[]`                                                                 | Extra globs to skip, added to the defaults below                     |
| `noDefaultExclude`        | `boolean`                                                       | `false`                                                              | Drop the default exclude list                                        |
| `maxFileSize`             | `number`                                                        | `1048576`                                                            | Bytes. Larger files are skipped (almost always generated)            |
| `categories`              | `{ xss?, secrets?, auth?, misconfig?, dependencies?: boolean }` | all `true`                                                           | Turn whole categories on or off                                      |
| `rules`                   | `Record<string, 'off' \| 'warn' \| 'error'>`                    | `{}`                                                                 | Per-rule level, keyed by id (`FG-XSS-001`) or name (`no-inner-html`) |
| `customRules`             | `Rule[]`                                                        | `[]`                                                                 | Your own rules, created with [`defineRule`](#writing-custom-rules)   |
| `failOn`                  | `'critical' \| 'high' \| 'medium' \| 'low' \| 'info' \| 'none'` | `'high'`                                                             | Lowest severity that exits with `1`                                  |
| `reporters`               | `('console' \| 'json' \| 'sarif' \| 'html')[]`                  | `['console']`                                                        | Outputs to produce                                                   |
| `outputDir`               | `string`                                                        | `'frontguard-report'`                                                | Report directory, relative to the scanned directory                  |
| `dependencies.includeDev` | `boolean`                                                       | `false`                                                              | Audit dev-only packages too                                          |
| `dependencies.offline`    | `boolean`                                                       | `false`                                                              | Never call OSV.dev                                                   |
| `dependencies.timeoutMs`  | `number`                                                        | `15000`                                                              | Timeout per OSV.dev request                                          |

**Default excludes:** `node_modules`, `.git`, `dist`, `build`, `out`, `coverage`, `.next`, `.nuxt`,
`.output`, `.svelte-kit`, `.astro`, `.vercel`, `.turbo`, `storybook-static`, `frontguard-report`,
`*.min.js`, `*.min.css`, `*.d.ts`, `*.test.*`, `*.spec.*` and `test`, `tests`, `__tests__`,
`__mocks__`, `fixtures`, `__fixtures__` directories. Binary files are always skipped.

### Severity, levels and exit codes

Two independent ideas:

- **Severity** (`critical` > `high` > `medium` > `low` > `info`) says how bad a finding is. Each
  rule has a default; secret patterns and dependency advisories set it per finding (a Google
  browser key is `low`, a Stripe live secret key is `high`, an advisory takes its GHSA/CVSS score).
- **Level** (`error` or `warn`, per rule) says whether the finding can fail the build.

The scan fails when a finding has level `error` **and** severity at or above `failOn`. Use `warn`
to keep a rule visible in reports while you clean up, and `off` to disable it.

### Recipes per framework

<details>
<summary><b>Next.js</b></summary>

```ts
export default defineConfig({
  exclude: ['public/**', 'next-env.d.ts'],
  // next.config.* is scanned for productionBrowserSourceMaps
});
```

</details>

<details>
<summary><b>Vite + React / Vue / Svelte</b></summary>

```ts
export default defineConfig({
  include: ['src/**/*.{ts,tsx,js,jsx,vue,svelte}', 'index.html', 'vite.config.*'],
});
```

</details>

<details>
<summary><b>Nuxt / SvelteKit / Astro</b></summary>

The default `include` already covers `.vue`, `.svelte` and `.astro`, and `.nuxt`, `.output`,
`.svelte-kit` and `.astro` build folders are excluded by default. Usually no config is needed.

</details>

<details>
<summary><b>Angular</b></summary>

```ts
export default defineConfig({
  include: ['src/**/*.ts', 'src/index.html'],
  // Angular sanitizes [innerHTML] bindings itself; FrontGuard reports the
  // bypassSecurityTrust* calls that switch that protection off.
});
```

</details>

<details>
<summary><b>Monorepo</b></summary>

Scan each app from its own directory so its lockfile and config are used:

```sh
npx @juliocarneiro/frontguard apps/web
npx @juliocarneiro/frontguard apps/admin
```

Or scan the root with excludes for apps you do not ship. The dependency audit reads the lockfile at
the scanned root; workspace packages (`workspace:`, `link:`) are skipped.

</details>

## Suppressing findings

Inline comments work in any comment syntax (`//`, `/* */`, `<!-- -->`, `#`) and accept rule ids or
names, comma-separated. Without a list, every rule is suppressed for that scope.

```ts
// frontguard-ignore-next-line FG-XSS-001
el.innerHTML = sanitizedByDomPurify;

const checksum = 'q8ZtR2vX9mK4pL7wN3sB6yH1'; // frontguard-ignore-line no-high-entropy-strings

/* frontguard-ignore-file no-eval, FG-XSS-003 */
```

```html
<!-- frontguard-ignore-next-line require-sri -->
<script src="https://cdn.example.com/widget.js"></script>
```

For broader exceptions use `exclude` globs, `rules: { id: 'off' }`, or `rules: { id: 'warn' }`.

## Reports

### Console

Default output: one block per finding (severity, message, rule id, `file:line:column`, a code
snippet with the line marked `>`, the fix and CWE/OWASP references), then warnings and a summary.
`--quiet` keeps only warnings and the summary. Colors follow `NO_COLOR`/`FORCE_COLOR` and TTY
detection.

### JSON

`--reporter json` writes `frontguard-report.json`. The format is versioned: `schemaVersion` only
changes on breaking changes.

```json
{
  "schemaVersion": 1,
  "tool": { "name": "frontguard", "version": "0.1.0" },
  "startedAt": "2026-11-10T13:00:00.000Z",
  "durationMs": 412,
  "filesScanned": 128,
  "summary": {
    "total": 2,
    "bySeverity": { "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 }
  },
  "findings": [
    {
      "ruleId": "FG-DEP-001",
      "ruleName": "no-vulnerable-dependencies",
      "severity": "high",
      "level": "error",
      "category": "dependencies",
      "title": "Vulnerable dependency",
      "message": "lodash@4.17.15: Command Injection in lodash (GHSA-35jh-r3h4-6jhm, CVE-2021-23337)",
      "description": "An installed package version has a published security advisory (source: OSV.dev).",
      "remediation": "Upgrade lodash to 4.17.21 or later. Details: https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
      "file": "package-lock.json",
      "line": 17,
      "column": 1,
      "snippet": "> 17 |     \"node_modules/lodash\": {",
      "cwe": "CWE-1395",
      "owasp": "A06:2021 - Vulnerable and Outdated Components",
      "data": {
        "package": "lodash",
        "version": "4.17.15",
        "dev": false,
        "advisory": "GHSA-35jh-r3h4-6jhm",
        "aliases": ["CVE-2021-23337"],
        "fixedIn": "4.17.21",
        "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"
      }
    }
  ],
  "warnings": []
}
```

| Finding field                | Description                                                                                    |
| ---------------------------- | ---------------------------------------------------------------------------------------------- |
| `ruleId`, `ruleName`         | Stable id and short name                                                                       |
| `severity`                   | Effective severity of this finding                                                             |
| `level`                      | `error` (can fail the scan) or `warn`                                                          |
| `category`                   | `xss`, `secrets`, `auth`, `misconfig`, `dependencies`                                          |
| `title` / `message`          | Rule title / title plus detail (provider, sink, package…)                                      |
| `description`, `remediation` | Why it matters and how to fix it                                                               |
| `file`, `line`, `column`     | Path relative to the scanned directory (forward slashes), 1-based position                     |
| `snippet`                    | Two lines of context around the hit; secrets masked                                            |
| `cwe`, `owasp`               | References, when applicable                                                                    |
| `data`                       | Extra structured data (dependency findings: package, version, advisory, aliases, fixedIn, url) |

### SARIF

`--reporter sarif` writes a SARIF 2.1.0 log ready for
[GitHub code scanning](https://docs.github.com/code-security/code-scanning) and any SARIF viewer:

- `artifactLocation.uri` is relative to the repository with a `SRCROOT` base, so alerts link to files;
- `partialFingerprints` keep alerts stable across runs when unrelated lines move;
- each rule and result carries GitHub's `security-severity` (critical 9.5, high 8.0, medium 5.5, low 3.0) so alerts are ranked correctly;
- rule help links point to [docs/rules.md](./docs/rules.md), tags include `security` and `external/cwe/cwe-*`.

### HTML dashboard

`--reporter html` (or `--open`) writes a single self-contained `frontguard-report.html`: summary
cards, a severity donut, findings per category, filters by severity and category, full-text search,
sorting, a rules table, light/dark theme and CSV export. It works offline and every value from the
scanned code is escaped, so a malicious file cannot inject markup into the report.

## Dependency audit

When the `dependencies` category is on (default), FrontGuard:

1. finds the lockfile in the scanned directory: `package-lock.json`, `npm-shrinkwrap.json`,
   `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic v1 and berry), or `bun.lock`;
2. lists **every installed package version**, transitive ones included, and drops workspace/linked
   packages;
3. classifies dev-only packages: npm records it per package; for pnpm, yarn and bun FrontGuard
   walks the dependency graph from your `dependencies` and `devDependencies`, and a package is
   dev-only when it is reachable from dev roots and not from production ones;
4. sends `{ name, version }` pairs to the OSV.dev batch API (1,000 per request), then fetches each
   advisory's details (8 in parallel);
5. reports one finding per package version and advisory, with:
   - **severity** from the GHSA label, or computed from the CVSS 3.x vector, or `medium` when absent;
   - the **CVE id** when the advisory has one;
   - the **lowest fixed version** for the range that contains your version;
   - the **line in the lockfile** where the package is declared.

Dev-only packages are skipped unless `--include-dev` / `dependencies.includeDev` is set. Without a
lockfile, FrontGuard falls back to the lowest versions allowed by `package.json` ranges and warns
that results are approximate. Network failures never fail the scan: they become a warning.
`--offline` disables the lookup entirely.

## Secrets: what is and is not reported

- **Provider patterns** (AWS, GitHub, GitLab, Stripe secret keys, OpenAI, Anthropic, Slack, Discord,
  Twilio, SendGrid, npm, Docker Hub, Azure, DigitalOcean, Shopify, Hugging Face, Groq, Replicate,
  Datadog, New Relic, Cloudflare…) are reported even inside comments: a committed token is leaked
  wherever it sits.
- **Generic patterns** (`password = "…"`, `apiKey: "…"`, `Authorization: "Bearer …"`) are filtered
  through heuristics: placeholders (`your-password`, `changeme`, `xxxx`), labels, URLs,
  `process.env`/`import.meta.env` lookups and low-entropy words are ignored.
- **High-entropy strings** are a fallback, reported only when no specific rule matched the line, and
  not in class names, SVG paths, hashes, integrity attributes or i18n calls.
- **Not reported, because they are public by design:** Stripe publishable keys (`pk_live_`,
  `pk_test_`), Sentry DSNs, Supabase anon keys, Mapbox public tokens, PayPal client ids, Algolia
  app ids, Firebase database URLs, Twilio account SIDs. Google/Firebase browser keys (`AIza…`) are
  reported as `low`, with advice to restrict them by HTTP referrer.
- **Masking:** each secret is replaced by its first four characters plus `*` (or only `*` when it
  is short) in every snippet of the file, including context lines of other findings. PEM private
  keys are masked line by line.

## CI and git hooks

### GitHub Actions (with the Security tab)

`frontguard init` writes this for you:

```yaml
name: FrontGuard

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
      - uses: actions/setup-node@v5
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - name: Scan
        run: npx @juliocarneiro/frontguard --reporter console,sarif
      - name: Upload results to GitHub code scanning
        if: ${{ !cancelled() }}
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: frontguard-report/frontguard-report.sarif
          category: frontguard
```

The job fails on findings at or above `failOn`, and alerts show up in **Security → Code scanning**
and as pull request annotations. Code scanning is free for public repositories; private
repositories need GitHub Advanced Security / Code Security.

### GitLab CI

```yaml
frontguard:
  image: node:22
  script:
    - npx --yes @juliocarneiro/frontguard --reporter console,json,html
  artifacts:
    when: always
    paths:
      - frontguard-report/
```

### Any other CI

Run `npx @juliocarneiro/frontguard` and rely on the exit code, then archive `frontguard-report/` if you enable the
JSON or HTML reporters. Use `--offline` on runners without internet access.

### Git hooks

```yaml
# lefthook.yml
pre-push:
  commands:
    frontguard:
      run: npx @juliocarneiro/frontguard --offline --quiet
```

```sh
# .husky/pre-push
npx @juliocarneiro/frontguard --offline --quiet
```

`pre-push` is a better fit than `pre-commit`: FrontGuard scans the directory, not only staged files.

## Programmatic API

```ts
import {
  scan,
  toSarif,
  toJson,
  toHtml,
  toConsole,
  writeReports,
  meetsThreshold,
} from '@juliocarneiro/frontguard';

const result = await scan({
  cwd: 'apps/web', // directory to scan, default process.cwd()
  config: { failOn: 'medium', dependencies: { offline: true } }, // optional, validated
});

console.log(`${result.findings.length} findings in ${result.filesScanned} files`);
await writeReports(result, ['sarif', 'html'], 'reports');
if (result.findings.some((f) => f.level === 'error' && meetsThreshold(f.severity, 'medium'))) {
  process.exitCode = 1;
}
```

`scan()` never writes to disk or stdout; reporters are pure functions that return strings.

| Export                                   | Description                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan(options?)`                         | Scans a directory. `options`: `cwd`, `config` (user or resolved config), `fetch` (custom fetch, for tests/proxies). Returns `Promise<ScanResult>` |
| `defineConfig(config)`                   | Typed identity helper for config files                                                                                                            |
| `loadConfig(cwd, path?)`                 | Finds, imports and validates a config. Returns `{ config, file? }`                                                                                |
| `resolveConfig(input?)`                  | Applies defaults and validates a config object; throws `ConfigError`                                                                              |
| `ConfigError`                            | Error class for invalid or unloadable configs                                                                                                     |
| `defineRule(rule)`                       | Typed identity helper for custom rules                                                                                                            |
| `builtinRules`                           | The 22 source rules (`Rule[]`)                                                                                                                    |
| `DEPENDENCY_RULE`                        | Metadata of `FG-DEP-001`                                                                                                                          |
| `toConsole(result, { color, compact? })` | Terminal text                                                                                                                                     |
| `toJson(result)`                         | JSON report string                                                                                                                                |
| `toSarif(result)`                        | SARIF 2.1.0 string                                                                                                                                |
| `toHtml(result)`                         | Self-contained HTML string                                                                                                                        |
| `writeReports(result, reporters, dir)`   | Writes json/sarif/html files, returns their paths                                                                                                 |
| `meetsThreshold(severity, threshold)`    | `true` when `severity` is at or above `threshold`                                                                                                 |
| `VERSION`                                | Package version                                                                                                                                   |

Types: `ScanResult`, `Finding`, `Rule`, `RuleMeta`, `RuleContext`, `ReportDescriptor`, `Severity`,
`Category`, `RuleLevel`, `Location`, `UserConfig`, `ResolvedConfig`, `ScanOptions`, `LoadedConfig`.

`ScanResult` contains `root` (absolute path), `findings` (sorted by severity, file, line),
`warnings` (unparseable files, network errors), `filesScanned`, `durationMs`, `startedAt` and
`rules` (metadata of the rules that ran).

## Writing custom rules

A rule is metadata plus a `create(context)` function called once per file. It can inspect the raw
text, return [Babel visitors](https://github.com/babel/babel/blob/main/packages/babel-traverse), or
both. Visitors from every rule are merged and run in a single traversal.

```ts
// security/no-alert.ts
import { defineRule } from '@juliocarneiro/frontguard';

export const noAlert = defineRule({
  meta: {
    id: 'ACME-001', // unique, stable
    name: 'no-alert', // usable in `rules` and suppression comments
    title: 'alert() call',
    description: 'alert() blocks the main thread and is easy to abuse for phishing.',
    remediation: 'Use the design-system dialog component.',
    severity: 'low',
    category: 'misconfig',
    cwe: 'CWE-451', // optional
  },
  create(context) {
    return {
      CallExpression({ node }) {
        if (node.callee.type === 'Identifier' && node.callee.name === 'alert' && node.loc) {
          context.report({ line: node.loc.start.line, column: node.loc.start.column + 1 });
        }
      },
    };
  },
});
```

```ts
// frontguard.config.ts
import { defineConfig } from '@juliocarneiro/frontguard';
import { noAlert } from './security/no-alert.ts';

export default defineConfig({ customRules: [noAlert] });
```

A text-based rule, for markup or files without a script:

```ts
export const noInlineHandlers = defineRule({
  meta: {
    id: 'ACME-002',
    name: 'no-inline-handlers',
    title: 'Inline event handler',
    description: 'Inline handlers require unsafe-inline in CSP.',
    remediation: 'Use addEventListener.',
    severity: 'low',
    category: 'misconfig',
  },
  create(context) {
    if (!context.filename.endsWith('.html')) return;
    context.lines.forEach((line, i) => {
      const m = /\son[a-z]+\s*=/i.exec(line);
      if (m) context.report({ line: i + 1, column: m.index + 2 });
    });
  },
});
```

**`RuleContext`**

| Member               | Description                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `filename`           | Path relative to the scanned directory, forward slashes                                            |
| `text`, `lines`      | Raw file content                                                                                   |
| `ast`                | Babel `File` for the script part (whole file for JS/TS, `<script>` blocks for SFC/HTML), or `null` |
| `report(descriptor)` | Records a finding                                                                                  |

**`ReportDescriptor`**: `line`, `column` (1-based, required), `message` (appended to the title),
`severity` (overrides the rule default), `redact` (string or strings to mask in every snippet).

Findings are deduplicated per rule and position, inline suppressions apply automatically, and a rule
that throws produces a warning instead of crashing the scan. Test rules with `scan()` on a temporary
directory, or study the built-in ones in [`src/rules`](./src/rules).

## How it works

```text
discover files ──► read (parallel, size/binary checks) ──► extract <script> blocks in place
       │                                                          │
       │                                     parse once with Babel (TS/JSX/decorators)
       │                                                          │
       │                 every rule: create(context) ──► text checks + visitors
       │                                                          │
       │                                    one merged traversal ──► report()
       │                                                          │
       └──► lockfile ──► OSV.dev batch + details ──► dependency findings
                                                                  │
                    suppressions · dedupe · secret masking · sort ──► reporters
```

- **Discovery**: [tinyglobby](https://github.com/SuperchupuDev/tinyglobby) with your include/exclude globs.
- **Parsing**: [@babel/parser](https://babeljs.io/docs/babel-parser) with error recovery, so a syntax error degrades to a warning.
- **Rules**: ESLint-style `create(context)` returning visitors; [@babel/traverse](https://babeljs.io/docs/babel-traverse) `visitors.merge` runs them all in one pass.
- **Config**: [Zod](https://zod.dev) schema; TS configs loaded natively by Node.
- **CLI**: [Commander](https://github.com/tj/commander.js), `node:util` `styleText` for colors.

## Limitations

FrontGuard is a static, pattern- and AST-based scanner. It is honest about what that means:

- **No taint tracking.** It reports dangerous sinks (`innerHTML = x`) without proving that `x` comes
  from user input. Sanitized values still need a suppression comment.
- **No cross-file analysis.** Each file is analyzed on its own.
- **Templates are partially covered.** Vue `v-html` and Svelte `{@html}` are detected in markup;
  other template expressions, Angular templates and Astro frontmatter are not analyzed.
- **Secrets heuristics can miss** unusual formats or flag random-looking constants.
- **Dependency results** are as good as OSV.dev data and your lockfile.

It complements, and does not replace, code review, a Content Security Policy, a server-side SAST
tool and runtime testing.

## FAQ

**Does my code leave my machine?**
No. Only `{ name, version }` of installed packages are sent to OSV.dev, and `--offline` turns even
that off.

**How is it different from ESLint security plugins?**
ESLint plugins cover JS/TS files with per-framework plugins and no secrets or dependency audit.
FrontGuard handles `.vue`/`.svelte`/`.astro`/`.html` script extraction itself, masks secrets, audits
lockfiles and produces SARIF/HTML reports, with no lint setup. Many teams run both.

**And from gitleaks or npm audit?**
gitleaks focuses on secrets (and git history); `npm audit` on npm dependencies only. FrontGuard
combines code, secrets and dependency checks for frontend projects, reads pnpm/yarn/bun lockfiles,
and knows which keys are public in a browser.

**It flagged something that is safe. What now?**
Add `// frontguard-ignore-next-line <rule>` with a short reason, set the rule to `warn`, or
[open an issue](https://github.com/juliocarneiro/frontguard/issues) with a minimal example:
false positives are bugs.

**Can I scan only changed files?**
Not yet. FrontGuard scans directories; it is fast enough for full scans in CI and `pre-push` hooks.

## Contributing, security and license

- Contributing guide: [CONTRIBUTING.md](./CONTRIBUTING.md) (setup, layout, adding a rule, changesets)
- Rule reference: [docs/rules.md](./docs/rules.md) (generated from the code)
- Changelog: [CHANGELOG.md](./CHANGELOG.md)
- Security policy: [SECURITY.md](./SECURITY.md) (report vulnerabilities privately)
- License: [MIT](./LICENSE) © Julio Carneiro
