# Contributing

Thanks for helping make frontend code safer.

## Setup

Requirements: Node.js 22.18+ and pnpm (the version is pinned in `packageManager`; `corepack enable` picks it up).

```sh
pnpm install
pnpm test          # vitest
pnpm typecheck
pnpm lint
pnpm build         # tsdown -> dist/
node dist/cli.mjs  # run the CLI you just built
```

## Project layout

```text
src/
  cli/            commander CLI (scan, init wizard, rules, report)
  config/         zod schema + config file loading
  core/           file discovery, script extraction, single-pass rule engine, suppressions
  rules/          built-in rules, one file per rule (xss/) or per category
  dependencies/   lockfile parsers, OSV client, CVSS
  reporters/      console, json, sarif, html (pure functions returning strings)
packages/
  create-frontguard/   `npm create @juliocarneiro/frontguard`
test/             vitest suites and fixtures
```

## Adding a rule

1. Create the rule with `defineRule()` in `src/rules/<category>/`. Prefer Babel visitors over regexes
   for JS/TS; use `context.lines` for markup and text patterns.
2. Register it in the category's `index.ts`.
3. Add positive **and** negative tests in `test/rules/`. False positives matter as much as detections.
4. Run `pnpm docs:rules` to regenerate `docs/rules.md`.

Rule ids are stable; never reuse an id for a different check.

## Changes and releases

Every user-facing change needs a changeset:

```sh
pnpm changeset
```

Merging to `main` opens a "Version Packages" PR; merging that PR publishes `@juliocarneiro/frontguard` and
`@juliocarneiro/create-frontguard` to npm with provenance.

First release only: add an npm automation token as the `NPM_TOKEN` repository secret. Once both
packages exist on npm, enable trusted publishing for them (workflow `release.yml`) and remove the
secret.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`...) are preferred.
