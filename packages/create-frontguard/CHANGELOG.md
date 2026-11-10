# create-frontguard

## 0.1.1

### Patch Changes

- Updated dependencies [[`43f04d4`](https://github.com/juliocarneiro/frontguard/commit/43f04d4f698366957b683364fc003e1622c29cd7), [`eb6bcb5`](https://github.com/juliocarneiro/frontguard/commit/eb6bcb59bcc4c3bf06a4f7223a70974aac44bc43)]:
  - @juliocarneiro/frontguard@0.2.0

## 0.1.0

### Minor Changes

- [#1](https://github.com/juliocarneiro/frontguard/pull/1) [`8ca5fa8`](https://github.com/juliocarneiro/frontguard/commit/8ca5fa8fc2c7843438d84a68a4cb5ebc34f7a82e) Thanks [@juliocarneiro](https://github.com/juliocarneiro)! - First public release.
  
  - Single-pass, ESLint-style rule engine with a public `defineRule()` API for custom rules.
  - Vue, Svelte, Astro and HTML `<script>` blocks are analyzed with exact positions; new rules for Svelte `{@html}`, `insertAdjacentHTML`/`setHTMLUnsafe`, and `postMessage(…, '*')`.
  - Dependency audit reads npm, pnpm, yarn (v1 and berry) and bun lockfiles, including transitive packages, with real severities, CVE ids and fixed versions from OSV.dev.
  - SARIF output ready for GitHub code scanning (relative paths, fingerprints, `security-severity`).
  - Secrets are masked in every report; browser-safe keys are no longer reported.
  - Validated configuration (`frontguard.config.ts` or `.frontguardrc.json`), `warn` rule level and inline suppression comments.
  - `frontguard init` / `npm create frontguard` set up install, config, script and a CI workflow.
  - Requires Node.js 22.18+.

### Patch Changes

- Updated dependencies [[`8ca5fa8`](https://github.com/juliocarneiro/frontguard/commit/8ca5fa8fc2c7843438d84a68a4cb5ebc34f7a82e)]:
  - frontguard@0.1.0
