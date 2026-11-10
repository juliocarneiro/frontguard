---
'frontguard': minor
'create-frontguard': minor
---

First public release.

- Single-pass, ESLint-style rule engine with a public `defineRule()` API for custom rules.
- Vue, Svelte, Astro and HTML `<script>` blocks are analyzed with exact positions; new rules for Svelte `{@html}`, `insertAdjacentHTML`/`setHTMLUnsafe`, and `postMessage(…, '*')`.
- Dependency audit reads npm, pnpm, yarn (v1 and berry) and bun lockfiles, including transitive packages, with real severities, CVE ids and fixed versions from OSV.dev.
- SARIF output ready for GitHub code scanning (relative paths, fingerprints, `security-severity`).
- Secrets are masked in every report; browser-safe keys are no longer reported.
- Validated configuration (`frontguard.config.ts` or `.frontguardrc.json`), `warn` rule level and inline suppression comments.
- `frontguard init` / `npm create frontguard` set up install, config, script and a CI workflow.
- Requires Node.js 22.18+.
