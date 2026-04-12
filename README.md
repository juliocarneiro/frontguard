<p align="center">
  <h1 align="center">FrontGuard</h1>
  <p align="center"><strong>Open-source frontend security scanner that catches vulnerabilities before they ship.</strong></p>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/frontguard"><img src="https://img.shields.io/npm/v/frontguard.svg" alt="npm version"></a>
  <a href="https://github.com/frontguard/frontguard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="license"></a>
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg" alt="node >= 18">
  <img src="https://img.shields.io/badge/TypeScript-5.7-blue.svg" alt="TypeScript">
</p>

---

FrontGuard is a static analysis security tool purpose-built for frontend codebases. It scans TypeScript, JavaScript, React, Vue, Angular, and Svelte projects for XSS vulnerabilities, leaked secrets, insecure auth patterns, misconfigurations, and vulnerable dependencies — all from a single CLI command.

## Features

- **XSS Detection** — 8 rules covering innerHTML, eval, document.write, dangerouslySetInnerHTML, v-html, Angular bypasses, and more
- **Secrets Scanner** — 149+ patterns for AWS, Google, GitHub, Stripe, Slack, OpenAI, database URIs, private keys, JWTs, and dozens more providers
- **Auth Pattern Analysis** — Flags localStorage token storage, tokens in URLs, and hardcoded credentials
- **Misconfiguration Detection** — Catches exposed sourcemaps, mixed content, and CDN resources without integrity checks
- **Dependency Auditing** — Queries OSV.dev for known vulnerabilities in your dependencies
- **AI-Powered Analysis** — Optional deep scan, auto-fix suggestions, and cross-file data flow analysis via OpenAI, Anthropic, Google, or Ollama
- **Live Vulnerability Feed** — Real-time feeds from OSV.dev, GitHub Advisory DB, and NVD with local JSON caching
- **Multiple Reporters** — Console, JSON, interactive HTML dashboard, and SARIF for CI/CD integration
- **CI/CD Ready** — SARIF output for GitHub Code Scanning, with built-in severity thresholds for fail gates

## Quick Start

```bash
# Install globally
npm install -g frontguard

# Initialize config (optional)
frontguard init

# Scan your project
frontguard scan ./src

# Scan with HTML report (auto-opens in browser)
frontguard scan ./src -r
```

## Example Output

```
  ┌────────────────────────────────────────────────────────┐
  │                                                        │
  │    FrontGuard  Security Scanner                        │
  │    Catch vulnerabilities before they ship              │
  │                                                        │
  └────────────────────────────────────────────────────────┘

  ✔ Scanned 127 files in 342ms

   CRITICAL  FG-XSS-002  Use of eval() or Similar Dynamic Code Execution
  src/utils/parser.ts:42:5

    41 | function parseInput(raw) {
  > 42 |   const result = eval(raw);
    43 |   return result;

  Ref: CWE-95 | A03:2021 - Injection
  Fix: Avoid eval() and new Function(). Use JSON.parse() for data.

   HIGH  FG-SEC-002  API Key or Token Exposed
  src/config/api.ts:8:1

   HIGH  FG-AUTH-001  Token Stored in Web Storage
  src/auth/session.ts:15:3

  ────────────────────────────────────────────────────────
    SCAN RESULTS
  ────────────────────────────────────────────────────────

  Files    127
  Time     342ms
  Findings 12

  ● CRITICAL  2  ██
  ● HIGH      7  ███████
  ● MEDIUM    3  ███

  ────────────────────────────────────────────────────────
```

## Scanners

| Scanner | Category | What It Detects | Rules |
|---------|----------|-----------------|-------|
| **XSS Scanner** | `xss` | innerHTML, eval, document.write, dangerouslySetInnerHTML, v-html, bypassSecurityTrust, outerHTML, javascript: URLs | 8 |
| **Secrets Scanner** | `secrets` | AWS keys, API tokens, private keys, JWTs, database URIs, high-entropy strings across 60+ providers | 6 rules, 149+ patterns |
| **Auth Patterns** | `auth-patterns` | localStorage/sessionStorage token storage, tokens in URL parameters, hardcoded credentials | 3 |
| **Misconfig Scanner** | `misconfig` | Exposed sourcemaps, mixed HTTP/HTTPS content, CDN resources without SRI | 3 |
| **Dependency Scanner** | `dependencies` | Known CVEs via OSV.dev, outdated critical dependencies | 2 |

## AI-Powered Analysis

FrontGuard integrates with AI providers for deeper analysis beyond static pattern matching.

```bash
# Deep scan with AI analysis
frontguard scan ./src --ai-deep

# Generate fix suggestions
frontguard scan ./src --ai-fix

# Cross-file data flow analysis
frontguard scan ./src --ai-flow

# Custom rule in natural language
frontguard scan ./src --ai-rule "Flag any API call that doesn't handle errors"

# Use a specific provider
frontguard scan ./src --ai-deep --ai-provider anthropic --ai-model claude-sonnet-4-20250514
```

Supported providers: **OpenAI**, **Anthropic**, **Google**, and **Ollama** (local).

## Live Vulnerability Feed

FrontGuard maintains a local vulnerability database updated from three sources:

- **OSV.dev** — Open Source Vulnerability database
- **GitHub Advisory Database** — GitHub's curated security advisories
- **NVD** — NIST National Vulnerability Database

```bash
# Update the local vulnerability database
frontguard update

# Check feed status
frontguard update --status
```

The feed uses a local JSON cache (`~/.frontguard/cache.json`) with configurable TTL (default: 24 hours). No native dependencies required.

## Dashboard

Generate an interactive HTML security dashboard:

```bash
# Quick: generate and auto-open in browser
frontguard scan ./src -r

# CI: output SARIF for GitHub Code Scanning
frontguard scan ./src --reporter sarif --output ./reports
```

The dashboard includes severity breakdowns, filterable findings, code snippets with highlighted lines, remediation guidance, and trend charts when run over time.

## Configuration

Create a `frontguard.config.ts` in your project root:

```typescript
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx,js,jsx,vue,svelte}'],
  exclude: ['node_modules', 'dist', '**/*.test.*'],
  scanners: {
    xss: true,
    dependencies: true,
    secrets: true,
    misconfig: true,
    authPatterns: true,
  },
  rules: {
    'FG-XSS-002': 'error',
    'FG-SEC-006': 'warn',
  },
  severity: {
    failOn: 'high',
  },
  reporters: ['console', 'sarif'],
  output: './frontguard-report',
  ai: {
    enabled: false,
    provider: 'openai',
    model: 'gpt-4o-mini',
  },
});
```

Also supports `frontguard.config.js`, `frontguard.config.mjs`, and `.frontguardrc.json`.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  frontguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm install -g frontguard
      - run: frontguard scan ./src --reporter sarif --output ./results
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ./results/frontguard.sarif
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `frontguard scan [target]` | Scan a directory for vulnerabilities |
| `frontguard init` | Generate a config file in the current directory |
| `frontguard report` | Regenerate reports from the last scan |
| `frontguard update` | Update the local vulnerability feed |
| `frontguard auth` | Configure AI provider authentication |

### Scan Options

| Flag | Description |
|------|-------------|
| `-c, --config <path>` | Path to config file |
| `-s, --scanners <list>` | Comma-separated scanner list (e.g. `xss,secrets`) |
| `-r, --report` | Generate HTML report and auto-open in browser |
| `--reporter <type>` | Reporter for CI: `json`, `html`, `sarif` |
| `-o, --output <path>` | Output directory for reports |
| `--fail-on <severity>` | Fail threshold: `critical`, `high`, `medium`, `low` |
| `--ai-deep` | Enable AI deep scan analysis |
| `--ai-fix` | Generate AI-powered fix suggestions |
| `--ai-flow` | Enable AI cross-file data flow analysis |
| `--ai-rule <rule>` | Custom rule in natural language |
| `--ai-provider <provider>` | AI provider: `openai`, `anthropic`, `google`, `ollama` |
| `--ai-model <model>` | AI model to use |
| `--ai-no-confirm` | Skip confirmation before sending code to AI |

## Local Development

```bash
# Clone and install
git clone https://github.com/frontguard/frontguard.git
cd frontguard
npm install

# Build
npm run build

# Link globally for testing
npm link

# Scan a project
frontguard scan /path/to/your/project

# Scan with HTML report
frontguard scan /path/to/your/project -r

# Run tests
npm test
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

[MIT](LICENSE) © 2024–2026 FrontGuard Contributors
