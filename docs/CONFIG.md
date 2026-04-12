# FrontGuard — Complete Configuration Reference

Detailed documentation for all FrontGuard configuration options.

---

## Table of Contents

- [Config File Format](#config-file-format)
- [Full Options Reference](#full-options-reference)
  - [include](#include)
  - [exclude](#exclude)
  - [scanners](#scanners)
  - [rules](#rules)
  - [severity](#severity)
  - [reporters](#reporters)
  - [output](#output)
  - [feed](#feed)
  - [ai](#ai)
- [Common Configuration Examples](#common-configuration-examples)
- [Environment Variables](#environment-variables)
- [Configuration Hierarchy](#configuration-hierarchy)

---

## Config File Format

FrontGuard automatically looks for the following configuration files (in order of priority):

1. `frontguard.config.ts` — TypeScript (recommended)
2. `frontguard.config.js` — JavaScript ESM
3. `frontguard.config.mjs` — Explicit JavaScript ESM
4. `.frontguardrc.json` — JSON

### Creating the configuration file

```bash
# Generate automatically
frontguard init

# Generate with --force to overwrite an existing file
frontguard init --force
```

### TypeScript format (recommended)

```typescript
// frontguard.config.ts
import { defineConfig } from 'frontguard';

export default defineConfig({
  // your options here
});
```

### JSON format

```json
// .frontguardrc.json
{
  "include": ["src/**/*.{ts,tsx}"],
  "severity": {
    "failOn": "high"
  }
}
```

---

## Full Options Reference

### `include`

Glob patterns for files to include in the scan.

| Field | Value |
|-------|-------|
| **Type** | `string[]` |
| **Default** | `['**/*.{ts,tsx,js,jsx,vue,svelte}']` |

```typescript
export default defineConfig({
  include: [
    'src/**/*.{ts,tsx}',
    'pages/**/*.{ts,tsx}',
    'app/**/*.{ts,tsx}',
    'public/**/*.html',
  ],
});
```

---

### `exclude`

Glob patterns for files/directories to exclude from the scan.

| Field | Value |
|-------|-------|
| **Type** | `string[]` |
| **Default** | `['node_modules', 'dist', 'build', '.next', '**/*.test.*', '**/*.spec.*', '**/*.d.ts']` |

```typescript
export default defineConfig({
  exclude: [
    'node_modules',
    'dist',
    'build',
    '.next',
    'coverage',
    '**/*.test.*',
    '**/*.spec.*',
    '**/*.d.ts',
    '**/*.stories.*',
    'scripts/',
    'e2e/',
  ],
});
```

---

### `scanners`

Enable/disable individual scanners.

| Field | Value |
|-------|-------|
| **Type** | `object` |

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scanners.xss` | `boolean` | `true` | Cross-Site Scripting (XSS) scanner |
| `scanners.dependencies` | `boolean` | `true` | Vulnerable dependencies scanner (OSV) |
| `scanners.secrets` | `boolean` | `true` | Leaked secrets scanner |
| `scanners.misconfig` | `boolean` | `true` | Misconfiguration scanner |
| `scanners.authPatterns` | `boolean` | `true` | Insecure authentication patterns scanner |

```typescript
export default defineConfig({
  scanners: {
    xss: true,
    dependencies: true,
    secrets: true,
    misconfig: true,
    authPatterns: true,
  },
});
```

---

### `rules`

Level overrides for individual rules. Allows disabling rules or changing their severity level.

| Field | Value |
|-------|-------|
| **Type** | `Record<string, RuleLevel>` |
| **Default** | `{}` (no overrides) |

**`RuleLevel` values:**

| Value | Description |
|-------|-------------|
| `'error'` | Rule enabled (default for all rules) |
| `'warn'` | Rule enabled as warning |
| `'off'` | Rule disabled |

```typescript
export default defineConfig({
  rules: {
    'FG-XSS-008': 'off',     // disable javascript: URL check
    'FG-SEC-006': 'warn',    // high entropy as warning only
    'FG-CFG-003': 'off',     // disable CDN integrity check
    'FG-XSS-002': 'error',   // keep eval() as error (default)
  },
});
```

**Available rule IDs:**

| Category | IDs |
|----------|-----|
| XSS | `FG-XSS-001` to `FG-XSS-008` |
| Secrets | `FG-SEC-001` to `FG-SEC-006` |
| Dependencies | `FG-DEP-001`, `FG-DEP-002` |
| Auth Patterns | `FG-AUTH-001` to `FG-AUTH-003` |
| Misconfig | `FG-CFG-001` to `FG-CFG-003` |

See [RULES.md](./RULES.md) for the full list with descriptions.

---

### `severity`

Settings related to finding severity.

| Field | Value |
|-------|-------|
| **Type** | `object` |

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `severity.failOn` | `Severity` | `'high'` | Minimum severity level that causes scan failure (exit code 1) |

**`Severity` values** (from most to least severe):

| Value | Description |
|-------|-------------|
| `'critical'` | Only critical findings cause failure |
| `'high'` | High and critical findings cause failure (default) |
| `'medium'` | Medium, high, and critical findings cause failure |
| `'low'` | Low and above findings cause failure |
| `'info'` | Any finding causes failure |

```typescript
export default defineConfig({
  severity: {
    failOn: 'critical', // only fail on critical findings
  },
});
```

---

### `reporters`

List of reporters to use for generating reports.

| Field | Value |
|-------|-------|
| **Type** | `string[]` |
| **Default** | `['console']` |

**Available reporters:**

| Reporter | Description | Output |
|----------|-------------|--------|
| `'console'` | Formatted terminal output | stdout |
| `'json'` | Structured JSON report | `{output}/frontguard-report.json` |
| `'html'` | Interactive HTML dashboard | `{output}/frontguard-report.html` |
| `'sarif'` | SARIF format for CI/CD | `{output}/report.sarif` |

```typescript
export default defineConfig({
  reporters: ['console', 'json', 'html', 'sarif'],
});
```

---

### `output`

Output directory for generated reports (JSON, HTML, SARIF).

| Field | Value |
|-------|-------|
| **Type** | `string` |
| **Default** | `'./frontguard-report'` |

```typescript
export default defineConfig({
  output: './security-reports',
});
```

---

### `feed`

Vulnerability feed settings (local CVE database).

| Field | Value |
|-------|-------|
| **Type** | `object` |

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `feed.autoUpdate` | `boolean` | `true` | Automatically update cache before scan if expired |
| `feed.ttl` | `string` | `'24h'` | Cache time-to-live. Formats: `'24h'`, `'7d'`, `'30m'` |
| `feed.sources` | `string[]` | `['osv', 'github', 'nvd']` | Vulnerability sources to query |
| `feed.githubToken` | `string?` | `undefined` | GitHub token to increase GitHub Advisory API rate limit |
| `feed.nvdApiKey` | `string?` | `undefined` | NVD/NIST API key to increase rate limit |

**Available sources:**

| Source | Description | API Key |
|--------|-------------|---------|
| `'osv'` | [OSV.dev](https://osv.dev/) — Open vulnerability database | Not required |
| `'github'` | [GitHub Advisory Database](https://github.com/advisories) | Optional (recommended) |
| `'nvd'` | [NVD/NIST](https://nvd.nist.gov/) — National Vulnerability Database | Optional (recommended) |

```typescript
export default defineConfig({
  feed: {
    autoUpdate: true,
    ttl: '12h',
    sources: ['osv', 'github'],
    githubToken: process.env.GITHUB_TOKEN,
    nvdApiKey: process.env.NVD_API_KEY,
  },
});
```

**Managing the feed manually:**

```bash
# Update cache manually
frontguard update --verbose

# View cache status
frontguard update --status
```

---

### `ai`

AI module settings.

| Field | Value |
|-------|-------|
| **Type** | `object` |

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ai.enabled` | `boolean` | `false` | Enable AI module |
| `ai.provider` | `'openai' \| 'anthropic' \| 'google' \| 'ollama'` | `'openai'` | AI provider |
| `ai.model` | `string` | `'gpt-4o-mini'` | Model to use |
| `ai.apiKey` | `string?` | `undefined` | Provider API key (not required for Ollama) |
| `ai.features.deepScan` | `boolean` | `true` | Enable deep analysis of findings |
| `ai.features.autoFix` | `boolean` | `false` | Enable automatic fix generation |
| `ai.features.crossFileFlow` | `boolean` | `true` | Enable cross-file flow analysis |
| `ai.features.customRules` | `string[]` | `[]` | Custom rules in natural language |
| `ai.confirmBeforeSend` | `boolean` | `true` | Prompt for confirmation before sending data to AI |
| `ai.ollamaBaseUrl` | `string` | `'http://localhost:11434'` | Ollama server base URL |

```typescript
export default defineConfig({
  ai: {
    enabled: true,
    provider: 'openai',
    model: 'gpt-4o-mini',
    apiKey: process.env.OPENAI_API_KEY,
    features: {
      deepScan: true,
      autoFix: true,
      crossFileFlow: true,
      customRules: [
        'Verify that all API routes validate input',
      ],
    },
    confirmBeforeSend: true,
    ollamaBaseUrl: 'http://localhost:11434',
  },
});
```

See [AI-GUIDE.md](./AI-GUIDE.md) for detailed AI module documentation.

---

## Common Configuration Examples

### Minimal Configuration

```typescript
// frontguard.config.ts
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx}'],
});
```

All other values use their defaults.

---

### CI/CD Configuration

```typescript
// frontguard.config.ts
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx,js,jsx}'],
  exclude: [
    'node_modules',
    'dist',
    '**/*.test.*',
    '**/*.spec.*',
    '**/*.d.ts',
    '**/*.stories.*',
  ],
  scanners: {
    xss: true,
    dependencies: true,
    secrets: true,
    misconfig: true,
    authPatterns: true,
  },
  severity: {
    failOn: 'high',
  },
  reporters: ['console', 'sarif', 'json'],
  output: './security-report',
  feed: {
    autoUpdate: true,
    ttl: '12h',
    sources: ['osv', 'github'],
    githubToken: process.env.GITHUB_TOKEN,
  },
  ai: {
    enabled: true,
    provider: 'google',
    model: 'gemini-2.0-flash',
    apiKey: process.env.GOOGLE_API_KEY,
    features: {
      deepScan: true,
      autoFix: false,
      crossFileFlow: false,
      customRules: [],
    },
    confirmBeforeSend: false,
  },
});
```

**GitHub Actions usage:**

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install
      - run: npx frontguard scan ./src --fail-on high -r sarif -o ./security-report
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ./security-report/report.sarif
```

---

### AI-Enabled Configuration (OpenAI)

```typescript
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx}'],
  severity: { failOn: 'high' },
  reporters: ['console', 'html'],
  ai: {
    enabled: true,
    provider: 'openai',
    model: 'gpt-4o-mini',
    apiKey: process.env.OPENAI_API_KEY,
    features: {
      deepScan: true,
      autoFix: true,
      crossFileFlow: true,
      customRules: [
        'Verify that forms have CSRF protection',
        'Ensure database queries use parameterized queries',
      ],
    },
    confirmBeforeSend: true,
  },
});
```

---

### Local AI Configuration (Ollama)

```typescript
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx}'],
  ai: {
    enabled: true,
    provider: 'ollama',
    model: 'llama3',
    ollamaBaseUrl: 'http://localhost:11434',
    features: {
      deepScan: true,
      autoFix: true,
      crossFileFlow: true,
      customRules: [],
    },
    confirmBeforeSend: false,
  },
});
```

---

### XSS and Secrets Only Configuration

```typescript
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx,js,jsx,vue}'],
  scanners: {
    xss: true,
    dependencies: false,
    secrets: true,
    misconfig: false,
    authPatterns: false,
  },
  rules: {
    'FG-SEC-006': 'warn',    // high entropy as warning only
    'FG-XSS-008': 'off',     // disable javascript: URL
  },
  severity: {
    failOn: 'critical',       // only fail on critical
  },
  reporters: ['console'],
});
```

---

### Vue/Svelte Project Configuration

```typescript
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: [
    'src/**/*.{ts,js,vue,svelte}',
    'components/**/*.{vue,svelte}',
  ],
  exclude: [
    'node_modules',
    'dist',
    '.nuxt',
    '.svelte-kit',
    '**/*.test.*',
    '**/*.d.ts',
  ],
  scanners: {
    xss: true,          // detects v-html, etc.
    secrets: true,
    misconfig: true,
    authPatterns: true,
    dependencies: true,
  },
});
```

---

## Environment Variables

FrontGuard supports the following environment variables:

| Variable | Description | Used by |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | AI Engine (provider: openai) |
| `ANTHROPIC_API_KEY` | Anthropic API key | AI Engine (provider: anthropic) |
| `GOOGLE_API_KEY` | Google API key | AI Engine (provider: google) |
| `GITHUB_TOKEN` | GitHub token | Feed (GitHub Advisory source) |
| `NVD_API_KEY` | NVD/NIST API key | Feed (NVD source) |
| `FRONTGUARD_AI_PROVIDER` | AI provider | AI Engine |
| `FRONTGUARD_AI_MODEL` | AI model | AI Engine |
| `FRONTGUARD_OLLAMA_URL` | Ollama URL | AI Engine (provider: ollama) |

**Example `.env` file:**

```bash
# API Keys
OPENAI_API_KEY=sk-proj-...
GITHUB_TOKEN=ghp_...
NVD_API_KEY=...

# AI Config
FRONTGUARD_AI_PROVIDER=openai
FRONTGUARD_AI_MODEL=gpt-4o-mini
```

**Usage in the configuration file:**

```typescript
export default defineConfig({
  feed: {
    githubToken: process.env.GITHUB_TOKEN,
    nvdApiKey: process.env.NVD_API_KEY,
  },
  ai: {
    apiKey: process.env.OPENAI_API_KEY,
  },
});
```

---

## Configuration Hierarchy

Settings are applied in the following order of priority (higher overrides lower):

```
CLI Flags  >  Config File  >  Saved Credentials (~/.frontguard/config.json)  >  Defaults
```

### Breakdown

| Priority | Source | Example |
|----------|--------|---------|
| 1 (highest) | **CLI Flags** | `--fail-on critical`, `--ai-provider openai` |
| 2 | **Configuration file** | `frontguard.config.ts`, `.frontguardrc.json` |
| 3 | **Saved credentials** | `~/.frontguard/config.json` (via `frontguard auth`) |
| 4 (lowest) | **Internal defaults** | Default values defined in code |

### Override Examples

```bash
# Config file sets failOn: 'high'
# CLI flag overrides to 'critical'
frontguard scan ./src --fail-on critical

# Config file sets provider: 'openai'
# CLI flag overrides to 'anthropic'
frontguard scan ./src --ai-deep --ai-provider anthropic

# Config file sets reporters: ['console']
# CLI flag adds sarif
frontguard scan ./src -r console -r sarif
```

### Configuration Merging

FrontGuard performs deep merge between the base configuration and the user configuration:

- `include`, `exclude`, `reporters`: **full replacement** (if provided by user, they replace the default)
- `scanners`, `rules`, `severity`, `feed`, `ai`: **deep merge** (unspecified fields retain their defaults)
- `ai.features`: **deep merge** (each feature can be configured individually)

```typescript
// Only setting 'xss: false' — all other scanners keep their default (true)
export default defineConfig({
  scanners: {
    xss: false,
  },
});
// Result: { xss: false, dependencies: true, secrets: true, misconfig: true, authPatterns: true }
```
