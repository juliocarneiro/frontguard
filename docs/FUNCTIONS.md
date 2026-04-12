# FrontGuard — Complete Functions & Classes Reference

Detailed documentation for all public functions, classes, and modules in FrontGuard.

---

## Table of Contents

- [ScanEngine](#scanengine)
- [Configuration (defineConfig / loadConfig / getDefaultConfig)](#configuration)
- [File Discovery (discoverFiles / readFileContent / getCodeSnippet)](#file-discovery)
- [Rule Registry (ruleRegistry)](#rule-registry)
- [BaseScanner](#basescanner)
- [XSSScanner](#xssscanner)
- [SecretsScanner](#secretsscanner)
- [DependencyScanner](#dependencyscanner)
- [AuthPatternsScanner](#authpatternsscanner)
- [MisconfigScanner](#misconfigscanner)
- [FeedManager](#feedmanager)
- [VulnCache](#vulncache)
- [AIEngine](#aiengine)
- [Reporters](#reporters)
- [Severity Utilities](#severity-utilities)

---

## ScanEngine

Core engine that orchestrates scanners, collects findings, and generates reports.

**Import:**

```typescript
import { ScanEngine } from 'frontguard';
```

### `new ScanEngine()`

Creates a new scan engine instance.

```typescript
const engine = new ScanEngine();
```

---

### `registerScanner(scanner: BaseScanner): void`

Registers a scanner with the engine. Automatically calls `scanner.init()` to register the scanner's rules in the global registry.

| Parameter | Type | Description |
|-----------|------|-------------|
| `scanner` | `BaseScanner` | Instance of any scanner extending `BaseScanner` |

```typescript
import { ScanEngine, XSSScanner, SecretsScanner } from 'frontguard';

const engine = new ScanEngine();
engine.registerScanner(new XSSScanner());
engine.registerScanner(new SecretsScanner());
```

---

### `registerReporter(reporter: Reporter): void`

Registers a reporter to generate reports after the scan.

| Parameter | Type | Description |
|-----------|------|-------------|
| `reporter` | `Reporter` | Object implementing the `Reporter` interface |

```typescript
import { ScanEngine, JsonReporter, HtmlReporter } from 'frontguard';

const engine = new ScanEngine();
engine.registerReporter(new JsonReporter('./reports'));
engine.registerReporter(new HtmlReporter('./reports'));
```

---

### `scan(targetPath: string, config: FrontGuardConfig): Promise<ScanResult>`

Runs a complete scan on the target directory. Discovers files, executes all registered scanners, sorts findings by severity, and generates reports.

| Parameter | Type | Description |
|-----------|------|-------------|
| `targetPath` | `string` | Path to the directory to scan |
| `config` | `FrontGuardConfig` | Complete FrontGuard configuration |

**Returns:** `Promise<ScanResult>` — Result containing findings, metrics, and configuration.

```typescript
import { ScanEngine, XSSScanner, loadConfig } from 'frontguard';

const engine = new ScanEngine();
engine.registerScanner(new XSSScanner());

const config = await loadConfig();
const result = await engine.scan('./src', config);

console.log(`Found ${result.findings.length} issues`);
console.log(`Files scanned: ${result.scannedFiles}`);
console.log(`Duration: ${result.scanDuration}ms`);
```

---

### `hasFailures(result: ScanResult): boolean`

Checks whether the result contains findings that meet the severity threshold configured in `severity.failOn`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `result` | `ScanResult` | Scan result |

**Returns:** `boolean` — `true` if there are findings with severity >= `failOn`.

```typescript
const result = await engine.scan('./src', config);

if (engine.hasFailures(result)) {
  console.error('Scan failed! Critical vulnerabilities found.');
  process.exit(1);
}
```

---

## Configuration

Functions for defining, loading, and managing FrontGuard configuration.

**Import:**

```typescript
import { defineConfig, loadConfig, getDefaultConfig } from 'frontguard';
```

### `defineConfig(config: Partial<FrontGuardConfig>): FrontGuardConfig`

Creates a complete configuration by performing a deep merge with default values. Used in the `frontguard.config.ts` file.

| Parameter | Type | Description |
|-----------|------|-------------|
| `config` | `Partial<FrontGuardConfig>` | Partial user configuration |

**Returns:** `FrontGuardConfig` — Complete configuration with all fields populated.

```typescript
// frontguard.config.ts
import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx}'],
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
  reporters: ['console', 'html'],
});
```

---

### `loadConfig(configPath?: string): Promise<FrontGuardConfig>`

Loads configuration from a file. If `configPath` is not provided, automatically searches for the following files (in priority order):

1. `frontguard.config.ts`
2. `frontguard.config.js`
3. `frontguard.config.mjs`
4. `.frontguardrc.json`

If no file is found, returns the default configuration.

| Parameter | Type | Description |
|-----------|------|-------------|
| `configPath` | `string?` | Optional path to the configuration file |

**Returns:** `Promise<FrontGuardConfig>`

```typescript
// Automatic lookup
const config = await loadConfig();

// Specific path
const config = await loadConfig('./configs/security.config.ts');
```

---

### `getDefaultConfig(): FrontGuardConfig`

Returns a copy of the default FrontGuard configuration.

**Returns:** `FrontGuardConfig`

```typescript
const defaults = getDefaultConfig();
console.log(defaults.severity.failOn); // 'high'
console.log(defaults.reporters);        // ['console']
console.log(defaults.ai.enabled);       // false
```

---

## File Discovery

Functions for locating, reading, and extracting code snippets from files.

**Import:**

```typescript
import { discoverFiles, readFileContent } from 'frontguard';
```

### `discoverFiles(targetPath: string, config: FrontGuardConfig): Promise<string[]>`

Discovers all files matching the `include` patterns in the configuration, excluding patterns in `exclude`. Uses fast-glob internally.

| Parameter | Type | Description |
|-----------|------|-------------|
| `targetPath` | `string` | Root directory for the search |
| `config` | `FrontGuardConfig` | Configuration with include/exclude patterns |

**Returns:** `Promise<string[]>` — Sorted list of absolute paths.

```typescript
import { discoverFiles, getDefaultConfig } from 'frontguard';

const config = getDefaultConfig();
const files = await discoverFiles('./src', config);

console.log(`Found ${files.length} files to scan`);
// Found 142 files to scan
```

---

### `readFileContent(filePath: string): FileContent`

Reads the contents of a file and returns a `FileContent` object with the raw content and split lines.

| Parameter | Type | Description |
|-----------|------|-------------|
| `filePath` | `string` | Absolute file path |

**Returns:** `FileContent` — Object containing `path`, `content`, and `lines`.

```typescript
import { readFileContent } from 'frontguard';

const file = readFileContent('/project/src/App.tsx');
console.log(file.path);            // '/project/src/App.tsx'
console.log(file.lines.length);    // 150
console.log(file.content.length);  // 4230
```

---

### `getCodeSnippet(lines: string[], line: number, contextLines?: number): string`

Extracts a code snippet with context lines around a specific line. The target line is marked with `>`.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `lines` | `string[]` | — | Array of file lines |
| `line` | `number` | — | Central line number (1-based) |
| `contextLines` | `number` | `2` | Number of context lines before and after |

**Returns:** `string` — Formatted snippet with line numbers.

```typescript
import { readFileContent, getCodeSnippet } from 'frontguard';

const file = readFileContent('./src/App.tsx');
const snippet = getCodeSnippet(file.lines, 10, 3);
console.log(snippet);
//    7 | import React from 'react';
//    8 | 
//    9 | function App() {
// > 10 |   element.innerHTML = userInput;
//   11 |   return <div />;
//   12 | }
//   13 |
```

---

## Rule Registry

Global singleton that manages all security rules registered by scanners.

**Import:**

```typescript
import { ruleRegistry } from 'frontguard';
```

### `register(rule: RuleDefinition): void`

Registers a single rule in the registry.

| Parameter | Type | Description |
|-----------|------|-------------|
| `rule` | `RuleDefinition` | Complete rule definition |

```typescript
import { ruleRegistry } from 'frontguard';

ruleRegistry.register({
  id: 'CUSTOM-001',
  title: 'My Custom Rule',
  description: 'Detects a custom insecure pattern',
  severity: 'high',
  category: 'xss',
  cwe: 'CWE-79',
  remediation: 'Fix the insecure pattern.',
});
```

---

### `getAll(): RuleDefinition[]`

Returns all registered rules.

**Returns:** `RuleDefinition[]`

```typescript
const allRules = ruleRegistry.getAll();
console.log(`Total rules: ${allRules.length}`);
```

---

### `setOverrides(overrides: Record<string, RuleLevel>): void`

Sets level overrides for specific rules. Clears previous overrides.

| Parameter | Type | Description |
|-----------|------|-------------|
| `overrides` | `Record<string, RuleLevel>` | Map of rule ID to level (`'error'`, `'warn'`, `'off'`) |

```typescript
ruleRegistry.setOverrides({
  'FG-XSS-008': 'off',      // disable javascript: URL rule
  'FG-SEC-006': 'warn',     // high-entropy becomes warning only
});
```

---

### `isEnabled(id: string): boolean`

Checks whether a rule is enabled (level is not `'off'`).

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | `string` | Rule ID |

**Returns:** `boolean`

```typescript
if (ruleRegistry.isEnabled('FG-XSS-002')) {
  console.log('eval() rule is active');
}
```

---

### `getByCategory(category: string): RuleDefinition[]`

Returns all rules belonging to a specific category.

| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | `string` | Category: `'xss'`, `'secrets'`, `'dependencies'`, `'misconfig'`, `'auth-patterns'` |

**Returns:** `RuleDefinition[]`

```typescript
const xssRules = ruleRegistry.getByCategory('xss');
console.log(`XSS rules: ${xssRules.length}`); // 8
```

---

## BaseScanner

Abstract base class that all scanners must extend.

**Import:**

```typescript
import { BaseScanner } from 'frontguard';
```

### Abstract Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Human-readable scanner name |
| `category` | `ScannerCategory` | Category: `'xss'`, `'secrets'`, `'dependencies'`, `'misconfig'`, `'auth-patterns'` |

### Abstract Methods

#### `getRules(): RuleDefinition[]`

Returns all rule definitions for the scanner.

#### `scanFile(file: FileContent, config: FrontGuardConfig): Finding[]`

Scans a single file and returns findings.

### Concrete Methods

#### `init(): void`

Registers all scanner rules in the global `ruleRegistry`. Called automatically by `ScanEngine.registerScanner()`.

#### `scan(files: FileContent[], config: FrontGuardConfig): Promise<Finding[]>`

Scans multiple files, filtering out findings from disabled rules.

#### `createFinding(rule: RuleDefinition, file: FileContent, line: number, column: number): Finding` *(protected)*

Helper method to create a `Finding` object with the code snippet included.

### Example — Creating a Custom Scanner

```typescript
import { BaseScanner } from 'frontguard';
import type { FileContent, Finding, FrontGuardConfig, RuleDefinition, ScannerCategory } from 'frontguard';

export class TodoScanner extends BaseScanner {
  readonly name = 'TODO Scanner';
  readonly category: ScannerCategory = 'misconfig';

  getRules(): RuleDefinition[] {
    return [{
      id: 'CUSTOM-TODO-001',
      title: 'TODO/FIXME in Production Code',
      description: 'TODO/FIXME comments indicate pending work.',
      severity: 'low',
      category: 'misconfig',
      remediation: 'Resolve the TODO before shipping to production.',
    }];
  }

  scanFile(file: FileContent, _config: FrontGuardConfig): Finding[] {
    const findings: Finding[] = [];
    const rule = this.getRules()[0];
    const regex = /\b(TODO|FIXME|HACK)\b/i;

    for (let i = 0; i < file.lines.length; i++) {
      const match = regex.exec(file.lines[i]);
      if (match) {
        findings.push(this.createFinding(rule, file, i + 1, match.index + 1));
      }
    }

    return findings;
  }
}
```

---

## XSSScanner

Scanner that detects Cross-Site Scripting (XSS) vulnerabilities using AST analysis via Babel.

**Import:**

```typescript
import { XSSScanner } from 'frontguard';
```

### `new XSSScanner()`

Creates an XSS scanner instance. Detects 8 XSS vulnerability patterns.

### `getRules(): RuleDefinition[]`

Returns the 8 XSS rules (FG-XSS-001 through FG-XSS-008).

### `scanFile(file: FileContent, config: FrontGuardConfig): Finding[]`

Analyzes a file using AST to detect XSS patterns such as `innerHTML`, `eval()`, `document.write()`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `outerHTML`, and `javascript:`.

```typescript
import { XSSScanner, readFileContent, getDefaultConfig } from 'frontguard';

const scanner = new XSSScanner();
scanner.init();

const file = readFileContent('./src/components/UserProfile.tsx');
const findings = scanner.scanFile(file, getDefaultConfig());

for (const finding of findings) {
  console.log(`[${finding.ruleId}] ${finding.title}`);
  console.log(`  File: ${finding.file}:${finding.line}`);
  console.log(`  Severity: ${finding.severity}`);
}
```

---

## SecretsScanner

Scanner that detects leaked secrets (API keys, tokens, credentials) using 149+ regex patterns and Shannon entropy analysis.

**Import:**

```typescript
import { SecretsScanner } from 'frontguard';
```

### `scanFile(file: FileContent, config: FrontGuardConfig): Finding[]`

Scans a file looking for known secret patterns and high-entropy strings. Automatically ignores binary files, `.lock`, `.svg`, `.map`, and minified files.

Detected providers include: AWS, Google, GitHub, Stripe, Slack, Firebase, OpenAI, Anthropic, npm, Docker Hub, Twilio, SendGrid, Azure, Supabase, and dozens more.

```typescript
import { SecretsScanner, readFileContent, getDefaultConfig } from 'frontguard';

const scanner = new SecretsScanner();
scanner.init();

const file = readFileContent('./src/config/api.ts');
const findings = scanner.scanFile(file, getDefaultConfig());

for (const finding of findings) {
  console.log(`${finding.title} at line ${finding.line}`);
}
```

---

## DependencyScanner

Scanner that checks project dependencies against the OSV.dev database to find known vulnerabilities.

**Import:**

```typescript
import { DependencyScanner } from 'frontguard';
```

### `scan(files: FileContent[], config: FrontGuardConfig): Promise<Finding[]>`

Overrides the base `scan()` method to read the project's `package.json` and query the OSV API. The `scanFile()` method is a no-op in this scanner.

```typescript
import { DependencyScanner, getDefaultConfig, discoverFiles, readFileContent } from 'frontguard';

const scanner = new DependencyScanner();
scanner.init();

const config = getDefaultConfig();
const filePaths = await discoverFiles('.', config);
const files = filePaths.map(readFileContent);

const findings = await scanner.scan(files, config);
console.log(`Vulnerable dependencies: ${findings.length}`);
```

---

## AuthPatternsScanner

Scanner that detects insecure authentication patterns using AST analysis.

**Import:**

```typescript
import { AuthPatternsScanner } from 'frontguard';
```

### `scanFile(file: FileContent, config: FrontGuardConfig): Finding[]`

Detects tokens in localStorage/sessionStorage, tokens in URLs, and hardcoded credentials.

```typescript
import { AuthPatternsScanner, readFileContent, getDefaultConfig } from 'frontguard';

const scanner = new AuthPatternsScanner();
scanner.init();

const file = readFileContent('./src/auth/login.ts');
const findings = scanner.scanFile(file, getDefaultConfig());

for (const f of findings) {
  console.log(`[${f.severity.toUpperCase()}] ${f.title}`);
}
```

---

## MisconfigScanner

Scanner that detects security misconfigurations in configuration files and HTML.

**Import:**

```typescript
import { MisconfigScanner } from 'frontguard';
```

### `scanFile(file: FileContent, config: FrontGuardConfig): Finding[]`

Detects exposed source maps, mixed content (HTTP in HTTPS context), and CDN resources without integrity verification (SRI).

```typescript
import { MisconfigScanner, readFileContent, getDefaultConfig } from 'frontguard';

const scanner = new MisconfigScanner();
scanner.init();

const file = readFileContent('./public/index.html');
const findings = scanner.scanFile(file, getDefaultConfig());

findings.forEach(f => {
  console.log(`${f.title} - ${f.file}:${f.line}`);
});
```

---

## FeedManager

Vulnerability feed manager. Queries multiple sources (OSV, GitHub Advisory, NVD) and maintains a local JSON file cache at `~/.frontguard/cache.json`. No native dependencies required.

**Import:**

```typescript
import { FeedManager } from 'frontguard/feed/feed-manager';
```

### `new FeedManager(config: FrontGuardConfig)`

Creates a feed manager based on the configuration. Initializes the sources configured in `config.feed.sources`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `config` | `FrontGuardConfig` | Configuration with feed options, tokens, and API keys |

---

### `update(verbose?: boolean): Promise<number>`

Updates the local cache by querying all configured sources in parallel.

| Parameter | Type | Description |
|-----------|------|-------------|
| `verbose` | `boolean?` | If `true`, prints detailed logs |

**Returns:** `Promise<number>` — Number of entries inserted/updated.

```typescript
const manager = new FeedManager(config);

const count = await manager.update(true);
console.log(`${count} vulnerabilities updated in cache`);

manager.close();
```

---

### `getStatus(): Promise<CacheStatus>`

Returns the current state of the local cache.

**Returns:** `Promise<CacheStatus>` — Object with `totalEntries`, `lastUpdate`, and `isExpired`.

```typescript
const status = await manager.getStatus();
console.log(`Entries: ${status.totalEntries}`);
console.log(`Last update: ${status.lastUpdate}`);
console.log(`Expired: ${status.isExpired}`);
```

---

### `checkPackage(name: string, version: string): Promise<VulnEntry[]>`

Queries the local cache for vulnerabilities of a specific package.

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `string` | npm package name |
| `version` | `string` | Package version |

**Returns:** `Promise<VulnEntry[]>`

```typescript
const vulns = await manager.checkPackage('lodash', '4.17.20');
if (vulns.length > 0) {
  console.log(`lodash 4.17.20 has ${vulns.length} known vulnerabilities`);
}
```

---

### `ensureFresh(): Promise<void>`

Checks if the cache is expired and, if so, performs an automatic update.

```typescript
await manager.ensureFresh();
// Cache is now up to date
const vulns = await manager.checkPackage('express', '4.18.0');
```

---

### `close(): void`

Releases resources. Safe to call when done with the manager.

---

## VulnCache

Local JSON file cache for vulnerabilities. Stored at `~/.frontguard/cache.json`.

### `new VulnCache()`

Creates or opens the JSON cache file. Creates the `~/.frontguard/` directory if it doesn't exist.

---

### `upsertMany(entries: VulnEntry[]): number`

Inserts or updates multiple vulnerability entries atomically.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entries` | `VulnEntry[]` | Array of vulnerability entries |

**Returns:** `number` — Number of entries processed.

---

### `query(packageName: string, version?: string): VulnEntry[]`

Queries vulnerabilities by package name and, optionally, version.

| Parameter | Type | Description |
|-----------|------|-------------|
| `packageName` | `string` | Package name |
| `version` | `string?` | Specific version |

**Returns:** `VulnEntry[]`

---

### `getStatus(ttl: string): CacheStatus`

Returns cache status including total entries, last update timestamp, and expiration state.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ttl` | `string` | Time-to-live in format `'24h'`, `'7d'`, or `'30m'` |

**Returns:** `CacheStatus`

---

### `isExpired(ttl: string): boolean`

Checks whether the cache is expired based on the given TTL.

| Parameter | Type | Description |
|-----------|------|-------------|
| `ttl` | `string` | Time-to-live in format `'24h'`, `'7d'`, or `'30m'` |

**Returns:** `boolean`

---

## AIEngine

Artificial intelligence engine for deep analysis, fix generation, cross-file data flow analysis, and custom rule evaluation.

**Import:**

```typescript
import { AIEngine } from 'frontguard/ai/ai-engine';
```

### `new AIEngine(config: FrontGuardConfig)`

Creates the AI engine. The provider is automatically selected based on `config.ai.provider`.

| Provider | Default Model | Requires API Key |
|----------|---------------|------------------|
| `openai` | `gpt-4o-mini` | Yes |
| `anthropic` | `claude-sonnet-4-20250514` | Yes |
| `google` | `gemini-2.0-flash` | Yes |
| `ollama` | `llama3` | No (local) |

---

### `isConfigured(): boolean`

Checks whether the provider is properly configured. Ollama always returns `true` (no API key required).

**Returns:** `boolean`

```typescript
const ai = new AIEngine(config);

if (!ai.isConfigured()) {
  console.warn('AI not configured. Please set an API key.');
}
```

---

### `deepScan(findings: Finding[], files: FileContent[]): Promise<AIFinding[]>`

Deep analysis of existing findings using AI to reduce false positives and increase confidence.

| Parameter | Type | Description |
|-----------|------|-------------|
| `findings` | `Finding[]` | Findings from the static scan |
| `files` | `FileContent[]` | Project files |

**Returns:** `Promise<AIFinding[]>` — Enriched findings with `aiConfidence` and `aiAnalyzed: true`.

```typescript
const ai = new AIEngine(config);
const enriched = await ai.deepScan(result.findings, files);

for (const f of enriched) {
  console.log(`${f.title} — AI Confidence: ${(f.aiConfidence * 100).toFixed(0)}%`);
}
```

---

### `generateFixes(findings: Finding[], files: FileContent[]): Promise<Map<string, string>>`

Generates fix suggestions for each finding.

| Parameter | Type | Description |
|-----------|------|-------------|
| `findings` | `Finding[]` | Findings to fix |
| `files` | `FileContent[]` | Project files |

**Returns:** `Promise<Map<string, string>>` — Map of `ruleId` to suggested diff/fix.

```typescript
const fixes = await ai.generateFixes(result.findings, files);

for (const [ruleId, diff] of fixes) {
  console.log(`--- Fix for ${ruleId} ---`);
  console.log(diff);
}
```

---

### `analyzeDataFlow(files: FileContent[]): Promise<DataFlowResult[]>`

Analyzes data flow between files to detect sensitive data propagation patterns.

| Parameter | Type | Description |
|-----------|------|-------------|
| `files` | `FileContent[]` | Project files |

**Returns:** `Promise<DataFlowResult[]>` — Results with source, sinks, path, and risk level.

```typescript
const flows = await ai.analyzeDataFlow(files);

for (const flow of flows) {
  console.log(`Source: ${flow.source.file}:${flow.source.line}`);
  console.log(`Risk: ${flow.risk}`);
  console.log(`Path: ${flow.path.join(' → ')}`);
  for (const sink of flow.sinks) {
    console.log(`  → Sink: ${sink.file}:${sink.line}`);
  }
}
```

---

### `evaluateCustomRules(rules: string[], files: FileContent[]): Promise<AIFinding[]>`

Evaluates security rules written in natural language.

| Parameter | Type | Description |
|-----------|------|-------------|
| `rules` | `string[]` | Rules in natural language |
| `files` | `FileContent[]` | Project files |

**Returns:** `Promise<AIFinding[]>`

```typescript
const customFindings = await ai.evaluateCustomRules(
  [
    'Verify that user data is validated before database insertion',
    'Ensure all API routes require authentication',
  ],
  files,
);
```

---

## Reporters

### ConsoleReporter

Default reporter that formats output to the terminal. The actual formatting is handled by the CLI UI functions.

```typescript
import { ConsoleReporter } from 'frontguard';

const reporter = new ConsoleReporter();
// name: 'console'
```

### JsonReporter

Generates a structured JSON report with summary and detailed findings.

```typescript
import { JsonReporter } from 'frontguard';

const reporter = new JsonReporter('./frontguard-report');
// Generates: ./frontguard-report/frontguard-report.json
```

**Generated JSON structure:**

```typescript
{
  timestamp: string;
  summary: {
    totalFindings: number;
    bySeverity: Record<Severity, number>;
    scannedFiles: number;
    scanDuration: number;
  };
  findings: Finding[];
}
```

### HtmlReporter

Generates an interactive HTML dashboard with SVG charts, filters, search, CSV export, and dark/light theme toggle.

```typescript
import { HtmlReporter } from 'frontguard';

const reporter = new HtmlReporter('./frontguard-report');
// Generates: ./frontguard-report/frontguard-report.html
```

### SarifReporter

Generates a report in SARIF (Static Analysis Results Interchange Format), compatible with GitHub Code Scanning, Azure DevOps, and other CI/CD tools.

```typescript
import { SarifReporter } from 'frontguard';

const reporter = new SarifReporter('./frontguard-report/report.sarif');
// Generates: ./frontguard-report/report.sarif
```

---

## Severity Utilities

Utility functions for working with severity levels.

**Import:**

```typescript
import { meetsThreshold, compareSeverity, severityToNumber } from 'frontguard';
```

### `severityToNumber(severity: Severity): number`

Converts a severity level to a numeric value.

| Severity | Value |
|----------|-------|
| `critical` | 5 |
| `high` | 4 |
| `medium` | 3 |
| `low` | 2 |
| `info` | 1 |

```typescript
severityToNumber('critical'); // 5
severityToNumber('low');      // 2
```

---

### `compareSeverity(a: Severity, b: Severity): number`

Compares two severity levels. Returns negative if `a` is more severe, positive if `b` is more severe, zero if equal.

```typescript
compareSeverity('critical', 'low');  // < 0 (critical is more severe)
compareSeverity('low', 'high');      // > 0 (high is more severe)
compareSeverity('medium', 'medium'); // 0
```

---

### `meetsThreshold(severity: Severity, threshold: Severity): boolean`

Checks whether a severity meets or exceeds a threshold.

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | `Severity` | Severity to check |
| `threshold` | `Severity` | Minimum threshold |

**Returns:** `boolean`

```typescript
meetsThreshold('critical', 'high'); // true
meetsThreshold('medium', 'high');   // false
meetsThreshold('high', 'high');     // true
```

---

## Exported Types

FrontGuard exports the following types from the main module:

```typescript
import type {
  Finding,
  ScanResult,
  FrontGuardConfig,
  RuleDefinition,
  Severity,        // 'critical' | 'high' | 'medium' | 'low' | 'info'
  RuleLevel,       // 'error' | 'warn' | 'off'
  ScannerCategory, // 'xss' | 'dependencies' | 'secrets' | 'misconfig' | 'auth-patterns'
  FileContent,
  Reporter,
} from 'frontguard';
```
