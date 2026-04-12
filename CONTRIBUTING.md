# Contributing to FrontGuard

Thank you for your interest in contributing to FrontGuard! This guide will help you set up the development environment, understand the project structure, and submit your contributions.

---

## Table of Contents

- [Setting Up the Development Environment](#setting-up-the-development-environment)
- [Project Structure](#project-structure)
- [How to Create a New Scanner](#how-to-create-a-new-scanner)
- [How to Add a New Rule](#how-to-add-a-new-rule)
- [How to Create a New Reporter](#how-to-create-a-new-reporter)
- [Code Standards](#code-standards)
- [Running Tests](#running-tests)
- [How to Submit a PR](#how-to-submit-a-pr)
- [Code of Conduct](#code-of-conduct)

---

## Setting Up the Development Environment

### Prerequisites

- **Node.js** >= 18
- **pnpm** (package manager)
- **Git**

### Step by Step

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/your-username/frontguard.git
cd frontguard

# 3. Install dependencies
pnpm install

# 4. Verify everything works
pnpm test       # run tests
pnpm typecheck  # check types
pnpm lint       # run linter
pnpm build      # build the project

# 5. Start development mode
pnpm dev        # auto-recompiles on save
```

### Watch Mode

```bash
# Tests in watch mode
pnpm test:watch

# Build in watch mode
pnpm dev
```

---

## Project Structure

```
frontguard/
├── src/
│   ├── index.ts                    # Main barrel export
│   ├── core/
│   │   ├── types.ts                # Central types and interfaces
│   │   ├── config.ts               # Configuration loading and merging
│   │   ├── engine.ts               # ScanEngine — orchestrator engine
│   │   ├── file-discovery.ts       # File discovery and reading
│   │   ├── rule-registry.ts        # Global rule registry (singleton)
│   │   └── severity.ts             # Severity utilities
│   ├── scanners/
│   │   ├── base-scanner.ts         # Abstract base class for scanners
│   │   ├── xss/                    # XSS scanner (8 rules)
│   │   │   ├── index.ts
│   │   │   └── rules/              # One rule per file
│   │   ├── secrets/                # Secrets scanner (6 rules, 149+ patterns)
│   │   │   ├── index.ts
│   │   │   ├── patterns.ts
│   │   │   └── entropy.ts
│   │   ├── dependencies/           # Dependencies scanner (2 rules)
│   │   │   ├── index.ts
│   │   │   └── osv-client.ts
│   │   ├── auth-patterns/          # Auth scanner (3 rules)
│   │   │   ├── index.ts
│   │   │   └── rules/
│   │   └── misconfig/              # Misconfiguration scanner (3 rules)
│   │       ├── index.ts
│   │       └── rules/
│   ├── reporters/
│   │   ├── console-reporter.ts     # Terminal output
│   │   ├── json-reporter.ts        # JSON report
│   │   ├── html-reporter.ts        # HTML dashboard
│   │   └── sarif-reporter.ts       # SARIF format
│   ├── feed/
│   │   ├── types.ts                # Feed types
│   │   ├── cache.ts                # Local SQLite cache
│   │   ├── feed-manager.ts         # Source manager
│   │   └── sources/                # Data sources (OSV, GitHub, NVD)
│   ├── ai/
│   │   ├── types.ts                # AI interfaces
│   │   ├── ai-engine.ts            # AI orchestrator engine
│   │   ├── providers/              # Providers (OpenAI, Anthropic, Google, Ollama)
│   │   └── prompts/                # Prompt templates
│   └── cli/
│       ├── index.ts                # CLI entry point
│       ├── ui.ts                   # Terminal UI functions
│       └── commands/               # Commands (scan, init, report, update, auth)
├── test/
│   ├── fixtures/                   # Vulnerable code fixtures
│   └── scanners/                   # Unit tests
├── docs/                           # Documentation
├── package.json
├── tsconfig.json
└── CONTRIBUTING.md                 # This file
```

### Key Concepts

- **Scanner**: A module that analyzes files looking for a specific category of vulnerability
- **Rule**: An individual definition of a vulnerability pattern within a scanner
- **Finding**: An occurrence of a detected vulnerability in a file
- **Reporter**: A module that formats and exports scan results
- **RuleRegistry**: A global singleton that stores all registered rules

---

## How to Create a New Scanner

### 1. Create the directory and main file

```
src/scanners/my-scanner/
├── index.ts
└── rules/
    ├── my-rule-001.ts
    └── my-rule-002.ts
```

### 2. Define the rules

```typescript
// src/scanners/my-scanner/rules/my-rule-001.ts
import type { FileContent, RuleDefinition } from '../../../core/types.js';

export interface RuleHit {
  line: number;
  column: number;
}

export const rule: RuleDefinition = {
  id: 'FG-CUSTOM-001',
  title: 'My Security Rule',
  description: 'Detailed description of what the rule detects and why it is dangerous.',
  severity: 'high',
  category: 'misconfig',  // or another existing category
  cwe: 'CWE-XXX',
  owasp: 'AXX:2021',
  remediation: 'Clear instructions on how to fix the issue.',
};

export function check(file: FileContent): RuleHit[] {
  const hits: RuleHit[] = [];

  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i];
    const match = /dangerous_pattern/.exec(line);
    if (match) {
      hits.push({ line: i + 1, column: match.index + 1 });
    }
  }

  return hits;
}
```

### 3. Implement the scanner

```typescript
// src/scanners/my-scanner/index.ts
import type {
  FileContent,
  Finding,
  FrontGuardConfig,
  RuleDefinition,
  ScannerCategory,
} from '../../core/types.js';
import { BaseScanner } from '../base-scanner.js';

import { rule as rule001, check as checkRule001 } from './rules/my-rule-001.js';
import { rule as rule002, check as checkRule002 } from './rules/my-rule-002.js';

interface RuleHit { line: number; column: number; }
type RuleCheckFn = (file: FileContent) => RuleHit[];
interface RuleEntry { rule: RuleDefinition; check: RuleCheckFn; }

const ALL_RULES: RuleEntry[] = [
  { rule: rule001, check: checkRule001 },
  { rule: rule002, check: checkRule002 },
];

export class MyScanner extends BaseScanner {
  readonly name = 'My Scanner';
  readonly category: ScannerCategory = 'misconfig';

  getRules(): RuleDefinition[] {
    return ALL_RULES.map(entry => entry.rule);
  }

  scanFile(file: FileContent, _config: FrontGuardConfig): Finding[] {
    const findings: Finding[] = [];

    for (const { rule, check } of ALL_RULES) {
      try {
        const hits = check(file);
        for (const hit of hits) {
          findings.push(this.createFinding(rule, file, hit.line, hit.column));
        }
      } catch {
        // skip rule on failure
      }
    }

    return findings;
  }
}
```

### 4. Register the scanner

Add the export to `src/index.ts`:

```typescript
export { MyScanner } from './scanners/my-scanner/index.js';
```

If needed, add the category to `src/core/types.ts`:

```typescript
export type ScannerCategory = 'xss' | 'dependencies' | 'secrets' | 'misconfig' | 'auth-patterns' | 'my-category';
```

And in the `ScanEngine` at `src/core/engine.ts`, add the mapping:

```typescript
const map: Record<string, boolean> = {
  // ... existing entries ...
  'my-category': config.scanners.myCategory ?? true,
};
```

### 5. Add tests

```typescript
// test/scanners/my-scanner.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { MyScanner } from '../../src/scanners/my-scanner/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

describe('MyScanner', () => {
  let scanner: MyScanner;
  let config: FrontGuardConfig;

  beforeEach(() => {
    scanner = new MyScanner();
    scanner.init();
    config = getDefaultConfig();
  });

  it('should detect the dangerous pattern', () => {
    const file: FileContent = {
      path: 'test.ts',
      content: 'code with dangerous_pattern here',
      lines: ['code with dangerous_pattern here'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-CUSTOM-001');
  });

  it('should not produce false positives', () => {
    const file: FileContent = {
      path: 'safe.ts',
      content: 'safe code without issues',
      lines: ['safe code without issues'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });
});
```

---

## How to Add a New Rule

To add a rule to an existing scanner:

### 1. Create the rule file

```typescript
// src/scanners/xss/rules/my-new-rule.ts
import type { FileContent, RuleDefinition } from '../../../core/types.js';
import type { RuleHit } from '../index.js';

export const rule: RuleDefinition = {
  id: 'FG-XSS-009',
  title: 'Descriptive Rule Name',
  description: 'Why this is dangerous and how it can be exploited.',
  severity: 'high',
  category: 'xss',
  cwe: 'CWE-79',
  owasp: 'A03:2021 - Injection',
  remediation: 'How to fix the issue.',
};

export function check(file: FileContent): RuleHit[] {
  const hits: RuleHit[] = [];
  // Implement detection logic
  return hits;
}
```

### 2. Register in the scanner

```typescript
// src/scanners/xss/index.ts
import { rule as newRule, check as checkNewRule } from './rules/my-new-rule.js';

const ALL_RULES: RuleEntry[] = [
  // ... existing rules ...
  { rule: newRule, check: checkNewRule },
];
```

### 3. Add tests

Add tests in the corresponding test file (`test/scanners/xss.test.ts`).

### 4. Document

Add the rule to `docs/RULES.md` following the existing format.

---

## How to Create a New Reporter

### 1. Implement the `Reporter` interface

```typescript
// src/reporters/my-reporter.ts
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Reporter, ScanResult } from '../core/types.js';

export class MyReporter implements Reporter {
  name = 'my-format';

  constructor(private outputDir: string) {}

  async generate(result: ScanResult): Promise<string> {
    await mkdir(this.outputDir, { recursive: true });

    const content = this.formatResult(result);
    const filePath = join(this.outputDir, 'frontguard-report.custom');

    await writeFile(filePath, content, 'utf-8');
    return filePath;
  }

  private formatResult(result: ScanResult): string {
    return JSON.stringify(result.findings, null, 2);
  }
}
```

### 2. Export in `src/index.ts`

```typescript
export { MyReporter } from './reporters/my-reporter.js';
```

### 3. Use with ScanEngine

```typescript
const engine = new ScanEngine();
engine.registerReporter(new MyReporter('./reports'));
```

---

## Code Standards

### TypeScript

- **Strict mode** enabled (`strict: true` in tsconfig)
- **ESM** (ECMAScript Modules) — use `import`/`export`, never `require`
- **`.js` extension** in imports: `import { foo } from './bar.js'` (required for ESM)
- **Target**: ES2022

### Style

- Use `const` by default, `let` when necessary, never `var`
- Prefer pure functions and immutability
- Use explicit types in public signatures
- Avoid `any` — use `unknown` when the type is not known

### Formatting

```bash
# Format all code
pnpm format

# Check linting
pnpm lint
```

- **Prettier** for automatic formatting
- **ESLint** for code quality rules
- Indentation: 2 spaces
- Single quotes for strings

### Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Files | kebab-case | `my-scanner.ts` |
| Classes | PascalCase | `MyScanner` |
| Functions | camelCase | `scanFile()` |
| Constants | UPPER_SNAKE_CASE | `MAX_RETRY` |
| Types/Interfaces | PascalCase | `ScanResult` |
| Rule IDs | `FG-CAT-NNN` | `FG-XSS-001` |

### Imports

Order imports in this sequence:

1. Native Node modules (`node:fs`, `node:path`)
2. External dependencies (`@babel/parser`, `chalk`)
3. Internal modules (`../core/types.js`)

---

## Running Tests

```bash
# All tests
pnpm test

# Watch mode
pnpm test:watch

# Specific scanner
pnpm test -- --grep "XSS"
pnpm test -- test/scanners/xss.test.ts

# With coverage
pnpm test -- --coverage

# Type checking
pnpm typecheck
```

### Writing Good Tests

- Test both vulnerable **and** safe code
- Verify `ruleId`, severity, and line numbers
- Use `beforeEach` for fresh instances
- One `.test.ts` file per scanner
- Fixtures in `test/fixtures/`

---

## How to Submit a PR

### 1. Create a branch

```bash
git checkout -b feat/my-new-scanner
# or
git checkout -b fix/fix-false-positive
```

### Branch naming convention

| Prefix | Usage |
|--------|-------|
| `feat/` | New feature |
| `fix/` | Bug fix |
| `docs/` | Documentation |
| `refactor/` | Refactoring |
| `test/` | Adding/fixing tests |

### 2. Make your changes

- Write code following the [Code Standards](#code-standards)
- Add tests for new features
- Update documentation when needed

### 3. Verify before committing

```bash
pnpm test        # all tests passing
pnpm typecheck   # no type errors
pnpm lint        # no lint errors
pnpm build       # successful build
```

### 4. Commit and push

```bash
git add .
git commit -m "feat: add performance scanner"
git push origin feat/my-new-scanner
```

### Commit convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Usage |
|--------|-------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation |
| `refactor:` | Refactoring (no behavior change) |
| `test:` | Adding/fixing tests |
| `chore:` | Maintenance (deps, CI, config) |

### 5. Open the Pull Request

- Clearly describe what was changed and why
- Reference related issues (`Closes #123`)
- Include output examples when relevant
- Make sure CI is passing

---

## Code of Conduct

### Our Pledge

We as contributors and maintainers pledge to make participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to a positive environment:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior:

- Use of sexualized language or imagery
- Insulting/derogatory comments and personal or political attacks
- Public or private harassment
- Publishing others' private information without permission
- Any conduct that would reasonably be considered inappropriate in a professional setting

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project maintainers. All complaints will be reviewed and investigated, resulting in a response deemed necessary and appropriate to the circumstances.

---

## Questions?

If you have questions about contributing, open an [issue](https://github.com/your-username/frontguard/issues) with the `question` tag or start a [discussion](https://github.com/your-username/frontguard/discussions).

Thank you for contributing to FrontGuard!
