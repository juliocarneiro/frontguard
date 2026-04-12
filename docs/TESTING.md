# FrontGuard — Complete Testing Guide

Comprehensive guide for running, creating, and organizing tests in FrontGuard.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Test Commands](#test-commands)
- [Test Directory Structure](#test-directory-structure)
- [Test Fixtures](#test-fixtures)
- [Testing Each Scanner](#testing-each-scanner)
- [Testing the CVE Feed](#testing-the-cve-feed)
- [Testing AI Integration](#testing-ai-integration)
- [Expected Outputs](#expected-outputs)
- [Adding New Tests](#adding-new-tests)

---

## Prerequisites

### Installing Dependencies

```bash
# Clone the repository
git clone https://github.com/your-username/frontguard.git
cd frontguard

# Install dependencies with pnpm
pnpm install
```

FrontGuard uses [Vitest](https://vitest.dev/) as its testing framework. It is already included in devDependencies.

### Verify Installation

```bash
# Verify that vitest is available
pnpm vitest --version
```

---

## Test Commands

### Run all tests

```bash
pnpm test
```

This command runs `vitest run`, which executes all tests once and exits.

### Run tests in watch mode

```bash
pnpm test:watch
```

Runs `vitest` in watch mode — automatically re-runs tests when files change. Ideal during development.

### Run tests for a specific scanner

```bash
# Filter by test name
pnpm test -- --grep "XSS"
pnpm test -- --grep "Secrets"
pnpm test -- --grep "Auth"
pnpm test -- --grep "Misconfig"

# Run a specific test file
pnpm test -- test/scanners/xss.test.ts
pnpm test -- test/scanners/secrets.test.ts
pnpm test -- test/scanners/auth-patterns.test.ts
pnpm test -- test/scanners/misconfig.test.ts
```

### Run tests with coverage

```bash
pnpm test -- --coverage
```

### Other useful commands

```bash
# Run type checking
pnpm typecheck

# Run linter
pnpm lint

# Format code
pnpm format
```

---

## Test Directory Structure

```
test/
├── fixtures/                          # Intentionally vulnerable code files for tests
│   ├── xss-vulnerable.tsx             # XSS fixtures (innerHTML, eval, etc.)
│   ├── secrets-exposed.ts            # Secret fixtures (AWS keys, tokens, etc.)
│   └── insecure-auth.ts              # Insecure auth fixtures (localStorage, URLs)
└── scanners/                          # Scanner unit tests
    ├── xss.test.ts                    # 15 tests — XSSScanner
    ├── secrets.test.ts                # 14 tests — SecretsScanner
    ├── auth-patterns.test.ts          # 12 tests — AuthPatternsScanner
    └── misconfig.test.ts              # 12 tests — MisconfigScanner
```

---

## Test Fixtures

Fixtures are intentionally vulnerable code files used as input for the tests.

### Creating Fixtures

To create a new fixture, add a file in `test/fixtures/` with code containing the patterns you want to test. Each fixture should have clear and predictable vulnerabilities.

### XSS Fixture (`test/fixtures/xss-vulnerable.tsx`)

```typescript
import React from 'react';

export function VulnerableComponent() {
  const userInput = '<img src=x onerror=alert(1)>';

  // FG-XSS-001: innerHTML
  document.getElementById('app')!.innerHTML = userInput;

  // FG-XSS-002: eval
  eval('alert("xss")');

  // FG-XSS-003: document.write
  document.write('<script>alert(1)</script>');

  // FG-XSS-004: dangerouslySetInnerHTML
  return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
}

// FG-XSS-007: outerHTML
document.body.outerHTML = '<div>replaced</div>';

// FG-XSS-008: javascript: URL
const link = 'javascript:alert(1)';

// FG-XSS-002: setTimeout with string
setTimeout('alert("xss")', 1000);

// FG-XSS-002: new Function
const fn = new Function('return 1');
```

### Secrets Fixture (`test/fixtures/secrets-exposed.ts`)

```typescript
// FG-SEC-001: AWS credentials
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// FG-SEC-002: API tokens
const GITHUB_TOKEN = 'ghp_yourTokenHere1234';
const STRIPE_KEY = 'sk_test_yourKeyHere';
const SLACK_TOKEN = 'xoxb-your-slack-token';

// FG-SEC-003: Private key
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;

// FG-SEC-004: JWT
const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

// FG-SEC-005: Database URIs
const PG_URI = 'postgresql://admin:s3cr3t@db.example.com:5432/mydb';
const MONGO_URI = 'mongodb://root:password123@mongo.example.com:27017/admin';
```

### Insecure Auth Fixture (`test/fixtures/insecure-auth.ts`)

```typescript
// FG-AUTH-001: Tokens in Web Storage
localStorage.setItem('token', jwtToken);
localStorage.setItem('access_token', response.token);
sessionStorage.setItem('authToken', token);

// FG-AUTH-002: Tokens in URLs
const apiUrl = `https://api.example.com/data?access_token=${token}`;
const url = `https://api.example.com?api_key=${key}`;
fetch(`/api/resource?token=${userToken}`);

// FG-AUTH-003: Hardcoded credentials
const password = 'super_secret_123';
const config = {
  password: 'admin123',
  secret: 'my-secret-key',
  secretKey: 'sk-1234567890',
};
```

---

## Testing Each Scanner

### XSSScanner

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { XSSScanner } from '../../src/scanners/xss/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

describe('XSSScanner', () => {
  let scanner: XSSScanner;
  let config: FrontGuardConfig;

  beforeEach(() => {
    scanner = new XSSScanner();
    scanner.init();
    config = getDefaultConfig();
  });

  it('should detect innerHTML assignment', () => {
    const file: FileContent = {
      path: 'test.ts',
      content: 'document.getElementById("app").innerHTML = userInput;',
      lines: ['document.getElementById("app").innerHTML = userInput;'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('FG-XSS-001');
  });

  it('should detect eval()', () => {
    const file: FileContent = {
      path: 'test.ts',
      content: 'const result = eval(userInput);',
      lines: ['const result = eval(userInput);'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-XSS-002')).toBe(true);
  });

  it('should detect document.write()', () => {
    const file: FileContent = {
      path: 'test.ts',
      content: 'document.write("<h1>" + title + "</h1>");',
      lines: ['document.write("<h1>" + title + "</h1>");'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-XSS-003')).toBe(true);
  });

  it('should detect dangerouslySetInnerHTML', () => {
    const file: FileContent = {
      path: 'test.tsx',
      content: 'const el = <div dangerouslySetInnerHTML={{ __html: data }} />;',
      lines: ['const el = <div dangerouslySetInnerHTML={{ __html: data }} />;'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-XSS-004')).toBe(true);
  });

  it('should detect v-html in Vue templates', () => {
    const file: FileContent = {
      path: 'test.vue',
      content: '<template><div v-html="userContent"></div></template>',
      lines: ['<template><div v-html="userContent"></div></template>'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-XSS-005')).toBe(true);
  });

  it('should detect bypassSecurityTrust (Angular)', () => {
    const file: FileContent = {
      path: 'test.ts',
      content: 'this.sanitizer.bypassSecurityTrustHtml(userInput);',
      lines: ['this.sanitizer.bypassSecurityTrustHtml(userInput);'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-XSS-006')).toBe(true);
  });

  it('should not generate findings for safe code', () => {
    const file: FileContent = {
      path: 'safe.ts',
      content: 'element.textContent = userInput;\nconsole.log("hello");',
      lines: ['element.textContent = userInput;', 'console.log("hello");'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });
});
```

### SecretsScanner

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { SecretsScanner } from '../../src/scanners/secrets/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

describe('SecretsScanner', () => {
  let scanner: SecretsScanner;
  let config: FrontGuardConfig;

  beforeEach(() => {
    scanner = new SecretsScanner();
    scanner.init();
    config = getDefaultConfig();
  });

  it('should detect AWS access key', () => {
    const file: FileContent = {
      path: 'config.ts',
      content: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      lines: ['const key = "AKIAIOSFODNN7EXAMPLE";'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-SEC-001')).toBe(true);
  });

  it('should detect GitHub token', () => {
    const file: FileContent = {
      path: 'api.ts',
      content: 'const token = "ghp_yourTokenHere1234";',
      lines: ['const token = "ghp_yourTokenHere1234";'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-SEC-002')).toBe(true);
  });

  it('should detect RSA private key', () => {
    const file: FileContent = {
      path: 'key.ts',
      content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...',
      lines: ['-----BEGIN RSA PRIVATE KEY-----', 'MIIEowIBAAKCAQEA...'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-SEC-003')).toBe(true);
  });

  it('should detect hardcoded JWT', () => {
    const file: FileContent = {
      path: 'auth.ts',
      content: 'const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";',
      lines: ['const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-SEC-004')).toBe(true);
  });

  it('should detect PostgreSQL connection string', () => {
    const file: FileContent = {
      path: 'db.ts',
      content: 'const uri = "postgresql://admin:s3cr3t@db.example.com:5432/mydb";',
      lines: ['const uri = "postgresql://admin:s3cr3t@db.example.com:5432/mydb";'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-SEC-005')).toBe(true);
  });

  it('should ignore binary and minified files', () => {
    const file: FileContent = {
      path: 'bundle.min.js',
      content: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      lines: ['const key = "AKIAIOSFODNN7EXAMPLE";'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });

  it('should not generate findings for code without secrets', () => {
    const file: FileContent = {
      path: 'safe.ts',
      content: 'const name = "John Doe";\nconst age = 30;',
      lines: ['const name = "John Doe";', 'const age = 30;'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });
});
```

### AuthPatternsScanner

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { AuthPatternsScanner } from '../../src/scanners/auth-patterns/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

describe('AuthPatternsScanner', () => {
  let scanner: AuthPatternsScanner;
  let config: FrontGuardConfig;

  beforeEach(() => {
    scanner = new AuthPatternsScanner();
    scanner.init();
    config = getDefaultConfig();
  });

  it('should detect token in localStorage', () => {
    const file: FileContent = {
      path: 'auth.ts',
      content: 'localStorage.setItem("token", jwtToken);',
      lines: ['localStorage.setItem("token", jwtToken);'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-AUTH-001')).toBe(true);
  });

  it('should detect token in URL', () => {
    const file: FileContent = {
      path: 'api.ts',
      content: 'const url = `https://api.example.com?access_token=${token}`;',
      lines: ['const url = `https://api.example.com?access_token=${token}`;'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-AUTH-002')).toBe(true);
  });

  it('should detect hardcoded credentials', () => {
    const file: FileContent = {
      path: 'config.ts',
      content: 'const password = "super_secret_123";',
      lines: ['const password = "super_secret_123";'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-AUTH-003')).toBe(true);
  });

  it('should not generate findings for safe code', () => {
    const file: FileContent = {
      path: 'safe.ts',
      content: 'const user = await getUser();\nconsole.log(user.name);',
      lines: ['const user = await getUser();', 'console.log(user.name);'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });
});
```

### MisconfigScanner

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { MisconfigScanner } from '../../src/scanners/misconfig/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

describe('MisconfigScanner', () => {
  let scanner: MisconfigScanner;
  let config: FrontGuardConfig;

  beforeEach(() => {
    scanner = new MisconfigScanner();
    scanner.init();
    config = getDefaultConfig();
  });

  it('should detect exposed sourceMappingURL', () => {
    const file: FileContent = {
      path: 'bundle.js',
      content: '//# sourceMappingURL=bundle.js.map',
      lines: ['//# sourceMappingURL=bundle.js.map'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-CFG-001')).toBe(true);
  });

  it('should detect mixed HTTP content', () => {
    const file: FileContent = {
      path: 'index.html',
      content: '<script src="http://cdn.example.com/lib.js"></script>',
      lines: ['<script src="http://cdn.example.com/lib.js"></script>'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-CFG-002')).toBe(true);
  });

  it('should detect CDN without integrity check', () => {
    const file: FileContent = {
      path: 'index.html',
      content: '<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/dist/lib.min.js"></script>',
      lines: ['<script src="https://cdn.jsdelivr.net/npm/lib@1.0.0/dist/lib.min.js"></script>'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.some(f => f.ruleId === 'FG-CFG-003')).toBe(true);
  });

  it('should ignore CDN with integrity', () => {
    const file: FileContent = {
      path: 'index.html',
      content: '<script src="https://cdn.jsdelivr.net/npm/lib@1.0/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>',
      lines: ['<script src="https://cdn.jsdelivr.net/npm/lib@1.0/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings.filter(f => f.ruleId === 'FG-CFG-003')).toHaveLength(0);
  });

  it('should not generate findings for safe code', () => {
    const file: FileContent = {
      path: 'safe.ts',
      content: 'const x = 1;\nconsole.log(x);',
      lines: ['const x = 1;', 'console.log(x);'],
    };

    const findings = scanner.scanFile(file, config);
    expect(findings).toHaveLength(0);
  });
});
```

---

## Testing the CVE Feed

To test the vulnerability feed without making real API calls, use Vitest mocks:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FeedManager } from '../../src/feed/feed-manager.js';
import { getDefaultConfig } from '../../src/core/config.js';
import type { VulnEntry } from '../../src/feed/types.js';

// Mock data sources
vi.mock('../../src/feed/sources/osv-source.js', () => ({
  OSVSource: class {
    name = 'osv';
    async fetch(): Promise<VulnEntry[]> {
      return [{
        id: 'GHSA-test-0001',
        source: 'osv',
        package: 'lodash',
        affectedVersions: '<4.17.21',
        severity: 'high',
        summary: 'Prototype Pollution in lodash',
        description: 'Lodash versions prior to 4.17.21 are vulnerable...',
        publishedAt: '2024-01-15T00:00:00Z',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
      }];
    }
  },
}));

vi.mock('../../src/feed/sources/github-source.js', () => ({
  GitHubSource: class {
    name = 'github';
    async fetch(): Promise<VulnEntry[]> { return []; }
  },
}));

vi.mock('../../src/feed/sources/nvd-source.js', () => ({
  NVDSource: class {
    name = 'nvd';
    async fetch(): Promise<VulnEntry[]> { return []; }
  },
}));

// Mock JSON cache (avoids writing to disk)
vi.mock('../../src/feed/cache.js', () => {
  const entries: VulnEntry[] = [];
  return {
    VulnCache: class {
      upsertMany(newEntries: VulnEntry[]) {
        entries.push(...newEntries);
        return newEntries.length;
      }
      query(name: string) {
        return entries.filter(e => e.package === name);
      }
      getStatus() {
        return {
          totalEntries: entries.length,
          lastUpdate: new Date().toISOString(),
          isExpired: false,
        };
      }
      isExpired() { return false; }
      close() {}
    },
  };
});

describe('FeedManager', () => {
  let manager: FeedManager;

  beforeEach(() => {
    manager = new FeedManager(getDefaultConfig());
  });

  it('should update the cache with data from sources', async () => {
    const count = await manager.update();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  it('should return cache status', async () => {
    const status = await manager.getStatus();
    expect(status).toHaveProperty('totalEntries');
    expect(status).toHaveProperty('lastUpdate');
    expect(status).toHaveProperty('isExpired');
  });

  it('should query packages in the cache', async () => {
    const vulns = await manager.checkPackage('lodash', '4.17.20');
    expect(Array.isArray(vulns)).toBe(true);
  });
});
```

---

## Testing AI Integration

To test the AI module without consuming real tokens, use mocks:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AIEngine } from '../../src/ai/ai-engine.js';
import { getDefaultConfig } from '../../src/core/config.js';
import type { FrontGuardConfig, Finding, FileContent } from '../../src/core/types.js';

// Mock OpenAI provider
vi.mock('../../src/ai/providers/openai.js', () => ({
  OpenAIProvider: class {
    name = 'openai';
    async analyze() {
      return [{
        ruleId: 'FG-XSS-001',
        severity: 'high',
        category: 'xss',
        title: 'Unsafe innerHTML Assignment',
        description: 'AI confirms: this innerHTML receives unsanitized user data.',
        file: 'test.ts',
        line: 5,
        column: 1,
        codeSnippet: '',
        remediation: 'Use DOMPurify.sanitize() before assigning to innerHTML.',
        aiAnalyzed: true,
        aiConfidence: 0.95,
      }];
    }
    async generateFix() {
      return '- element.innerHTML = userInput;\n+ element.innerHTML = DOMPurify.sanitize(userInput);';
    }
    async analyzeDataFlow() {
      return [{
        source: { file: 'input.ts', line: 10, description: 'User input' },
        sinks: [{ file: 'render.ts', line: 25, description: 'innerHTML assignment' }],
        path: ['input.ts:getInput()', 'process.ts:transform()', 'render.ts:display()'],
        risk: 'high',
      }];
    }
    async evaluateCustomRule() { return []; }
  },
}));

describe('AIEngine', () => {
  let engine: AIEngine;
  let config: FrontGuardConfig;

  beforeEach(() => {
    config = {
      ...getDefaultConfig(),
      ai: {
        ...getDefaultConfig().ai,
        enabled: true,
        provider: 'openai',
        apiKey: 'sk-test-key',
      },
    };
    engine = new AIEngine(config);
  });

  it('should verify it is configured', () => {
    expect(engine.isConfigured()).toBe(true);
  });

  it('should run deep scan', async () => {
    const mockFinding: Finding = {
      ruleId: 'FG-XSS-001',
      severity: 'high',
      category: 'xss',
      title: 'Unsafe innerHTML',
      description: 'test',
      file: 'test.ts',
      line: 5,
      column: 1,
      codeSnippet: '',
      remediation: 'fix it',
    };

    const results = await engine.deepScan([mockFinding], []);
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].aiAnalyzed).toBe(true);
    expect(results[0].aiConfidence).toBeGreaterThan(0);
  });

  it('should generate fixes', async () => {
    const mockFinding: Finding = {
      ruleId: 'FG-XSS-001',
      severity: 'high',
      category: 'xss',
      title: 'Unsafe innerHTML',
      description: 'test',
      file: 'test.ts',
      line: 5,
      column: 1,
      codeSnippet: '',
      remediation: 'fix it',
    };

    const mockFile: FileContent = {
      path: 'test.ts',
      content: 'element.innerHTML = userInput;',
      lines: ['element.innerHTML = userInput;'],
    };

    const fixes = await engine.generateFixes([mockFinding], [mockFile]);
    expect(fixes.size).toBeGreaterThan(0);
    expect(fixes.get('FG-XSS-001')).toContain('DOMPurify');
  });

  it('should analyze data flow between files', async () => {
    const files: FileContent[] = [
      { path: 'input.ts', content: 'export const getInput = () => prompt();', lines: ['export const getInput = () => prompt();'] },
      { path: 'render.ts', content: 'element.innerHTML = data;', lines: ['element.innerHTML = data;'] },
    ];

    const flows = await engine.analyzeDataFlow(files);
    expect(flows.length).toBeGreaterThan(0);
    expect(flows[0].source.file).toBe('input.ts');
  });
});
```

---

## Expected Outputs

### XSSScanner Output

```
[FG-XSS-001] Unsafe innerHTML Assignment
  File: src/components/UserProfile.tsx:12
  Severity: high
  CWE: CWE-79
  OWASP: A03:2021 - Injection
  Remediation: Use textContent or innerText for plain text...
```

### SecretsScanner Output

```
[FG-SEC-001] AWS Credentials Exposed
  File: src/config/aws.ts:5
  Severity: critical
  CWE: CWE-798
  Remediation: Remove the credentials from source code immediately...
```

### DependencyScanner Output

```
[FG-DEP-001] Known Vulnerability in Dependency
  Package: lodash@4.17.20
  Severity: high
  Vulnerability: Prototype Pollution (CVE-2021-23337)
```

### AuthPatternsScanner Output

```
[FG-AUTH-001] Token Stored in Web Storage
  File: src/auth/session.ts:15
  Severity: high
  CWE: CWE-922
  Remediation: Use httpOnly cookies instead of Web Storage...
```

### MisconfigScanner Output

```
[FG-CFG-003] CDN Resource Without Integrity Check
  File: public/index.html:8
  Severity: low
  CWE: CWE-353
  Remediation: Add integrity and crossorigin attributes...
```

---

## Adding New Tests

### When creating a new rule in an existing scanner

1. Add the rule definition in the scanner's rules file
2. Create a fixture in `test/fixtures/` with vulnerable code
3. Add tests in the corresponding `.test.ts` file:

```typescript
it('should detect my new rule', () => {
  const file: FileContent = {
    path: 'test.ts',
    content: 'vulnerable code here',
    lines: ['vulnerable code here'],
  };

  const findings = scanner.scanFile(file, config);
  expect(findings.some(f => f.ruleId === 'FG-NEW-001')).toBe(true);
  expect(findings[0].severity).toBe('high');
});

it('should not produce false positives for safe code', () => {
  const file: FileContent = {
    path: 'safe.ts',
    content: 'safe code here',
    lines: ['safe code here'],
  };

  const findings = scanner.scanFile(file, config);
  const relevant = findings.filter(f => f.ruleId === 'FG-NEW-001');
  expect(relevant).toHaveLength(0);
});
```

### When creating an entirely new scanner

1. Create the scanner in `src/scanners/new-scanner/index.ts`
2. Create the test file in `test/scanners/new-scanner.test.ts`
3. Create relevant fixtures in `test/fixtures/`
4. Follow the existing test patterns:

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { NewScanner } from '../../src/scanners/new-scanner/index.js';
import type { FileContent, FrontGuardConfig } from '../../src/core/types.js';
import { getDefaultConfig } from '../../src/core/config.js';

describe('NewScanner', () => {
  let scanner: NewScanner;
  let config: FrontGuardConfig;

  beforeEach(() => {
    scanner = new NewScanner();
    scanner.init();
    config = getDefaultConfig();
  });

  it('should return the correct rules', () => {
    const rules = scanner.getRules();
    expect(rules.length).toBeGreaterThan(0);
    expect(rules[0].id).toMatch(/^FG-/);
  });

  // Add tests for each rule...
});
```

### Testing best practices

- Always test both vulnerable code **and** safe code (no false positives)
- Verify the correct `ruleId` in findings
- Verify severity and category
- Verify line numbers when relevant
- Use `beforeEach` to create fresh scanner instances
- Keep fixtures simple and focused on one vulnerability type
