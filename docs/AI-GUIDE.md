# FrontGuard — Complete AI Module Guide

Detailed documentation on FrontGuard's artificial intelligence integration for deep security analysis, automatic fix generation, and cross-file data flow detection.

---

## Table of Contents

- [Overview](#overview)
- [Supported Providers](#supported-providers)
- [Configuration](#configuration)
- [AI Features](#ai-features)
  - [Deep Scan (--ai-deep)](#deep-scan---ai-deep)
  - [Auto Fix (--ai-fix)](#auto-fix---ai-fix)
  - [Cross-File Flow (--ai-flow)](#cross-file-flow---ai-flow)
  - [Custom Rules (--ai-rule)](#custom-rules---ai-rule)
- [Ollama — Free Local AI](#ollama--free-local-ai)
- [Cost Tips](#cost-tips)
- [Privacy and Security](#privacy-and-security)
- [Complete Workflows](#complete-workflows)

---

## Overview

FrontGuard's AI module uses the [Vercel AI SDK](https://sdk.vercel.ai/) to integrate multiple LLM providers. AI complements static analysis with:

- **Deep Scan**: Contextual analysis of findings to reduce false positives and increase confidence.
- **Auto Fix**: Automatic generation of fix suggestions for each vulnerability.
- **Cross-File Flow**: Tracking sensitive data flow across multiple files.
- **Custom Rules**: Evaluation of security rules written in natural language.

AI is **optional** and disabled by default. All static scanning works normally without it.

---

## Supported Providers

| Provider | Default Model | API Key | Cost |
|----------|---------------|---------|------|
| **OpenAI** | `gpt-4o-mini` | `OPENAI_API_KEY` | Paid |
| **Anthropic** | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` | Paid |
| **Google** | `gemini-2.0-flash` | `GOOGLE_API_KEY` | Paid / Free tier |
| **Ollama** | `llama3` | Not required | Free (local) |

---

## Configuration

There are 3 ways to configure the AI module, in order of priority:

### 1. CLI Flags (highest priority)

```bash
frontguard scan ./src \
  --ai-deep \
  --ai-provider openai \
  --ai-model gpt-4o-mini
```

### 2. Environment Variables

```bash
# Provider and model
export FRONTGUARD_AI_PROVIDER=openai
export FRONTGUARD_AI_MODEL=gpt-4o-mini

# API Keys
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_API_KEY=AIza...

# Ollama
export FRONTGUARD_OLLAMA_URL=http://localhost:11434
```

### 3. Configuration File

```typescript
// frontguard.config.ts
import { defineConfig } from 'frontguard';

export default defineConfig({
  ai: {
    enabled: true,
    provider: 'openai',
    model: 'gpt-4o-mini',
    apiKey: process.env.OPENAI_API_KEY,
    features: {
      deepScan: true,
      autoFix: false,
      crossFileFlow: true,
      customRules: [],
    },
    confirmBeforeSend: true,
    ollamaBaseUrl: 'http://localhost:11434',
  },
});
```

### 4. `frontguard auth` Command (local persistence)

Saves credentials to `~/.frontguard/config.json`:

```bash
# Configure provider and API key
frontguard auth --provider openai --key sk-...

# Configure model
frontguard auth --provider anthropic --key sk-ant-... --model claude-sonnet-4-20250514

# View current configuration
frontguard auth --show
```

### Per-Provider Configuration

#### OpenAI

```bash
# Via CLI
frontguard auth --provider openai --key sk-proj-...
frontguard scan ./src --ai-deep --ai-provider openai --ai-model gpt-4o

# Via environment variable
export OPENAI_API_KEY=sk-proj-...
```

#### Anthropic

```bash
# Via CLI
frontguard auth --provider anthropic --key sk-ant-api03-...
frontguard scan ./src --ai-deep --ai-provider anthropic --ai-model claude-sonnet-4-20250514

# Via environment variable
export ANTHROPIC_API_KEY=sk-ant-api03-...
```

#### Google (Gemini)

```bash
# Via CLI
frontguard auth --provider google --key AIzaSy...
frontguard scan ./src --ai-deep --ai-provider google --ai-model gemini-2.0-flash

# Via environment variable
export GOOGLE_API_KEY=AIzaSy...
```

#### Ollama (Local)

```bash
# No API key required
frontguard scan ./src --ai-deep --ai-provider ollama --ai-model llama3
```

---

## AI Features

### Deep Scan (`--ai-deep`)

Deep Scan sends static analysis findings to the AI, which analyzes the code context to:

- Confirm whether the vulnerability is real or a false positive
- Assign a confidence level (0–100%)
- Enrich the description with contextual analysis

**Usage:**

```bash
frontguard scan ./src --ai-deep
```

**Example output:**

```
AI Deep Scan enabled (provider: openai, model: gpt-4o-mini)

  CRITICAL  FG-XSS-002  Use of eval() (AI Confidence: 97%)
  src/utils/parser.ts:42
  AI: "The eval() directly receives the result of getQueryParam(),
  which is unsanitized user input. Vulnerability confirmed with
  high confidence."

  HIGH  FG-XSS-001  Unsafe innerHTML (AI Confidence: 35%)
  src/components/StaticContent.tsx:18
  AI: "The innerHTML receives a constant defined within the component
  itself, with no relation to external input. Likely false positive."

AI Summary:
  Confirmed: 8 findings
  Possible false positives: 3 findings
  Analysis time: 4.2s
```

**Programmatic usage:**

```typescript
import { AIEngine } from 'frontguard/ai/ai-engine';

const ai = new AIEngine(config);
const enriched = await ai.deepScan(result.findings, files);

for (const finding of enriched) {
  if (finding.aiConfidence > 0.8) {
    console.log(`Confirmed: ${finding.title}`);
  } else {
    console.log(`Low confidence: ${finding.title} (${finding.aiConfidence})`);
  }
}
```

---

### Auto Fix (`--ai-fix`)

Auto Fix generates fix suggestions in diff format for each vulnerability found.

**Usage:**

```bash
frontguard scan ./src --ai-fix
```

**Example output (generated diff):**

```
Suggested fix for FG-XSS-001 in src/components/Comment.tsx:

--- src/components/Comment.tsx
+++ src/components/Comment.tsx (fixed)
@@ -1,6 +1,8 @@
 import React from 'react';
+import DOMPurify from 'dompurify';
 
 function Comment({ html }: { html: string }) {
-  return <div dangerouslySetInnerHTML={{ __html: html }} />;
+  const sanitized = DOMPurify.sanitize(html);
+  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
 }

Apply fix? [y/n/all]
```

**Programmatic usage:**

```typescript
const ai = new AIEngine(config);
const fixes = await ai.generateFixes(result.findings, files);

for (const [ruleId, diff] of fixes) {
  console.log(`=== Fix for ${ruleId} ===`);
  console.log(diff);
}
```

---

### Cross-File Flow (`--ai-flow`)

Analyzes sensitive data flow across multiple files to detect vulnerabilities that single-file analysis cannot see.

**Usage:**

```bash
frontguard scan ./src --ai-flow
```

**Example output:**

```
Cross-File Data Flow Analysis

  FLOW 1 (Risk: HIGH)
  ────────────────────────────────────
  Source: src/api/users.ts:23
    → User data received via req.body

  Path:
    src/api/users.ts:getUser()
    → src/services/user-service.ts:processUser()
    → src/components/UserProfile.tsx:renderProfile()

  Sink: src/components/UserProfile.tsx:45
    → Data inserted via innerHTML without sanitization

  FLOW 2 (Risk: CRITICAL)
  ────────────────────────────────────
  Source: src/auth/callback.ts:12
    → JWT token stored in variable

  Path:
    src/auth/callback.ts:handleCallback()
    → src/stores/auth-store.ts:setToken()
    → src/api/client.ts:makeRequest()

  Sink: src/api/client.ts:30
    → Token passed as query parameter in URL
```

**Programmatic usage:**

```typescript
const ai = new AIEngine(config);
const flows = await ai.analyzeDataFlow(files);

for (const flow of flows) {
  console.log(`Risk: ${flow.risk}`);
  console.log(`${flow.source.file}:${flow.source.line} → ${flow.source.description}`);
  console.log(`Path: ${flow.path.join(' → ')}`);
  for (const sink of flow.sinks) {
    console.log(`  Sink: ${sink.file}:${sink.line} → ${sink.description}`);
  }
}
```

---

### Custom Rules (`--ai-rule`)

Define security rules in natural language. The AI analyzes the code by applying these custom rules.

**Usage:**

```bash
# Single rule via CLI
frontguard scan ./src --ai-rule "Check that all API routes validate the request body"

# Multiple rules via CLI
frontguard scan ./src \
  --ai-rule "Ensure SQL queries use prepared statements" \
  --ai-rule "Verify that logs do not contain sensitive user data"
```

**Via configuration file:**

```typescript
export default defineConfig({
  ai: {
    enabled: true,
    provider: 'openai',
    features: {
      deepScan: true,
      autoFix: false,
      crossFileFlow: true,
      customRules: [
        'Verify that all API routes require authentication',
        'Ensure user data is validated before database insertion',
        'Check that API responses do not leak internal system data',
        'Confirm that rate limiting is applied to public endpoints',
      ],
    },
  },
});
```

**Example output:**

```
Custom Rules (AI)

  RULE: "Verify that all API routes require authentication"

    HIGH  src/api/routes/public-data.ts:15
    "The GET /api/users route has no authentication middleware.
    Any unauthenticated user can access the user list."

    HIGH  src/api/routes/admin.ts:8
    "The POST /api/admin/config route does not check for the 'admin' role.
    Any authenticated user can modify admin settings."
```

**Programmatic usage:**

```typescript
const ai = new AIEngine(config);
const findings = await ai.evaluateCustomRules(
  [
    'Verify that sensitive data is encrypted before saving',
    'Ensure CORS is configured restrictively',
  ],
  files,
);
```

---

## Ollama — Free Local AI

[Ollama](https://ollama.ai/) lets you run LLMs locally, at no cost and with full privacy.

### Installation

```bash
# macOS / Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download the installer from https://ollama.ai/download

# Verify installation
ollama --version
```

### Recommended Models

| Model | Size | VRAM | Quality | Speed |
|-------|------|------|---------|-------|
| `llama3` | 4.7 GB | 8 GB | Good | Fast |
| `llama3:70b` | 40 GB | 48 GB | Excellent | Slow |
| `codellama` | 3.8 GB | 8 GB | Good (code) | Fast |
| `deepseek-coder-v2` | 8.9 GB | 16 GB | Excellent (code) | Medium |
| `mistral` | 4.1 GB | 8 GB | Good | Fast |
| `qwen2.5-coder` | 4.7 GB | 8 GB | Very good (code) | Fast |

### Setting Up Ollama

```bash
# 1. Pull the model
ollama pull llama3

# 2. Verify it's running
ollama list

# 3. Use with FrontGuard
frontguard scan ./src --ai-deep --ai-provider ollama --ai-model llama3
```

**Via configuration file:**

```typescript
export default defineConfig({
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

### Remote Ollama Server

If Ollama is running on a different server:

```bash
# On the server
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# In FrontGuard
frontguard scan ./src --ai-deep --ai-provider ollama
```

```typescript
export default defineConfig({
  ai: {
    provider: 'ollama',
    ollamaBaseUrl: 'http://ai-server.local:11434',
  },
});
```

---

## Cost Tips

### Cost Comparison (estimate per scan of ~100 files)

| Provider / Model | Approx. Cost per Scan | Recommendation |
|------------------|----------------------|----------------|
| Ollama (local) | **Free** | Development and private CI |
| Google Gemini Flash | ~$0.01 | CI/CD on a tight budget |
| OpenAI GPT-4o-mini | ~$0.02 | Good cost-to-quality ratio |
| Anthropic Claude Sonnet | ~$0.05 | When accuracy is the priority |
| OpenAI GPT-4o | ~$0.15 | Maximum quality |

### Recommendations for CI/CD

```typescript
// Cost-optimized config for CI
export default defineConfig({
  ai: {
    enabled: true,
    provider: 'google',          // cheapest cloud option
    model: 'gemini-2.0-flash',   // flash model
    features: {
      deepScan: true,            // keep deep scan
      autoFix: false,            // disable auto fix in CI
      crossFileFlow: false,      // disable data flow (saves tokens)
      customRules: [],
    },
    confirmBeforeSend: false,    // no confirmation in CI
  },
});
```

### Tips to Reduce Cost

1. **Filter files**: Use `include`/`exclude` to scan only relevant code
2. **Disable non-essential features**: `autoFix: false` and `crossFileFlow: false` in CI
3. **Use smaller models**: `gpt-4o-mini` instead of `gpt-4o`
4. **Cache results**: Static analysis is free — use AI only for confirmation
5. **Ollama in CI**: Run Ollama as a service on the CI runner for zero cost

---

## Privacy and Security

### What Data Is Sent to the AI?

When AI features are enabled, the following data may be sent:

| Feature | Data Sent |
|---------|-----------|
| Deep Scan | Findings (ruleId, description, code snippet) |
| Auto Fix | Finding + contents of the affected file |
| Cross-File Flow | Contents of multiple files |
| Custom Rules | Rule + contents of multiple files |

### Privacy Controls

#### Confirmation before sending

```typescript
export default defineConfig({
  ai: {
    confirmBeforeSend: true, // default: true
  },
});
```

When enabled, FrontGuard shows exactly what will be sent and asks for confirmation:

```
[AI] Preparing request to OpenAI (gpt-4o-mini)
Data to be sent:
  - 12 findings from 8 files
  - ~2,400 estimated tokens
  
Continue? [y/n]
```

#### Use Ollama for full privacy

```typescript
export default defineConfig({
  ai: {
    provider: 'ollama',   // everything local, nothing leaves the machine
  },
});
```

#### Disable via CLI

```bash
# Disable confirmation (CI)
frontguard scan ./src --ai-deep --ai-no-confirm

# Don't use AI at all
frontguard scan ./src   # no --ai-* flags
```

### Security Recommendations

1. **Never commit API keys** — Use `frontguard auth` or environment variables
2. **Use Ollama for proprietary code** — No data leaves the machine
3. **Review with `confirmBeforeSend`** — Always verify what will be sent
4. **Exclude sensitive files** — Configure `exclude` for files containing internal data
5. **Be careful with Auto Fix** — Review all suggested fixes before applying

---

## Complete Workflows

### Workflow 1: Basic scan with Deep Scan

```bash
# Run static scan + AI validation
frontguard scan ./src --ai-deep

# Output includes AI confidence for each finding
```

### Workflow 2: Full scan with all features

```bash
frontguard scan ./src \
  --ai-deep \
  --ai-fix \
  --ai-flow \
  --ai-provider openai \
  --ai-model gpt-4o-mini
```

### Workflow 3: CI/CD with Ollama (zero cost)

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    services:
      ollama:
        image: ollama/ollama
        ports:
          - 11434:11434
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - run: pnpm install
      - run: |
          # Pull model
          curl http://localhost:11434/api/pull -d '{"name":"llama3"}'
          # Run scan
          npx frontguard scan ./src \
            --ai-deep \
            --ai-provider ollama \
            --ai-model llama3 \
            --ai-no-confirm \
            --fail-on high \
            -r sarif \
            -o ./security-report
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./security-report/report.sarif
```

### Workflow 4: Custom rules for a specific project

```bash
frontguard scan ./src \
  --ai-deep \
  --ai-rule "Ensure all fetch calls include error handling" \
  --ai-rule "Verify that React components do not make direct HTTP calls" \
  --ai-rule "Confirm that environment variables are accessed only via the config module" \
  --ai-provider openai
```

### Workflow 5: Security analysis before code review

```bash
# 1. Static scan + deep scan
frontguard scan ./src --ai-deep --ai-flow -r json -r html -o ./reports

# 2. Review the HTML report
open ./reports/frontguard-report.html

# 3. Generate fixes for confirmed findings
frontguard scan ./src --ai-fix --ai-provider openai

# 4. Review and apply fixes
```

### Workflow 6: Full programmatic usage

```typescript
import {
  ScanEngine,
  XSSScanner,
  SecretsScanner,
  AuthPatternsScanner,
  MisconfigScanner,
  DependencyScanner,
  loadConfig,
} from 'frontguard';
import { AIEngine } from 'frontguard/ai/ai-engine';

async function runSecurityAnalysis() {
  const config = await loadConfig();

  // Static scan
  const engine = new ScanEngine();
  engine.registerScanner(new XSSScanner());
  engine.registerScanner(new SecretsScanner());
  engine.registerScanner(new AuthPatternsScanner());
  engine.registerScanner(new MisconfigScanner());
  engine.registerScanner(new DependencyScanner());

  const result = await engine.scan('./src', config);

  // AI analysis
  if (config.ai.enabled) {
    const ai = new AIEngine(config);

    if (ai.isConfigured()) {
      // Deep scan
      const enriched = await ai.deepScan(result.findings, files);
      const confirmed = enriched.filter(f => f.aiConfidence > 0.7);

      // Generate fixes
      const fixes = await ai.generateFixes(confirmed, files);

      // Data flow analysis
      const flows = await ai.analyzeDataFlow(files);

      console.log(`AI-confirmed findings: ${confirmed.length}`);
      console.log(`Fixes generated: ${fixes.size}`);
      console.log(`Data flows detected: ${flows.length}`);
    }
  }

  if (engine.hasFailures(result)) {
    process.exit(1);
  }
}
```
