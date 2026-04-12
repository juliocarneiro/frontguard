import type { Finding } from '../../core/types.js';

export function buildDeepScanSystemPrompt(): string {
  return `You are an elite frontend security analyst specializing in OWASP Top 10 for web applications, CWE classifications, and modern JavaScript/TypeScript vulnerability patterns.

Your task is to validate and score static analysis findings against actual source code. For each finding you must:

1. Determine if it is a TRUE POSITIVE or FALSE POSITIVE by analyzing the surrounding code context, data flow, and whether adequate sanitization or encoding exists.
2. Assign a confidence score from 0.0 to 1.0 reflecting how certain you are the vulnerability is exploitable.
3. Refine the severity (critical/high/medium/low/info) based on real-world exploitability, attack surface, and impact.
4. Improve the description with concrete exploitation scenario details.
5. Provide actionable remediation guidance specific to the framework and code pattern observed.

Respond ONLY with a JSON array of validated findings. Each object must have these fields:
- ruleId (string)
- severity ("critical" | "high" | "medium" | "low" | "info")
- category ("xss" | "dependencies" | "secrets" | "misconfig" | "auth-patterns")
- title (string)
- description (string) — include exploitation scenario
- file (string)
- line (number)
- column (number)
- codeSnippet (string)
- cwe (string, optional)
- owasp (string, optional)
- remediation (string)
- aiConfidence (number, 0-1)
- aiAnalyzed (true)

Omit findings you determine to be false positives. Do not wrap the JSON in markdown code fences.`;
}

export function buildDeepScanUserPrompt(findings: Finding[], codeSnippets: string[]): string {
  const findingsList = findings
    .map((f, i) => `### Finding ${i + 1}
- Rule: ${f.ruleId}
- Severity: ${f.severity}
- File: ${f.file}:${f.line}:${f.column}
- Title: ${f.title}
- Description: ${f.description}
- Snippet: \`${f.codeSnippet}\`
- CWE: ${f.cwe ?? 'N/A'}
- OWASP: ${f.owasp ?? 'N/A'}`)
    .join('\n\n');

  const codeContext = codeSnippets
    .map((snippet, i) => `--- Code Context ${i + 1} ---\n${snippet}`)
    .join('\n\n');

  return `Analyze these static analysis findings against the source code and return validated results as JSON.

## Findings
${findingsList}

## Source Code Context
${codeContext}`;
}
