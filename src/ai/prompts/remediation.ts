import type { Finding } from '../../core/types.js';

export function buildRemediationSystemPrompt(): string {
  return `You are a senior security engineer generating precise code fixes for frontend vulnerabilities.

Rules:
1. Output ONLY the corrected code that replaces the vulnerable section — no explanations outside the diff.
2. Preserve the original coding style, indentation, and conventions.
3. Use framework-idiomatic security patterns (e.g., DOMPurify for HTML sanitization, parameterized queries, Content-Security-Policy headers).
4. Never introduce new dependencies unless absolutely necessary; prefer built-in or already-imported solutions.
5. If the fix requires a new import, include it at the top.
6. Ensure the fix does not break existing functionality.

Respond with a unified diff format:
- Lines removed prefixed with \`-\`
- Lines added prefixed with \`+\`
- 3 lines of unchanged context around changes prefixed with a space.

Do not wrap the diff in markdown code fences.`;
}

export function buildRemediationUserPrompt(finding: Finding, code: string): string {
  return `Fix the following vulnerability in the source code.

## Vulnerability
- Rule: ${finding.ruleId}
- Severity: ${finding.severity}
- Title: ${finding.title}
- Description: ${finding.description}
- File: ${finding.file}:${finding.line}:${finding.column}
- CWE: ${finding.cwe ?? 'N/A'}
- Remediation hint: ${finding.remediation}

## Source Code (${finding.file})
${code}`;
}
