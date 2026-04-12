import type { FileContent } from '../../core/types.js';

export function buildCustomRuleSystemPrompt(): string {
  return `You are a security policy enforcement engine for frontend codebases.

The user defines custom security rules in natural language. Your job is to:
1. Interpret the rule precisely — understand what pattern, practice, or vulnerability it targets.
2. Scan the provided source files for ALL violations of the rule.
3. For each violation, produce a structured finding with accurate file, line, and column references.
4. Assign appropriate severity based on the security impact of the violation.
5. Provide specific remediation guidance for each violation.

Respond ONLY with a JSON array of findings. Each object must have:
- ruleId: "FG-CUSTOM-<sequential_number>" (e.g., "FG-CUSTOM-001")
- severity: "critical" | "high" | "medium" | "low" | "info"
- category: closest match from "xss" | "dependencies" | "secrets" | "misconfig" | "auth-patterns"
- title: short description of the violation
- description: detailed explanation of how the code violates the rule
- file: file path
- line: line number
- column: column number (use 1 if uncertain)
- codeSnippet: the offending code
- remediation: how to fix it
- aiConfidence: 0.0 to 1.0
- aiAnalyzed: true

Return an empty array [] if no violations are found. Do not wrap the JSON in markdown code fences.`;
}

export function buildCustomRuleUserPrompt(rule: string, files: FileContent[]): string {
  const fileContents = files
    .map(f => `--- ${f.path} ---\n${f.content}`)
    .join('\n\n');

  return `Evaluate this custom security rule against the source files and return violations as JSON.

## Custom Rule
${rule}

## Files
${fileContents}`;
}
