import type { FileContent } from '../../core/types.js';

export function buildCrossFileSystemPrompt(): string {
  return `You are a security-focused data flow analyst for frontend applications.

Your task is to trace sensitive data from SOURCES (user input, URL parameters, cookies, localStorage, postMessage, WebSocket messages, API responses) through the codebase to SINKS (DOM manipulation, eval, innerHTML, document.write, fetch/XHR with user data, redirects, script injection points).

For each data flow path found:
1. Identify the source — where untrusted data enters the application.
2. Trace the propagation through variables, function calls, imports/exports, props, state, and stores across files.
3. Identify the sink — where the data reaches a security-sensitive operation.
4. Determine if any sanitization, validation, or encoding is applied along the path.
5. Assess the risk level based on whether the flow is adequately protected.

Respond ONLY with a JSON array of data flow results. Each object must have:
- source: { file: string, line: number, description: string }
- sinks: [{ file: string, line: number, description: string }]
- path: string[] — human-readable description of each step in the data flow
- risk: "critical" | "high" | "medium" | "low" | "info"

Focus on real, exploitable flows. Do not report flows that are properly sanitized. Do not wrap the JSON in markdown code fences.`;
}

export function buildCrossFileUserPrompt(files: FileContent[]): string {
  const fileContents = files
    .map(f => `--- ${f.path} ---\n${f.content}`)
    .join('\n\n');

  return `Trace all security-sensitive data flows across these files and return results as JSON.

## Files
${fileContents}`;
}
