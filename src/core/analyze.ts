import traverse, { visitors, type Visitor } from '@babel/traverse';
import type { File as BabelFile } from '@babel/types';
import type { Finding, ReportDescriptor, Rule, RuleContext, RuleLevel } from '../types.ts';
import { buildSnippet } from './snippet.ts';
import { extractScript, parseScript } from './source.ts';
import { parseSuppressions } from './suppressions.ts';

export interface ActiveRule {
  rule: Rule;
  level: Exclude<RuleLevel, 'off'>;
}

export interface AnalyzeOutcome {
  findings: Finding[];
  warnings: string[];
}

/** Runs every rule on one file. Script rules share a single parse and a single traversal. */
export function analyzeFile(filename: string, text: string, rules: ActiveRule[]): AnalyzeOutcome {
  const lines = text.split(/\r?\n/);
  const warnings: string[] = [];
  const findings: Finding[] = [];
  const secrets = new Set<string>();
  const seen = new Set<string>();
  const suppressions = parseSuppressions(lines);

  let ast: BabelFile | null = null;
  const script = extractScript(filename, text);
  if (script) {
    const outcome = parseScript(script);
    ast = outcome.ast;
    if (outcome.error) warnings.push(`${filename}: could not parse script (${outcome.error})`);
  }

  const collected: Visitor[] = [];

  for (const { rule, level } of rules) {
    const { meta } = rule;
    const report = (d: ReportDescriptor) => {
      if (suppressions.isSuppressed(d.line, meta.id, meta.name)) return;
      const key = `${meta.id}:${d.line}:${d.column}`;
      if (seen.has(key)) return;
      seen.add(key);
      if (d.redact) secrets.add(d.redact);
      findings.push({
        ruleId: meta.id,
        ruleName: meta.name,
        severity: d.severity ?? meta.severity,
        level,
        category: meta.category,
        title: meta.title,
        message: d.message ? `${meta.title}: ${d.message}` : meta.title,
        description: meta.description,
        remediation: meta.remediation,
        file: filename,
        line: d.line,
        column: d.column,
        snippet: '',
        ...(meta.cwe && { cwe: meta.cwe }),
        ...(meta.owasp && { owasp: meta.owasp }),
      });
    };

    const context: RuleContext = { filename, text, lines, ast, report };
    try {
      const visitor = rule.create(context);
      if (visitor && Object.keys(visitor).length > 0) collected.push(visitor);
    } catch (error) {
      warnings.push(`${filename}: rule ${meta.id} crashed (${errorMessage(error)})`);
    }
  }

  if (ast && collected.length > 0) {
    try {
      traverse(ast, visitors.merge(collected));
    } catch (error) {
      warnings.push(`${filename}: traversal failed (${errorMessage(error)})`);
    }
  }

  // The entropy check is a fallback: drop it where a specific secret rule already fired.
  const specificSecretLines = new Set(
    findings
      .filter((f) => f.category === 'secrets' && f.ruleId !== ENTROPY_RULE_ID)
      .map((f) => f.line),
  );
  const kept = findings.filter(
    (f) => f.ruleId !== ENTROPY_RULE_ID || !specificSecretLines.has(f.line),
  );

  // Snippets are built last so every secret found in the file is masked, including
  // secrets that appear only as context lines of another finding.
  for (const finding of kept) finding.snippet = buildSnippet(lines, finding.line, [...secrets]);

  return { findings: kept, warnings };
}

const ENTROPY_RULE_ID = 'FG-SEC-006';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
