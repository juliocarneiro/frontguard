import { styleText } from 'node:util';
import type { Finding, ScanResult, Severity } from '../types.ts';
import { summarize } from './json.ts';

type Style = Parameters<typeof styleText>[0];

export interface ConsoleOptions {
  color: boolean;
  /** Print only the summary line. */
  compact?: boolean;
}

const SEVERITY_STYLE: Record<Severity, Style> = {
  critical: ['bgRed', 'white', 'bold'],
  high: ['red', 'bold'],
  medium: 'yellow',
  low: 'blue',
  info: 'gray',
};

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function painter(enabled: boolean) {
  return (style: Style, text: string) =>
    enabled ? styleText(style, text, { validateStream: false }) : text;
}

function formatFinding(finding: Finding, paint: ReturnType<typeof painter>): string {
  const badge = paint(SEVERITY_STYLE[finding.severity], ` ${finding.severity.toUpperCase()} `);
  const warn = finding.level === 'warn' ? paint('yellow', ' (warn)') : '';
  const lines = [
    `${badge}${warn} ${paint('bold', finding.message)} ${paint('dim', finding.ruleId)}`,
    paint('cyan', `  ${finding.file}:${finding.line}:${finding.column}`),
    '',
    ...finding.snippet
      .split('\n')
      .map((line) =>
        line.startsWith('>') ? paint('red', `  ${line}`) : paint('dim', `  ${line}`),
      ),
    '',
    `  ${paint('green', 'Fix:')} ${finding.remediation}`,
  ];
  const refs = [finding.cwe, finding.owasp].filter(Boolean).join(' · ');
  if (refs) lines.push(`  ${paint('dim', refs)}`);
  return lines.join('\n');
}

function formatSummary(result: ScanResult, color: boolean): string {
  const paint = painter(color);
  const counts = summarize(result);
  const total = result.findings.length;
  const seconds = (result.durationMs / 1000).toFixed(2);
  const scanned = `${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'} in ${seconds}s`;
  if (total === 0)
    return `${paint(['green', 'bold'], '✔ No issues found')} ${paint('dim', `(${scanned})`)}`;
  const parts = ORDER.filter((s) => counts[s] > 0).map((s) =>
    paint(SEVERITY_STYLE[s], `${counts[s]} ${s}`),
  );
  return `${paint('bold', `✖ ${total} issue${total === 1 ? '' : 's'}`)} (${parts.join(', ')}) ${paint('dim', `· ${scanned}`)}`;
}

export function toConsole(result: ScanResult, options: ConsoleOptions): string {
  const paint = painter(options.color);
  const out: string[] = [];
  if (!options.compact) {
    for (const finding of result.findings) out.push(formatFinding(finding, paint), '');
  }
  for (const warning of result.warnings) out.push(paint('yellow', `⚠ ${warning}`));
  if (result.warnings.length > 0) out.push('');
  out.push(formatSummary(result, options.color));
  return out.join('\n');
}
