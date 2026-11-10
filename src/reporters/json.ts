import type { ScanResult, Severity } from '../types.ts';
import { VERSION } from '../version.ts';

export function summarize(result: ScanResult): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of result.findings) counts[finding.severity]++;
  return counts;
}

/** Stable, machine-readable report. `schemaVersion` changes only on breaking changes. */
export function toJson(result: ScanResult): string {
  const report = {
    schemaVersion: 1,
    tool: { name: 'frontguard', version: VERSION },
    startedAt: result.startedAt,
    durationMs: result.durationMs,
    filesScanned: result.filesScanned,
    summary: { total: result.findings.length, bySeverity: summarize(result) },
    findings: result.findings,
    warnings: result.warnings,
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}
