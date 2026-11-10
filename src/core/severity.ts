import type { Severity } from '../types.ts';

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Sort comparator: most severe first. */
export function bySeverity(a: { severity: Severity }, b: { severity: Severity }): number {
  return RANK[b.severity] - RANK[a.severity];
}

export function meetsThreshold(severity: Severity, threshold: Severity | 'none'): boolean {
  return threshold !== 'none' && RANK[severity] >= RANK[threshold];
}

/** Maps a CVSS base score (0-10) to a severity bucket, following the CVSS v3 qualitative scale. */
export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}
