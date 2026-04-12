import type { Severity } from './types.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function severityToNumber(severity: Severity): number {
  return SEVERITY_ORDER[severity];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[b] - SEVERITY_ORDER[a];
}

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}

export function severityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    critical: 'red',
    high: 'redBright',
    medium: 'yellow',
    low: 'blue',
    info: 'gray',
  };
  return colors[severity];
}
