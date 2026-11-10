/**
 * CVSS v3.0/v3.1 base score from a vector string, per the FIRST specification
 * (https://www.first.org/cvss/v3.1/specification-document). Returns `null` for other versions.
 */
const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
} as const;

const PR = {
  U: { N: 0.85, L: 0.62, H: 0.27 },
  C: { N: 0.85, L: 0.68, H: 0.5 },
} as const;

/** Rounds up to one decimal, avoiding floating point artefacts (spec Appendix A). */
function roundUp(value: number): number {
  const int = Math.round(value * 100_000);
  return int % 10_000 === 0 ? int / 100_000 : (Math.floor(int / 10_000) + 1) / 10;
}

export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const metrics = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((part) => part.split(':') as [string, string]),
  );

  const pick = (table: Record<string, number>, key: string): number | undefined =>
    table[metrics[key] ?? ''];

  const scope = metrics.S as 'U' | 'C' | undefined;
  const av = pick(WEIGHTS.AV, 'AV');
  const ac = pick(WEIGHTS.AC, 'AC');
  const ui = pick(WEIGHTS.UI, 'UI');
  const c = pick(WEIGHTS.C, 'C');
  const i = pick(WEIGHTS.I, 'I');
  const a = pick(WEIGHTS.A, 'A');
  const pr = scope ? pick(PR[scope], 'PR') : undefined;
  if ([av, ac, ui, c, i, a, pr].some((v) => v === undefined) || !scope) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact =
    scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  const raw = scope === 'U' ? impact + exploitability : 1.08 * (impact + exploitability);
  return roundUp(Math.min(raw, 10));
}
