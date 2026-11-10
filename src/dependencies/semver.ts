/** Minimal SemVer 2.0 precedence comparison (enough for OSV range events). */
export function compareVersions(a: string, b: string): number {
  const [coreA = '', preA] = a.replace(/\+.*$/, '').split(/-(.*)/s);
  const [coreB = '', preB] = b.replace(/\+.*$/, '').split(/-(.*)/s);
  const partsA = coreA.split('.').map(Number);
  const partsB = coreB.split('.').map(Number);

  for (let i = 0; i < 3; i++) {
    const diff = (partsA[i] ?? 0) - (partsB[i] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  if (preA === preB) return 0;
  if (preA === undefined) return 1;
  if (preB === undefined) return -1;

  const idsA = preA.split('.');
  const idsB = preB.split('.');
  for (let i = 0; i < Math.max(idsA.length, idsB.length); i++) {
    const x = idsA[i];
    const y = idsB[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const nx = /^\d+$/.test(x) ? Number(x) : null;
    const ny = /^\d+$/.test(y) ? Number(y) : null;
    if (nx !== null && ny !== null) return Math.sign(nx - ny);
    if (nx !== null) return -1;
    if (ny !== null) return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}
