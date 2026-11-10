export function calculateShannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  const len = str.length;
  let entropy = 0;

  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

const DEFAULT_THRESHOLD = 4.5;

export function isHighEntropy(str: string, threshold = DEFAULT_THRESHOLD): boolean {
  return calculateShannonEntropy(str) >= threshold;
}
