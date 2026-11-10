const MAX_LINE_LENGTH = 200;

/** Masks a secret, keeping just enough of it to be recognisable. */
export function mask(secret: string): string {
  const visible = secret.length > 12 ? 4 : 0;
  return secret.slice(0, visible) + '*'.repeat(Math.min(Math.max(secret.length - visible, 4), 16));
}

/** Returns `line` with `context` lines around it, prefixed by line numbers; `>` marks the hit. */
export function buildSnippet(
  lines: readonly string[],
  line: number,
  redact: readonly string[] = [],
  context = 2,
): string {
  const start = Math.max(1, line - context);
  const end = Math.min(lines.length, line + context);
  const width = String(end).length;
  const out: string[] = [];

  for (let n = start; n <= end; n++) {
    let text = lines[n - 1] ?? '';
    for (const secret of redact) text = text.replaceAll(secret, mask(secret));
    if (text.length > MAX_LINE_LENGTH) text = `${text.slice(0, MAX_LINE_LENGTH)}…`;
    out.push(`${n === line ? '>' : ' '} ${String(n).padStart(width)} | ${text}`);
  }
  return out.join('\n');
}
