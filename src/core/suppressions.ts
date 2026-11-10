/**
 * Inline suppressions, usable in any comment syntax (`//`, `/* *\/`, `<!-- -->`, `#`):
 *
 *   frontguard-ignore-file [FG-XSS-001, no-eval]
 *   frontguard-ignore-next-line [FG-SEC-006]
 *   frontguard-ignore-line [FG-SEC-006]
 *
 * Without a rule list, every rule is suppressed for that scope.
 */
const DIRECTIVE_RE =
  /frontguard-ignore-(file|next-line|line)\b(?:[ \t]+([\w-]+(?:[ \t]*,[ \t]*[\w-]+)*))?/g;

const ALL = '*';

export interface Suppressions {
  isSuppressed(line: number, ruleId: string, ruleName: string): boolean;
}

export function parseSuppressions(lines: readonly string[]): Suppressions {
  const fileWide = new Set<string>();
  const byLine = new Map<number, Set<string>>();

  const add = (line: number, ids: string[]) => {
    const set = byLine.get(line) ?? new Set<string>();
    for (const id of ids) set.add(id);
    byLine.set(line, set);
  };

  for (const [index, text] of lines.entries()) {
    if (!text.includes('frontguard-ignore')) continue;
    for (const match of text.matchAll(DIRECTIVE_RE)) {
      const ids = match[2] ? match[2].split(',').map((id) => id.trim()) : [ALL];
      const scope = match[1];
      if (scope === 'file') for (const id of ids) fileWide.add(id);
      else add(scope === 'line' ? index + 1 : index + 2, ids);
    }
  }

  const matches = (set: Set<string> | undefined, id: string, name: string) =>
    !!set && (set.has(ALL) || set.has(id) || set.has(name));

  return {
    isSuppressed: (line, id, name) =>
      matches(fileWide, id, name) || matches(byLine.get(line), id, name),
  };
}
