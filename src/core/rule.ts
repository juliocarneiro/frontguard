import type { Node } from '@babel/types';
import type { Location, Rule } from '../types.ts';

/** Identity helper that gives custom rules full type inference. */
export function defineRule(rule: Rule): Rule {
  return rule;
}

/** Converts a Babel node location to a 1-based line/column pair. */
export function locOf(node: Node): Location | null {
  const start = node.loc?.start;
  return start ? { line: start.line, column: start.column + 1 } : null;
}

/** Converts a character offset in `text` to a 1-based line/column pair. */
export function positionAt(text: string, offset: number): Location {
  const before = text.slice(0, offset);
  const lineStart = before.lastIndexOf('\n');
  return { line: before.split('\n').length, column: offset - lineStart };
}

/** Yields every match of a global regex on each line, with 1-based positions. */
export function* matchLines(
  lines: readonly string[],
  pattern: RegExp,
): Generator<Location & { match: RegExpExecArray }> {
  const re = pattern.global ? pattern : new RegExp(pattern.source, `${pattern.flags}g`);
  for (const [index, line] of lines.entries()) {
    re.lastIndex = 0;
    for (let match = re.exec(line); match; match = re.exec(line)) {
      yield { line: index + 1, column: match.index + 1, match };
      if (match[0] === '') re.lastIndex++;
    }
  }
}
