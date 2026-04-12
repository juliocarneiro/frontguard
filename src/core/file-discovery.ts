import fg from 'fast-glob';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { FileContent, FrontGuardConfig } from './types.js';

export async function discoverFiles(
  targetPath: string,
  config: FrontGuardConfig,
): Promise<string[]> {
  const cwd = resolve(targetPath);
  const files = await fg(config.include, {
    cwd,
    ignore: config.exclude,
    absolute: true,
    dot: false,
    onlyFiles: true,
  });

  return files.sort();
}

export function readFileContent(filePath: string): FileContent {
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  return { path: filePath, content, lines };
}

export function getCodeSnippet(
  lines: string[],
  line: number,
  contextLines = 2,
): string {
  const start = Math.max(0, line - 1 - contextLines);
  const end = Math.min(lines.length, line + contextLines);
  return lines
    .slice(start, end)
    .map((l, i) => {
      const lineNum = start + i + 1;
      const marker = lineNum === line ? '>' : ' ';
      return `${marker} ${String(lineNum).padStart(4)} | ${l}`;
    })
    .join('\n');
}
