import { readFile, stat } from 'node:fs/promises';
import { glob } from 'tinyglobby';
import { DEFAULT_EXCLUDE, type ResolvedConfig } from '../config/schema.ts';

/** Returns matching files relative to `root`, with forward slashes, sorted. */
export async function discoverFiles(root: string, config: ResolvedConfig): Promise<string[]> {
  const ignore = config.noDefaultExclude ? config.exclude : [...DEFAULT_EXCLUDE, ...config.exclude];
  const files = await glob(config.include, {
    cwd: root,
    ignore,
    onlyFiles: true,
    dot: false,
    followSymbolicLinks: false,
    expandDirectories: false,
  });
  return files.sort();
}

export type ReadOutcome =
  | { ok: true; text: string }
  | { ok: false; reason: 'too-large' | 'binary' | 'unreadable'; detail?: string };

export async function readSourceFile(path: string, maxSize: number): Promise<ReadOutcome> {
  try {
    const info = await stat(path);
    if (info.size > maxSize) return { ok: false, reason: 'too-large' };
    const text = await readFile(path, 'utf8');
    if (text.includes('\u0000')) return { ok: false, reason: 'binary' };
    return { ok: true, text };
  } catch (error) {
    return {
      ok: false,
      reason: 'unreadable',
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}
