import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ReporterName } from '../config/schema.ts';
import type { ScanResult } from '../types.ts';
import { toHtml } from './html.ts';
import { toJson } from './json.ts';
import { toSarif } from './sarif.ts';

export { toConsole } from './console.ts';
export { toHtml } from './html.ts';
export { toJson } from './json.ts';
export { toSarif } from './sarif.ts';

const FILE_REPORTERS = {
  json: { file: 'frontguard-report.json', render: toJson },
  sarif: { file: 'frontguard-report.sarif', render: toSarif },
  html: { file: 'frontguard-report.html', render: toHtml },
} as const;

/** Writes the file-based reports into `outputDir` and returns their paths. */
export async function writeReports(
  result: ScanResult,
  reporters: readonly ReporterName[],
  outputDir: string,
): Promise<Partial<Record<keyof typeof FILE_REPORTERS, string>>> {
  const written: Partial<Record<keyof typeof FILE_REPORTERS, string>> = {};
  const selected = [...new Set(reporters)].filter(
    (name): name is keyof typeof FILE_REPORTERS => name in FILE_REPORTERS,
  );
  if (selected.length === 0) return written;

  await mkdir(outputDir, { recursive: true });
  for (const name of selected) {
    const { file, render } = FILE_REPORTERS[name];
    const path = join(outputDir, file);
    await writeFile(path, render(result), 'utf8');
    written[name] = path;
  }
  return written;
}
