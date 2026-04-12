import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Reporter, ScanResult, Severity } from '../core/types.js';

export class JsonReporter implements Reporter {
  name = 'json';

  constructor(private outputDir: string) {}

  async generate(result: ScanResult): Promise<string> {
    await mkdir(this.outputDir, { recursive: true });

    const severityCounts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of result.findings) {
      severityCounts[f.severity]++;
    }

    const report = {
      timestamp: result.timestamp,
      summary: {
        totalFindings: result.findings.length,
        bySeverity: severityCounts,
        scannedFiles: result.scannedFiles,
        scanDuration: result.scanDuration,
      },
      findings: result.findings,
    };

    const filePath = join(this.outputDir, 'frontguard-report.json');
    await writeFile(filePath, JSON.stringify(report, null, 2), 'utf-8');
    return filePath;
  }
}
