import type { Finding, FrontGuardConfig, Reporter, ScanResult } from './types.js';
import { discoverFiles, readFileContent } from './file-discovery.js';
import { ruleRegistry } from './rule-registry.js';
import { meetsThreshold } from './severity.js';
import type { BaseScanner } from '../scanners/base-scanner.js';

export class ScanEngine {
  private scanners: BaseScanner[] = [];
  private reporters: Reporter[] = [];

  registerScanner(scanner: BaseScanner): void {
    scanner.init();
    this.scanners.push(scanner);
  }

  registerReporter(reporter: Reporter): void {
    this.reporters.push(reporter);
  }

  async scan(targetPath: string, config: FrontGuardConfig): Promise<ScanResult> {
    const startTime = Date.now();

    ruleRegistry.setOverrides(config.rules);

    const filePaths = await discoverFiles(targetPath, config);
    const files = filePaths.map(readFileContent);

    const allFindings: Finding[] = [];

    for (const scanner of this.scanners) {
      if (!this.isScannerEnabled(scanner, config)) continue;
      const findings = await scanner.scan(files, config);
      allFindings.push(...findings);
    }

    allFindings.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    const result: ScanResult = {
      findings: allFindings,
      scannedFiles: filePaths.length,
      scanDuration: Date.now() - startTime,
      timestamp: new Date().toISOString(),
      config,
    };

    for (const reporter of this.reporters) {
      await reporter.generate(result);
    }

    return result;
  }

  hasFailures(result: ScanResult): boolean {
    const threshold = result.config.severity.failOn;
    return result.findings.some(f => meetsThreshold(f.severity, threshold));
  }

  private isScannerEnabled(scanner: BaseScanner, config: FrontGuardConfig): boolean {
    const map: Record<string, boolean> = {
      xss: config.scanners.xss,
      dependencies: config.scanners.dependencies,
      secrets: config.scanners.secrets,
      misconfig: config.scanners.misconfig,
      'auth-patterns': config.scanners.authPatterns,
    };
    return map[scanner.category] ?? true;
  }
}
