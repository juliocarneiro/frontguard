import type { FileContent, Finding, FrontGuardConfig, RuleDefinition, ScannerCategory } from '../core/types.js';
import { ruleRegistry } from '../core/rule-registry.js';
import { getCodeSnippet } from '../core/file-discovery.js';

export abstract class BaseScanner {
  abstract readonly name: string;
  abstract readonly category: ScannerCategory;

  abstract getRules(): RuleDefinition[];

  init(): void {
    ruleRegistry.registerMany(this.getRules());
  }

  abstract scanFile(file: FileContent, config: FrontGuardConfig): Finding[];

  async scan(files: FileContent[], config: FrontGuardConfig): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const file of files) {
      const fileFindings = this.scanFile(file, config);
      for (const finding of fileFindings) {
        if (ruleRegistry.isEnabled(finding.ruleId)) {
          findings.push(finding);
        }
      }
    }
    return findings;
  }

  protected createFinding(
    rule: RuleDefinition,
    file: FileContent,
    line: number,
    column: number,
  ): Finding {
    return {
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      title: rule.title,
      description: rule.description,
      file: file.path,
      line,
      column,
      codeSnippet: getCodeSnippet(file.lines, line),
      cwe: rule.cwe,
      owasp: rule.owasp,
      remediation: rule.remediation,
    };
  }
}
