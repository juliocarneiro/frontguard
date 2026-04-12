import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type {
  FileContent,
  Finding,
  FrontGuardConfig,
  RuleDefinition,
  ScannerCategory,
  Severity,
} from '../../core/types.js';
import { BaseScanner } from '../base-scanner.js';
import { queryOSV, type OSVResult } from './osv-client.js';

const RULE_KNOWN_VULN: RuleDefinition = {
  id: 'FG-DEP-001',
  title: 'Known Vulnerability in Dependency',
  description:
    'A dependency has a known security vulnerability reported in the OSV database.',
  severity: 'high',
  category: 'dependencies',
  cwe: 'CWE-1395',
  remediation:
    'Update the affected package to a patched version. Check the advisory for specific remediation steps.',
};

const RULE_OUTDATED_CRITICAL: RuleDefinition = {
  id: 'FG-DEP-002',
  title: 'Outdated Critical Dependency',
  description:
    'A dependency with known vulnerabilities is using an outdated version that may lack security fixes.',
  severity: 'medium',
  category: 'dependencies',
  remediation:
    'Run `npm update` or `npm install <package>@latest` to update to the latest version.',
};

function resolveVersion(range: string): string {
  return range.replace(/^[\^~>=<\s]+/, '');
}

function readPackageJson(root: string): { name: string; version: string }[] {
  try {
    const raw = readFileSync(join(root, 'package.json'), 'utf-8');
    const pkg = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };

    const all: Record<string, string> = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    return Object.entries(all)
      .map(([name, version]) => ({ name, version: resolveVersion(version) }))
      .filter(p => p.version && !p.version.includes('*'));
  } catch {
    return [];
  }
}

export class DependencyScanner extends BaseScanner {
  readonly name = 'Dependency Scanner';
  readonly category: ScannerCategory = 'dependencies';

  getRules(): RuleDefinition[] {
    return [RULE_KNOWN_VULN, RULE_OUTDATED_CRITICAL];
  }

  scanFile(_file: FileContent, _config: FrontGuardConfig): Finding[] {
    return [];
  }

  override async scan(
    files: FileContent[],
    config: FrontGuardConfig,
  ): Promise<Finding[]> {
    const root = this.resolveProjectRoot(files);
    const packages = readPackageJson(root);
    if (packages.length === 0) return [];

    const osvResults = await queryOSV(packages);
    return this.buildFindings(osvResults, root);
  }

  private resolveProjectRoot(files: FileContent[]): string {
    const pkgFile = files.find(f => f.path.endsWith('package.json'));
    if (pkgFile) {
      return pkgFile.path.replace(/[/\\]package\.json$/, '');
    }
    return process.cwd();
  }

  private buildFindings(results: OSVResult[], root: string): Finding[] {
    const findings: Finding[] = [];
    const pkgJsonPath = join(root, 'package.json');

    for (const result of results) {
      const seenVulns = new Set<string>();

      for (const vuln of result.vulns) {
        if (seenVulns.has(vuln.id)) continue;
        seenVulns.add(vuln.id);

        const rule: RuleDefinition = {
          ...RULE_KNOWN_VULN,
          severity: vuln.severity as Severity,
          title: `${RULE_KNOWN_VULN.title}: ${vuln.id}`,
          description: `${result.package}@${result.version} — ${vuln.summary}`,
        };

        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          description: rule.description,
          file: pkgJsonPath,
          line: 1,
          column: 1,
          codeSnippet: `"${result.package}": "${result.version}"`,
          cwe: rule.cwe,
          owasp: rule.owasp,
          remediation: rule.remediation,
        });
      }
    }

    return findings;
  }
}
