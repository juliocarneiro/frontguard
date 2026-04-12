import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Finding, Reporter, ScanResult, Severity } from '../core/types.js';

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn: number; snippet?: { text: string } };
    };
  }[];
}

const SEVERITY_TO_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

function buildRules(findings: Finding[]): SarifRule[] {
  const seen = new Map<string, SarifRule>();
  for (const f of findings) {
    if (seen.has(f.ruleId)) continue;
    const tags: string[] = [f.category];
    if (f.cwe) tags.push(f.cwe);
    if (f.owasp) tags.push(f.owasp);
    seen.set(f.ruleId, {
      id: f.ruleId,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description },
      properties: { tags },
    });
  }
  return [...seen.values()];
}

function buildResults(findings: Finding[], rules: SarifRule[]): SarifResult[] {
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));
  return findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: { text: `${f.description}\n\nRemediation: ${f.remediation}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: {
            startLine: f.line,
            startColumn: f.column,
            snippet: { text: f.codeSnippet },
          },
        },
      },
    ],
  }));
}

export class SarifReporter implements Reporter {
  name = 'sarif';

  constructor(private outputPath: string) {}

  async generate(result: ScanResult): Promise<string> {
    await mkdir(dirname(this.outputPath), { recursive: true });

    const rules = buildRules(result.findings);
    const results = buildResults(result.findings, rules);

    const sarif = {
      $schema:
        'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0' as const,
      runs: [
        {
          tool: {
            driver: {
              name: 'FrontGuard',
              version: '0.1.0',
              informationUri: 'https://github.com/frontguard/frontguard',
              rules,
            },
          },
          results,
        },
      ],
    };

    await writeFile(this.outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
    return this.outputPath;
  }
}
