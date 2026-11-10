import { createHash } from 'node:crypto';
import type { Finding, RuleMeta, ScanResult, Severity } from '../types.ts';
import { HOMEPAGE, RULES_DOC_URL, VERSION } from '../version.ts';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub code scanning ranks alerts by this 0-10 score. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

function fingerprint(finding: Finding): string {
  const anchor = finding.snippet.split('\n').find((line) => line.startsWith('>')) ?? '';
  return createHash('sha256')
    .update(`${finding.ruleId}|${finding.file}|${anchor.replace(/^>\s*\d+\s*\|/, '').trim()}`)
    .digest('hex')
    .slice(0, 32);
}

function ruleDescriptor(meta: RuleMeta) {
  const tags = ['security', meta.category];
  if (meta.cwe) tags.push(`external/cwe/${meta.cwe.toLowerCase()}`);
  return {
    id: meta.id,
    name: meta.name,
    shortDescription: { text: meta.title },
    fullDescription: { text: meta.description },
    help: { text: meta.remediation, markdown: meta.remediation },
    helpUri: `${RULES_DOC_URL}#${meta.id.toLowerCase()}`,
    defaultConfiguration: { level: LEVEL[meta.severity] },
    properties: {
      tags,
      precision: meta.id === 'FG-SEC-006' ? 'low' : 'medium',
      'security-severity': SECURITY_SEVERITY[meta.severity],
    },
  };
}

/** SARIF 2.1.0 log, ready for `github/codeql-action/upload-sarif`. Paths are relative to the scan root. */
export function toSarif(result: ScanResult): string {
  const rules = result.rules.map(ruleDescriptor);
  const index = new Map(rules.map((rule, i) => [rule.id, i]));

  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'FrontGuard',
            semanticVersion: VERSION,
            informationUri: HOMEPAGE,
            rules,
          },
        },
        originalUriBaseIds: {
          SRCROOT: { uri: `file:///${result.root.replace(/\\/g, '/').replace(/^\//, '')}/` },
        },
        results: result.findings.map((finding) => ({
          ruleId: finding.ruleId,
          ...(index.has(finding.ruleId) && { ruleIndex: index.get(finding.ruleId) }),
          level: finding.level === 'warn' ? 'warning' : LEVEL[finding.severity],
          message: { text: `${finding.message}. ${finding.remediation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: encodeURI(finding.file), uriBaseId: 'SRCROOT' },
                region: { startLine: finding.line, startColumn: finding.column },
              },
            },
          ],
          partialFingerprints: { 'frontguard/v1': fingerprint(finding) },
          properties: { 'security-severity': SECURITY_SEVERITY[finding.severity] },
        })),
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
