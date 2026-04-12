import type { Severity } from '../../core/types.js';

export interface OSVVulnerability {
  id: string;
  summary: string;
  details?: string;
  severity: Severity;
  aliases?: string[];
  references?: { type: string; url: string }[];
}

export interface OSVResult {
  package: string;
  version: string;
  vulns: OSVVulnerability[];
}

interface OSVQueryResponse {
  results: {
    vulns?: {
      id: string;
      summary?: string;
      details?: string;
      database_specific?: Record<string, unknown>;
      severity?: { type: string; score: string }[];
      aliases?: string[];
      references?: { type: string; url: string }[];
    }[];
  }[];
}

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

type OSVRawVuln = NonNullable<OSVQueryResponse['results'][number]['vulns']>[number];

function mapSeverity(vuln: OSVRawVuln): Severity {
  if (vuln.severity && vuln.severity.length > 0) {
    const cvss = vuln.severity.find(s => s.type === 'CVSS_V3') ?? vuln.severity[0];
    const score = parseFloat(cvss.score);
    if (!isNaN(score)) {
      if (score >= 9.0) return 'critical';
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      return 'low';
    }
  }

  const summary = (vuln.summary ?? '').toLowerCase();
  if (summary.includes('critical')) return 'critical';
  if (summary.includes('high')) return 'high';
  if (summary.includes('moderate') || summary.includes('medium')) return 'medium';
  return 'low';
}

export async function queryOSV(
  packages: { name: string; version: string }[],
): Promise<OSVResult[]> {
  if (packages.length === 0) return [];

  const body = {
    queries: packages.map(pkg => ({
      package: { name: pkg.name, ecosystem: 'npm' },
      version: pkg.version,
    })),
  };

  let data: OSVQueryResponse;

  try {
    const response = await fetch(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      return [];
    }

    data = (await response.json()) as OSVQueryResponse;
  } catch {
    return [];
  }

  const results: OSVResult[] = [];

  for (let i = 0; i < packages.length; i++) {
    const entry = data.results[i];
    if (!entry?.vulns || entry.vulns.length === 0) continue;

    results.push({
      package: packages[i].name,
      version: packages[i].version,
      vulns: entry.vulns.map(v => ({
        id: v.id,
        summary: v.summary ?? v.id,
        details: v.details,
        severity: mapSeverity(v),
        aliases: v.aliases,
        references: v.references,
      })),
    });
  }

  return results;
}
