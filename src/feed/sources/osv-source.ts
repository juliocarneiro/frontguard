import type { FeedSource, VulnEntry } from '../types.js';

interface OSVVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string };
    ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
    versions?: string[];
  }>;
  references?: Array<{ url: string }>;
  published?: string;
  database_specific?: Record<string, unknown>;
}

function mapSeverity(vuln: OSVVuln): VulnEntry['severity'] {
  const scoring = vuln.severity?.find(s => s.type === 'CVSS_V3');
  if (!scoring) return 'medium';
  const score = parseFloat(scoring.score);
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function extractCvss(vuln: OSVVuln): number | undefined {
  const scoring = vuln.severity?.find(s => s.type === 'CVSS_V3');
  return scoring ? parseFloat(scoring.score) : undefined;
}

function buildAffectedRange(affected?: OSVVuln['affected']): string {
  if (!affected?.length) return '*';
  const parts: string[] = [];
  for (const a of affected) {
    if (a.ranges) {
      for (const range of a.ranges) {
        const introduced = range.events.find(e => e.introduced)?.introduced ?? '0';
        const fixed = range.events.find(e => e.fixed)?.fixed;
        parts.push(fixed ? `>=${introduced} <${fixed}` : `>=${introduced}`);
      }
    } else if (a.versions?.length) {
      parts.push(a.versions.join(' || '));
    }
  }
  return parts.join(' || ') || '*';
}

function toVulnEntry(vuln: OSVVuln): VulnEntry | null {
  const npmAffected = vuln.affected?.filter(
    a => a.package?.ecosystem === 'npm',
  );
  if (!npmAffected?.length) return null;

  const packageName = npmAffected[0].package?.name ?? 'unknown';

  return {
    id: vuln.id,
    source: 'osv',
    package: packageName,
    affectedVersions: buildAffectedRange(npmAffected),
    severity: mapSeverity(vuln),
    cvssScore: extractCvss(vuln),
    summary: vuln.summary ?? vuln.id,
    description: vuln.details ?? vuln.summary ?? '',
    publishedAt: vuln.published ?? new Date().toISOString(),
    references: vuln.references?.map(r => r.url) ?? [],
  };
}

export class OSVSource implements FeedSource {
  name = 'osv';

  async fetch(options?: { verbose?: boolean }): Promise<VulnEntry[]> {
    const entries: VulnEntry[] = [];

    try {
      const batchUrl = 'https://api.osv.dev/v1/querybatch';
      const res = await fetch(batchUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: [{ package: { ecosystem: 'npm', name: '' } }],
        }),
      });

      if (!res.ok) {
        if (options?.verbose) {
          console.warn(`[osv] querybatch returned ${res.status}, trying list endpoint`);
        }
      } else {
        const data = (await res.json()) as { results?: Array<{ vulns?: OSVVuln[] }> };
        for (const result of data.results ?? []) {
          for (const vuln of result.vulns ?? []) {
            const entry = toVulnEntry(vuln);
            if (entry) entries.push(entry);
          }
        }
      }
    } catch (err) {
      if (options?.verbose) {
        console.warn(`[osv] querybatch failed: ${(err as Error).message}`);
      }
    }

    try {
      const listUrl = 'https://api.osv.dev/v1/query';
      const res = await fetch(listUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: { ecosystem: 'npm' },
          version: '',
        }),
      });

      if (res.ok) {
        const data = (await res.json()) as { vulns?: OSVVuln[] };
        const seen = new Set(entries.map(e => e.id));
        for (const vuln of data.vulns ?? []) {
          if (seen.has(vuln.id)) continue;
          const entry = toVulnEntry(vuln);
          if (entry) entries.push(entry);
        }
      } else if (options?.verbose) {
        console.warn(`[osv] query returned ${res.status}`);
      }
    } catch (err) {
      if (options?.verbose) {
        console.warn(`[osv] query failed: ${(err as Error).message}`);
      }
    }

    if (options?.verbose) {
      console.log(`[osv] fetched ${entries.length} entries`);
    }

    return entries;
  }
}
