import type { FeedSource, VulnEntry } from '../types.js';

interface NVDResponse {
  resultsPerPage: number;
  totalResults: number;
  vulnerabilities: Array<{
    cve: {
      id: string;
      descriptions: Array<{ lang: string; value: string }>;
      published: string;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: { baseScore: number; baseSeverity: string };
        }>;
      };
      references?: Array<{ url: string }>;
      configurations?: Array<{
        nodes: Array<{
          cpeMatch: Array<{
            criteria: string;
            versionStartIncluding?: string;
            versionEndExcluding?: string;
            versionEndIncluding?: string;
          }>;
        }>;
      }>;
    };
  }>;
}

function mapSeverity(baseSeverity: string): VulnEntry['severity'] {
  switch (baseSeverity.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'medium';
  }
}

function extractPackageFromCpe(criteria: string): string | null {
  const parts = criteria.split(':');
  if (parts.length >= 5) return parts[4];
  return null;
}

function buildVersionRange(
  nodes: NVDResponse['vulnerabilities'][0]['cve']['configurations'],
): string {
  if (!nodes?.length) return '*';
  const ranges: string[] = [];

  for (const config of nodes) {
    for (const node of config.nodes) {
      for (const match of node.cpeMatch) {
        const start = match.versionStartIncluding;
        const endExcl = match.versionEndExcluding;
        const endIncl = match.versionEndIncluding;

        if (start && endExcl) ranges.push(`>=${start} <${endExcl}`);
        else if (start && endIncl) ranges.push(`>=${start} <=${endIncl}`);
        else if (endExcl) ranges.push(`<${endExcl}`);
        else if (endIncl) ranges.push(`<=${endIncl}`);
        else if (start) ranges.push(`>=${start}`);
      }
    }
  }

  return ranges.join(' || ') || '*';
}

export class NVDSource implements FeedSource {
  name = 'nvd';
  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey;
  }

  async fetch(options?: { verbose?: boolean }): Promise<VulnEntry[]> {
    const entries: VulnEntry[] = [];
    const url =
      'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=javascript+npm&resultsPerPage=100';

    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers['apiKey'] = this.apiKey;
    }

    try {
      const res = await fetch(url, { headers });

      if (res.status === 403 || res.status === 429) {
        console.warn('[nvd] rate limited, try again later or provide an API key');
        return entries;
      }

      if (!res.ok) {
        if (options?.verbose) {
          console.warn(`[nvd] API returned ${res.status}`);
        }
        return entries;
      }

      const data = (await res.json()) as NVDResponse;

      for (const item of data.vulnerabilities) {
        const cve = item.cve;
        const metric = cve.metrics?.cvssMetricV31?.[0];
        const enDesc = cve.descriptions.find(d => d.lang === 'en');

        let packageName = 'unknown';
        if (cve.configurations?.length) {
          for (const config of cve.configurations) {
            for (const node of config.nodes) {
              for (const match of node.cpeMatch) {
                const name = extractPackageFromCpe(match.criteria);
                if (name) {
                  packageName = name;
                  break;
                }
              }
              if (packageName !== 'unknown') break;
            }
            if (packageName !== 'unknown') break;
          }
        }

        entries.push({
          id: cve.id,
          source: 'nvd',
          package: packageName,
          affectedVersions: buildVersionRange(cve.configurations),
          severity: metric ? mapSeverity(metric.cvssData.baseSeverity) : 'medium',
          cvssScore: metric?.cvssData.baseScore,
          summary: enDesc?.value?.slice(0, 200) ?? cve.id,
          description: enDesc?.value ?? '',
          publishedAt: cve.published,
          references: cve.references?.map(r => r.url) ?? [],
        });
      }
    } catch (err) {
      console.warn(`[nvd] fetch failed: ${(err as Error).message}`);
    }

    if (options?.verbose) {
      console.log(`[nvd] fetched ${entries.length} entries`);
    }

    return entries;
  }
}
