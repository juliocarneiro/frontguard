import type { FeedSource, VulnEntry } from '../types.js';

interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  cvss?: { score: number };
  published_at: string;
  references: string[];
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string;
  }>;
}

function mapSeverity(sev: string): VulnEntry['severity'] {
  switch (sev.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'medium';
  }
}

export class GitHubSource implements FeedSource {
  name = 'github';
  private token?: string;

  constructor(token?: string) {
    this.token = token;
  }

  async fetch(options?: { verbose?: boolean }): Promise<VulnEntry[]> {
    const entries: VulnEntry[] = [];
    const url = 'https://api.github.com/advisories?ecosystem=npm&per_page=100';

    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const res = await fetch(url, { headers });

      if (res.status === 403 || res.status === 429) {
        const resetHeader = res.headers.get('x-ratelimit-reset');
        const resetTime = resetHeader ? new Date(parseInt(resetHeader) * 1000).toISOString() : 'unknown';
        console.warn(`[github] rate limited, resets at ${resetTime}`);
        return entries;
      }

      if (!res.ok) {
        if (options?.verbose) {
          console.warn(`[github] API returned ${res.status}`);
        }
        return entries;
      }

      const advisories = (await res.json()) as GitHubAdvisory[];

      for (const adv of advisories) {
        const npmVulns = adv.vulnerabilities.filter(
          v => v.package.ecosystem === 'npm',
        );
        if (!npmVulns.length) continue;

        for (const vuln of npmVulns) {
          entries.push({
            id: adv.cve_id ?? adv.ghsa_id,
            source: 'github',
            package: vuln.package.name,
            affectedVersions: vuln.vulnerable_version_range,
            severity: mapSeverity(adv.severity),
            cvssScore: adv.cvss?.score,
            summary: adv.summary,
            description: adv.description,
            publishedAt: adv.published_at,
            references: adv.references ?? [],
          });
        }
      }
    } catch (err) {
      console.warn(`[github] fetch failed: ${(err as Error).message}`);
    }

    if (options?.verbose) {
      console.log(`[github] fetched ${entries.length} entries`);
    }

    return entries;
  }
}
