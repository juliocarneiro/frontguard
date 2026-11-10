import { severityFromScore } from '../core/severity.ts';
import type { Severity } from '../types.ts';
import { cvss3BaseScore } from './cvss.ts';
import { compareVersions } from './semver.ts';

const API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 8;

export interface OsvClientOptions {
  fetch: typeof globalThis.fetch;
  timeoutMs: number;
}

export interface Advisory {
  id: string;
  summary: string;
  aliases: string[];
  severity: Severity;
  /** Lowest version that fixes the advisory for the queried version, if known. */
  fixedIn?: string;
  url: string;
}

interface RawVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: {
      type: string;
      events: Partial<Record<'introduced' | 'fixed' | 'last_affected' | 'limit', string>>[];
    }[];
  }[];
}

async function request<T>(url: string, init: RequestInit, options: OsvClientOptions): Promise<T> {
  const response = await options.fetch(url, {
    ...init,
    headers: { 'content-type': 'application/json' },
    signal: AbortSignal.timeout(options.timeoutMs),
  });
  if (!response.ok) throw new Error(`${url} responded ${response.status}`);
  return (await response.json()) as T;
}

/** Returns, for each package, the ids of advisories affecting that exact version. */
export async function queryVulnerabilityIds(
  packages: { name: string; version: string }[],
  options: OsvClientOptions,
): Promise<string[][]> {
  const ids: string[][] = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const batch = packages.slice(i, i + BATCH_SIZE);
    const body = JSON.stringify({
      queries: batch.map((p) => ({
        package: { name: p.name, ecosystem: 'npm' },
        version: p.version,
      })),
    });
    const data = await request<{ results?: { vulns?: { id: string }[] }[] }>(
      `${API}/querybatch`,
      { method: 'POST', body },
      options,
    );
    for (let j = 0; j < batch.length; j++) {
      ids.push(data.results?.[j]?.vulns?.map((v) => v.id) ?? []);
    }
  }
  return ids;
}

/** Fetches full advisory records, which the batch endpoint does not include. */
export async function fetchVulnerabilities(
  ids: string[],
  options: OsvClientOptions,
): Promise<Map<string, RawVuln>> {
  const result = new Map<string, RawVuln>();
  const queue = [...new Set(ids)];
  const worker = async () => {
    for (let id = queue.shift(); id; id = queue.shift()) {
      result.set(id, await request<RawVuln>(`${API}/vulns/${encodeURIComponent(id)}`, {}, options));
    }
  };
  await Promise.all(Array.from({ length: DETAIL_CONCURRENCY }, worker));
  return result;
}

const GHSA_SEVERITY: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  LOW: 'low',
};

export function severityOf(vuln: RawVuln): Severity {
  const label = vuln.database_specific?.severity?.toUpperCase();
  if (label && label in GHSA_SEVERITY) return GHSA_SEVERITY[label]!;
  for (const entry of vuln.severity ?? []) {
    const score = cvss3BaseScore(entry.score);
    if (score !== null) return severityFromScore(score);
  }
  return 'medium';
}

/** Finds the `fixed` event of the affected range that contains `version`. */
export function fixedVersionFor(vuln: RawVuln, name: string, version: string): string | undefined {
  const candidates: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== 'npm' || affected.package.name !== name) continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      let introduced: string | undefined;
      for (const event of range.events) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed !== undefined && introduced !== undefined) {
          const lower = introduced === '0' ? '0.0.0' : introduced;
          if (compareVersions(version, lower) >= 0 && compareVersions(version, event.fixed) < 0) {
            candidates.push(event.fixed);
          }
          introduced = undefined;
        }
      }
    }
  }
  return candidates.sort(compareVersions)[0];
}

export function toAdvisory(vuln: RawVuln, name: string, version: string): Advisory {
  const fixedIn = fixedVersionFor(vuln, name, version);
  return {
    id: vuln.id,
    summary: vuln.summary ?? vuln.details?.split('\n')[0]?.slice(0, 160) ?? vuln.id,
    aliases: vuln.aliases ?? [],
    severity: severityOf(vuln),
    ...(fixedIn && { fixedIn }),
    url: `https://osv.dev/vulnerability/${vuln.id}`,
  };
}
