import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { VulnEntry, CacheStatus } from './types.js';

const CACHE_DIR = join(homedir(), '.frontguard');
const CACHE_PATH = join(CACHE_DIR, 'cache.json');

interface CacheData {
  entries: Record<string, VulnEntry & { fetchedAt: string }>;
}

function parseTtl(ttl: string): number {
  const match = ttl.match(/^(\d+)(h|d|m)$/);
  if (!match) return 24 * 60 * 60 * 1000;
  const value = parseInt(match[1], 10);
  switch (match[2]) {
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    case 'm': return value * 60 * 1000;
    default: return 24 * 60 * 60 * 1000;
  }
}

export class VulnCache {
  private data: CacheData;

  constructor() {
    if (!existsSync(CACHE_DIR)) {
      mkdirSync(CACHE_DIR, { recursive: true });
    }
    this.data = this.load();
  }

  private load(): CacheData {
    if (!existsSync(CACHE_PATH)) {
      return { entries: {} };
    }
    try {
      const raw = readFileSync(CACHE_PATH, 'utf-8');
      return JSON.parse(raw);
    } catch {
      return { entries: {} };
    }
  }

  private save(): void {
    writeFileSync(CACHE_PATH, JSON.stringify(this.data), 'utf-8');
  }

  upsertMany(entries: VulnEntry[]): number {
    const now = new Date().toISOString();
    let count = 0;
    for (const entry of entries) {
      this.data.entries[entry.id] = { ...entry, fetchedAt: now };
      count++;
    }
    this.save();
    return count;
  }

  query(packageName: string, _version?: string): VulnEntry[] {
    return Object.values(this.data.entries)
      .filter(e => e.package === packageName)
      .map(({ fetchedAt: _, ...entry }) => entry);
  }

  getStatus(ttl: string): CacheStatus {
    const all = Object.values(this.data.entries);
    let lastUpdate: string | null = null;

    if (all.length > 0) {
      lastUpdate = all.reduce((latest, e) =>
        e.fetchedAt > latest ? e.fetchedAt : latest,
        all[0].fetchedAt,
      );
    }

    return {
      totalEntries: all.length,
      lastUpdate,
      isExpired: this.isExpired(ttl),
    };
  }

  isExpired(ttl: string): boolean {
    const all = Object.values(this.data.entries);
    if (all.length === 0) return true;

    const latest = all.reduce((max, e) =>
      e.fetchedAt > max ? e.fetchedAt : max,
      all[0].fetchedAt,
    );

    return Date.now() - new Date(latest).getTime() > parseTtl(ttl);
  }

  clear(): void {
    this.data = { entries: {} };
    this.save();
  }

  close(): void {
    // no-op for JSON cache (kept for API compatibility)
  }
}
