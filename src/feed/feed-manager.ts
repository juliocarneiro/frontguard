import type { FrontGuardConfig } from '../core/types.js';
import type { FeedSource, VulnEntry, CacheStatus } from './types.js';
import { VulnCache } from './cache.js';
import { OSVSource } from './sources/osv-source.js';
import { GitHubSource } from './sources/github-source.js';
import { NVDSource } from './sources/nvd-source.js';

export class FeedManager {
  private sources: FeedSource[] = [];
  private cache: VulnCache;
  private config: FrontGuardConfig;

  constructor(config: FrontGuardConfig) {
    this.config = config;
    this.cache = new VulnCache();

    for (const name of config.feed.sources) {
      switch (name) {
        case 'osv':
          this.sources.push(new OSVSource());
          break;
        case 'github':
          this.sources.push(new GitHubSource(config.feed.githubToken));
          break;
        case 'nvd':
          this.sources.push(new NVDSource(config.feed.nvdApiKey));
          break;
        default:
          console.warn(`[feed] unknown source: ${name}`);
      }
    }
  }

  async update(verbose?: boolean): Promise<number> {
    const allEntries: VulnEntry[] = [];

    const results = await Promise.allSettled(
      this.sources.map(source => source.fetch({ verbose })),
    );

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === 'fulfilled') {
        allEntries.push(...result.value);
      } else {
        console.warn(`[feed] ${this.sources[i].name} failed: ${result.reason}`);
      }
    }

    if (allEntries.length > 0) {
      this.cache.upsertMany(allEntries);
    }

    if (verbose) {
      console.log(`[feed] total entries upserted: ${allEntries.length}`);
    }

    return allEntries.length;
  }

  async getStatus(): Promise<CacheStatus> {
    return this.cache.getStatus(this.config.feed.ttl);
  }

  async checkPackage(name: string, version: string): Promise<VulnEntry[]> {
    return this.cache.query(name, version);
  }

  async ensureFresh(): Promise<void> {
    if (this.cache.isExpired(this.config.feed.ttl)) {
      await this.update();
    }
  }

  close(): void {
    this.cache.close();
  }
}
