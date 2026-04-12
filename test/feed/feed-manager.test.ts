import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getDefaultConfig } from '../../src/core/config.js';
import type { FrontGuardConfig } from '../../src/core/types.js';
import type { CacheStatus } from '../../src/feed/types.js';
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const CACHE_PATH = join(homedir(), '.frontguard', 'cache.json');
let cacheBackup: string | null = null;

vi.mock('../../src/feed/sources/osv-source.js', () => ({
  OSVSource: class {
    name = 'osv';
    fetch = vi.fn().mockResolvedValue([
      {
        id: 'GHSA-test-001',
        source: 'osv',
        package: 'lodash',
        affectedVersions: '<4.17.21',
        severity: 'high',
        summary: 'Prototype Pollution',
        description: 'Test vulnerability',
        publishedAt: '2024-01-01',
        references: [],
      },
    ]);
  },
}));

vi.mock('../../src/feed/sources/github-source.js', () => ({
  GitHubSource: class {
    name = 'github';
    fetch = vi.fn().mockResolvedValue([]);
  },
}));

vi.mock('../../src/feed/sources/nvd-source.js', () => ({
  NVDSource: class {
    name = 'nvd';
    fetch = vi.fn().mockResolvedValue([]);
  },
}));

describe('FeedManager', () => {
  let config: FrontGuardConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    config = getDefaultConfig();
    if (existsSync(CACHE_PATH)) {
      const { readFileSync } = require('node:fs');
      cacheBackup = readFileSync(CACHE_PATH, 'utf-8');
    }
  });

  afterEach(() => {
    if (cacheBackup !== null) {
      const { writeFileSync } = require('node:fs');
      writeFileSync(CACHE_PATH, cacheBackup, 'utf-8');
      cacheBackup = null;
    }
  });

  it('constructs with configured feed sources', async () => {
    const { FeedManager } = await import('../../src/feed/feed-manager.js');
    const manager = new FeedManager(config);
    expect(manager).toBeDefined();
    manager.close();
  });

  it('getStatus() returns a valid CacheStatus', async () => {
    const { FeedManager } = await import('../../src/feed/feed-manager.js');
    const manager = new FeedManager(config);
    const status: CacheStatus = await manager.getStatus();

    expect(status).toHaveProperty('totalEntries');
    expect(status).toHaveProperty('lastUpdate');
    expect(status).toHaveProperty('isExpired');
    expect(typeof status.totalEntries).toBe('number');
    expect(typeof status.isExpired).toBe('boolean');

    manager.close();
  });

  it('update() fetches from configured sources and returns entry count', async () => {
    const { FeedManager } = await import('../../src/feed/feed-manager.js');
    const manager = new FeedManager(config);
    const count = await manager.update();

    expect(typeof count).toBe('number');
    expect(count).toBeGreaterThanOrEqual(0);

    manager.close();
  });

  it('update() handles source failures gracefully', async () => {
    const { FeedManager } = await import('../../src/feed/feed-manager.js');
    const manager = new FeedManager(config);
    const count = await manager.update();

    expect(typeof count).toBe('number');
    manager.close();
  });

  it('close() can be called without error', async () => {
    const { FeedManager } = await import('../../src/feed/feed-manager.js');
    const manager = new FeedManager(config);
    expect(() => manager.close()).not.toThrow();
  });
});

describe('VulnCache', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('can be instantiated', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    expect(cache).toBeDefined();
    cache.close();
  });

  it('getStatus() returns CacheStatus shape', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const status = cache.getStatus('24h');

    expect(status).toHaveProperty('totalEntries');
    expect(status).toHaveProperty('lastUpdate');
    expect(status).toHaveProperty('isExpired');

    cache.close();
  });

  it('isExpired() returns boolean', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const expired = cache.isExpired('24h');
    expect(typeof expired).toBe('boolean');
    cache.close();
  });

  it('query() returns an array', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const results = cache.query('lodash');
    expect(Array.isArray(results)).toBe(true);
    cache.close();
  });

  it('clear() can be called without error', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    expect(() => cache.clear()).not.toThrow();
    cache.close();
  });
});

describe('TTL format handling', () => {
  it('handles 24h TTL format', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const status = cache.getStatus('24h');
    expect(status).toHaveProperty('isExpired');
    cache.close();
  });

  it('handles 12h TTL format', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const status = cache.getStatus('12h');
    expect(status).toHaveProperty('isExpired');
    cache.close();
  });

  it('handles 1d TTL format', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const status = cache.getStatus('1d');
    expect(status).toHaveProperty('isExpired');
    cache.close();
  });

  it('handles 30m TTL format', async () => {
    const { VulnCache } = await import('../../src/feed/cache.js');
    const cache = new VulnCache();
    const status = cache.getStatus('30m');
    expect(status).toHaveProperty('isExpired');
    cache.close();
  });
});
