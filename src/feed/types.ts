export interface VulnEntry {
  id: string;
  source: 'osv' | 'github' | 'nvd';
  package: string;
  affectedVersions: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore?: number;
  summary: string;
  description: string;
  publishedAt: string;
  references: string[];
}

export interface FeedSource {
  name: string;
  fetch(options?: { verbose?: boolean }): Promise<VulnEntry[]>;
}

export interface CacheStatus {
  totalEntries: number;
  lastUpdate: string | null;
  isExpired: boolean;
}
