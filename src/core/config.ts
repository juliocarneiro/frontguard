import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { FrontGuardConfig } from './types.js';

const DEFAULT_CONFIG: FrontGuardConfig = {
  include: ['**/*.{ts,tsx,js,jsx,vue,svelte}'],
  exclude: [
    'node_modules', '**/node_modules/**', 'dist', 'build', '.next', '.nuxt', '.svelte-kit',
    '**/*.test.*', '**/*.spec.*', '**/*.d.ts',
    '**/test/**', '**/tests/**', '**/__tests__/**', '**/fixtures/**',
    '**/coverage/**', '**/frontguard-report/**',
  ],
  scanners: {
    xss: true,
    dependencies: true,
    secrets: true,
    misconfig: true,
    authPatterns: true,
  },
  rules: {},
  severity: {
    failOn: 'high',
  },
  reporters: ['console'],
  output: './frontguard-report',
  feed: {
    autoUpdate: true,
    ttl: '24h',
    sources: ['osv', 'github', 'nvd'],
  },
  ai: {
    enabled: false,
    provider: 'openai',
    model: 'gpt-4o-mini',
    features: {
      deepScan: true,
      autoFix: false,
      crossFileFlow: true,
      customRules: [],
    },
    confirmBeforeSend: true,
    ollamaBaseUrl: 'http://localhost:11434',
  },
};

export function defineConfig(config: Partial<FrontGuardConfig>): FrontGuardConfig {
  return mergeConfig(DEFAULT_CONFIG, config);
}

export function getDefaultConfig(): FrontGuardConfig {
  return { ...DEFAULT_CONFIG };
}

function mergeConfig(
  base: FrontGuardConfig,
  override: Partial<FrontGuardConfig>,
): FrontGuardConfig {
  return {
    ...base,
    ...override,
    scanners: { ...base.scanners, ...override.scanners },
    rules: { ...base.rules, ...override.rules },
    severity: { ...base.severity, ...override.severity },
    feed: { ...base.feed, ...override.feed },
    ai: {
      ...base.ai,
      ...override.ai,
      features: { ...base.ai.features, ...override.ai?.features },
    },
    include: override.include ?? base.include,
    exclude: override.exclude ?? base.exclude,
    reporters: override.reporters ?? base.reporters,
  };
}

const CONFIG_FILES = [
  'frontguard.config.ts',
  'frontguard.config.js',
  'frontguard.config.mjs',
  '.frontguardrc.json',
];

export async function loadConfig(configPath?: string): Promise<FrontGuardConfig> {
  if (configPath) {
    return loadConfigFile(configPath);
  }

  for (const file of CONFIG_FILES) {
    const fullPath = resolve(process.cwd(), file);
    if (existsSync(fullPath)) {
      return loadConfigFile(fullPath);
    }
  }

  return getDefaultConfig();
}

async function loadConfigFile(filePath: string): Promise<FrontGuardConfig> {
  const fullPath = resolve(filePath);

  if (filePath.endsWith('.json')) {
    const raw = readFileSync(fullPath, 'utf-8');
    return mergeConfig(DEFAULT_CONFIG, JSON.parse(raw));
  }

  try {
    const url = pathToFileURL(fullPath).href;
    const mod = await import(url);
    const userConfig = mod.default ?? mod;
    return mergeConfig(DEFAULT_CONFIG, userConfig);
  } catch {
    return getDefaultConfig();
  }
}

export function generateConfigTemplate(): string {
  return `import { defineConfig } from 'frontguard';

export default defineConfig({
  include: ['src/**/*.{ts,tsx,js,jsx,vue,svelte}'],
  exclude: [
    'node_modules', 'dist', 'build', '.next',
    '**/*.test.*', '**/*.spec.*', '**/*.d.ts',
    '**/test/**', '**/tests/**', '**/__tests__/**', '**/fixtures/**',
  ],
  scanners: {
    xss: true,
    dependencies: true,
    secrets: true,
    misconfig: true,
    authPatterns: true,
  },
  rules: {
    'FG-XSS-002': 'error',
    'FG-SEC-006': 'warn',
  },
  severity: {
    failOn: 'high',
  },
  reporters: ['console'],
  output: './frontguard-report',
  feed: {
    autoUpdate: true,
    ttl: '24h',
    sources: ['osv', 'github', 'nvd'],
  },
  ai: {
    enabled: false,
    provider: 'openai',
    model: 'gpt-4o-mini',
    features: {
      deepScan: true,
      autoFix: false,
      crossFileFlow: true,
      customRules: [],
    },
    confirmBeforeSend: true,
    ollamaBaseUrl: 'http://localhost:11434',
  },
});
`;
}
