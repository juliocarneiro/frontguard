import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ConfigError, resolveConfig, type ResolvedConfig, type UserConfig } from './schema.ts';

const CONFIG_FILES = [
  'frontguard.config.ts',
  'frontguard.config.mts',
  'frontguard.config.js',
  'frontguard.config.mjs',
  '.frontguardrc.json',
] as const;

/** Identity helper that gives config files type checking and autocompletion. */
export function defineConfig(config: UserConfig): UserConfig {
  return config;
}

export function findConfigFile(dir: string): string | undefined {
  for (const name of CONFIG_FILES) {
    const candidate = join(dir, name);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

async function importConfig(file: string): Promise<unknown> {
  if (file.endsWith('.json')) {
    return JSON.parse(await readFile(file, 'utf8')) as unknown;
  }
  // TypeScript configs rely on Node's built-in type stripping (Node >= 22.18).
  const mod = (await import(pathToFileURL(file).href)) as { default?: unknown };
  return mod.default ?? mod;
}

export interface LoadedConfig {
  config: ResolvedConfig;
  /** Absolute path of the config file, if one was used. */
  file?: string;
}

/**
 * Loads and validates the config. An explicit `configPath` must exist; otherwise the
 * known file names are looked up in `cwd`. Errors are never swallowed.
 */
export async function loadConfig(cwd: string, configPath?: string): Promise<LoadedConfig> {
  const file = configPath ? resolve(cwd, configPath) : findConfigFile(cwd);
  if (!file) return { config: resolveConfig() };
  if (!existsSync(file)) throw new ConfigError(`Config file not found: ${file}`);

  let raw: unknown;
  try {
    raw = await importConfig(file);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new ConfigError(`Failed to load ${file}: ${reason}`);
  }

  try {
    return { config: resolveConfig(raw as UserConfig), file };
  } catch (error) {
    if (error instanceof ConfigError) throw new ConfigError(`${file}\n${error.message}`);
    throw error;
  }
}
