import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/load.ts';
import { ConfigError, resolveConfig } from '../../src/config/schema.ts';
import { tempProject } from '../helpers.ts';

describe('resolveConfig', () => {
  it('applies defaults', () => {
    const config = resolveConfig();
    expect(config.failOn).toBe('high');
    expect(config.reporters).toEqual(['console']);
    expect(config.categories).toEqual({
      xss: true,
      secrets: true,
      auth: true,
      misconfig: true,
      dependencies: true,
    });
  });

  it('merges partial category settings', () => {
    expect(resolveConfig({ categories: { dependencies: false } }).categories.dependencies).toBe(
      false,
    );
    expect(resolveConfig({ categories: { dependencies: false } }).categories.xss).toBe(true);
  });

  it('rejects unknown keys and invalid values with a readable error', () => {
    expect(() => resolveConfig({ failOn: 'urgent' } as never)).toThrow(ConfigError);
    expect(() => resolveConfig({ scanners: {} } as never)).toThrow(/scanners/);
  });
});

describe('loadConfig', () => {
  it('returns defaults when there is no config file', async () => {
    const root = tempProject({});
    expect((await loadConfig(root)).file).toBeUndefined();
  });

  it('loads .frontguardrc.json', async () => {
    const root = tempProject({ '.frontguardrc.json': '{ "failOn": "low" }' });
    const { config, file } = await loadConfig(root);
    expect(config.failOn).toBe('low');
    expect(file).toMatch(/\.frontguardrc\.json$/);
  });

  it('loads TypeScript configs through Node type stripping', async () => {
    const root = tempProject({
      'frontguard.config.ts': "const failOn: 'medium' = 'medium';\nexport default { failOn };\n",
    });
    expect((await loadConfig(root)).config.failOn).toBe('medium');
  });

  it('fails loudly on broken or invalid configs instead of using defaults', async () => {
    const broken = tempProject({ 'frontguard.config.mjs': 'export default {' });
    await expect(loadConfig(broken)).rejects.toThrow(/Failed to load/);

    const invalid = tempProject({ '.frontguardrc.json': '{ "failOn": 3 }' });
    await expect(loadConfig(invalid)).rejects.toThrow(ConfigError);

    await expect(loadConfig(tempProject({}), 'missing.json')).rejects.toThrow(/not found/);
  });
});
