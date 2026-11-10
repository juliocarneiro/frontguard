/**
 * FrontGuard programmatic API.
 *
 * @example
 * import { scan, toSarif } from '@juliocarneiro/frontguard';
 * const result = await scan({ cwd: 'apps/web', config: { failOn: 'medium' } });
 * await writeFile('frontguard.sarif', toSarif(result));
 */
export { scan, type ScanOptions } from './core/scan.ts';
export { defineConfig, loadConfig, type LoadedConfig } from './config/load.ts';
export {
  resolveConfig,
  ConfigError,
  type UserConfig,
  type ResolvedConfig,
} from './config/schema.ts';
export { defineRule } from './core/rule.ts';
export { builtinRules } from './rules/index.ts';
export { DEPENDENCY_RULE } from './dependencies/audit.ts';
export { meetsThreshold } from './core/severity.ts';
export { toConsole, toHtml, toJson, toSarif, writeReports } from './reporters/index.ts';
export { VERSION } from './version.ts';
export type {
  Category,
  Finding,
  Location,
  ReportDescriptor,
  Rule,
  RuleContext,
  RuleLevel,
  RuleMeta,
  ScanResult,
  Severity,
} from './types.ts';
