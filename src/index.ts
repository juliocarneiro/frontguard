export { ScanEngine } from './core/engine.js';
export { defineConfig, loadConfig, getDefaultConfig } from './core/config.js';
export { ruleRegistry } from './core/rule-registry.js';
export { discoverFiles, readFileContent } from './core/file-discovery.js';
export { meetsThreshold, compareSeverity, severityToNumber } from './core/severity.js';

export { BaseScanner } from './scanners/base-scanner.js';
export { XSSScanner } from './scanners/xss/index.js';
export { SecretsScanner } from './scanners/secrets/index.js';
export { DependencyScanner } from './scanners/dependencies/index.js';
export { AuthPatternsScanner } from './scanners/auth-patterns/index.js';
export { MisconfigScanner } from './scanners/misconfig/index.js';

export { ConsoleReporter } from './reporters/console-reporter.js';
export { JsonReporter } from './reporters/json-reporter.js';
export { HtmlReporter } from './reporters/html-reporter.js';
export { SarifReporter } from './reporters/sarif-reporter.js';

export type {
  Finding,
  ScanResult,
  FrontGuardConfig,
  RuleDefinition,
  Severity,
  RuleLevel,
  ScannerCategory,
  FileContent,
  Reporter,
} from './core/types.js';
