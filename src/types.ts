import type { File as BabelFile } from '@babel/types';
import type { Visitor } from '@babel/traverse';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category = 'xss' | 'secrets' | 'auth' | 'misconfig' | 'dependencies';

/** `off` disables a rule, `warn` reports it without failing the scan, `error` is the default. */
export type RuleLevel = 'off' | 'warn' | 'error';

export interface RuleMeta {
  /** Stable identifier, e.g. `FG-XSS-001`. */
  id: string;
  /** Short kebab-case name, e.g. `no-inner-html`. */
  name: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  remediation: string;
  cwe?: string;
  owasp?: string;
}

export interface Location {
  /** 1-based line. */
  line: number;
  /** 1-based column. */
  column: number;
}

export interface ReportDescriptor extends Location {
  /** Extra detail appended to the rule title, e.g. the secret provider. */
  message?: string;
  /** Overrides the rule's default severity for this finding. */
  severity?: Severity;
  /** A sensitive value that must be masked in snippets and reports. */
  redact?: string;
}

export interface RuleContext {
  /** Path relative to the scan root, with forward slashes. */
  readonly filename: string;
  /** Full raw text of the file. */
  readonly text: string;
  readonly lines: readonly string[];
  /** Parsed script (whole file for JS/TS, `<script>` blocks for Vue/Svelte/HTML). `null` when there is no script or it failed to parse. */
  readonly ast: BabelFile | null;
  report(descriptor: ReportDescriptor): void;
}

/**
 * A rule is created once per file. It can inspect `context.text` / `context.lines`
 * directly and/or return Babel visitors, which the engine merges and runs in a single traversal.
 */
export interface Rule {
  meta: RuleMeta;
  create(context: RuleContext): Visitor | undefined;
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  level: Exclude<RuleLevel, 'off'>;
  category: Category;
  title: string;
  message: string;
  description: string;
  remediation: string;
  /** Path relative to the scan root, with forward slashes. */
  file: string;
  line: number;
  column: number;
  snippet: string;
  cwe?: string;
  owasp?: string;
  /** Extra structured data, e.g. vulnerability ids for dependency findings. */
  data?: Record<string, unknown>;
}

export interface ScanResult {
  /** Absolute path of the scanned directory. */
  root: string;
  findings: Finding[];
  /** Non-fatal problems (unparseable files, network errors). */
  warnings: string[];
  filesScanned: number;
  durationMs: number;
  startedAt: string;
  rules: RuleMeta[];
}
