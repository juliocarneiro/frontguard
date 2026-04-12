export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RuleLevel = 'error' | 'warn' | 'off';
export type ScannerCategory = 'xss' | 'dependencies' | 'secrets' | 'misconfig' | 'auth-patterns';

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: ScannerCategory;
  title: string;
  description: string;
  file: string;
  line: number;
  column: number;
  codeSnippet: string;
  cwe?: string;
  owasp?: string;
  remediation: string;
  aiAnalyzed?: boolean;
  aiConfidence?: number;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  scanDuration: number;
  timestamp: string;
  config: FrontGuardConfig;
}

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: ScannerCategory;
  cwe?: string;
  owasp?: string;
  remediation: string;
}

export interface FrontGuardConfig {
  include: string[];
  exclude: string[];
  scanners: {
    xss: boolean;
    dependencies: boolean;
    secrets: boolean;
    misconfig: boolean;
    authPatterns: boolean;
  };
  rules: Record<string, RuleLevel>;
  severity: {
    failOn: Severity;
  };
  reporters: string[];
  output: string;
  feed: {
    autoUpdate: boolean;
    ttl: string;
    sources: string[];
    githubToken?: string;
    nvdApiKey?: string;
  };
  ai: {
    enabled: boolean;
    provider: 'openai' | 'anthropic' | 'google' | 'ollama';
    model: string;
    apiKey?: string;
    features: {
      deepScan: boolean;
      autoFix: boolean;
      crossFileFlow: boolean;
      customRules: string[];
    };
    confirmBeforeSend: boolean;
    ollamaBaseUrl: string;
  };
}

export interface FileContent {
  path: string;
  content: string;
  lines: string[];
}

export interface Reporter {
  name: string;
  generate(result: ScanResult): Promise<string | void>;
}
