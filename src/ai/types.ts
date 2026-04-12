import type { Finding, FileContent, Severity } from '../core/types.js';

export interface AIFinding extends Finding {
  aiConfidence: number;
  aiAnalyzed: true;
}

export interface DataFlowResult {
  source: { file: string; line: number; description: string };
  sinks: { file: string; line: number; description: string }[];
  path: string[];
  risk: Severity;
}

export interface AIAnalysisContext {
  findings: Finding[];
  files: FileContent[];
  customRule?: string;
}

export interface AIProvider {
  name: string;
  analyze(context: AIAnalysisContext): Promise<AIFinding[]>;
  generateFix(finding: Finding, fileContent: string): Promise<string>;
  analyzeDataFlow(files: FileContent[]): Promise<DataFlowResult[]>;
  evaluateCustomRule(rule: string, files: FileContent[]): Promise<AIFinding[]>;
}
