import type { Finding, FileContent } from '../../core/types.js';
import type { AIProvider, AIFinding, AIAnalysisContext, DataFlowResult } from '../types.js';
import { buildDeepScanSystemPrompt, buildDeepScanUserPrompt } from '../prompts/deep-scan.js';
import { buildRemediationSystemPrompt, buildRemediationUserPrompt } from '../prompts/remediation.js';
import { buildCrossFileSystemPrompt, buildCrossFileUserPrompt } from '../prompts/cross-file.js';
import { buildCustomRuleSystemPrompt, buildCustomRuleUserPrompt } from '../prompts/custom-rule.js';

function extractJSON(raw: string): string {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1].trim();
  const bracketStart = raw.indexOf('[');
  const bracketEnd = raw.lastIndexOf(']');
  if (bracketStart !== -1 && bracketEnd !== -1) {
    return raw.slice(bracketStart, bracketEnd + 1);
  }
  return raw.trim();
}

export abstract class BaseAIProvider implements AIProvider {
  abstract name: string;
  protected abstract chat(systemPrompt: string, userPrompt: string): Promise<string>;

  async analyze(context: AIAnalysisContext): Promise<AIFinding[]> {
    const codeSnippets = context.files.map(
      f => `// ${f.path}\n${f.content}`,
    );

    const systemPrompt = buildDeepScanSystemPrompt();
    const userPrompt = buildDeepScanUserPrompt(context.findings, codeSnippets);
    const response = await this.chat(systemPrompt, userPrompt);

    try {
      const parsed = JSON.parse(extractJSON(response));
      return (parsed as AIFinding[]).map(f => ({ ...f, aiAnalyzed: true as const }));
    } catch {
      return context.findings.map(f => ({
        ...f,
        aiConfidence: 0.5,
        aiAnalyzed: true as const,
      }));
    }
  }

  async generateFix(finding: Finding, fileContent: string): Promise<string> {
    const systemPrompt = buildRemediationSystemPrompt();
    const userPrompt = buildRemediationUserPrompt(finding, fileContent);
    return this.chat(systemPrompt, userPrompt);
  }

  async analyzeDataFlow(files: FileContent[]): Promise<DataFlowResult[]> {
    const systemPrompt = buildCrossFileSystemPrompt();
    const userPrompt = buildCrossFileUserPrompt(files);
    const response = await this.chat(systemPrompt, userPrompt);

    try {
      return JSON.parse(extractJSON(response)) as DataFlowResult[];
    } catch {
      return [];
    }
  }

  async evaluateCustomRule(rule: string, files: FileContent[]): Promise<AIFinding[]> {
    const systemPrompt = buildCustomRuleSystemPrompt();
    const userPrompt = buildCustomRuleUserPrompt(rule, files);
    const response = await this.chat(systemPrompt, userPrompt);

    try {
      const parsed = JSON.parse(extractJSON(response));
      return (parsed as AIFinding[]).map(f => ({ ...f, aiAnalyzed: true as const }));
    } catch {
      return [];
    }
  }
}
