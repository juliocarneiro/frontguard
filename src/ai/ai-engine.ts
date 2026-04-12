import type { FrontGuardConfig, Finding, FileContent } from '../core/types.js';
import type { AIProvider, AIFinding, DataFlowResult } from './types.js';
import { OpenAIProvider } from './providers/openai.js';
import { AnthropicProvider } from './providers/anthropic.js';
import { GoogleProvider } from './providers/google.js';
import { OllamaProvider } from './providers/ollama.js';

export class AIEngine {
  private provider: AIProvider;
  private config: FrontGuardConfig;

  constructor(config: FrontGuardConfig) {
    this.config = config;
    this.provider = this.createProvider();
  }

  private createProvider(): AIProvider {
    const { provider, model, apiKey, ollamaBaseUrl } = this.config.ai;

    switch (provider) {
      case 'openai':
        return new OpenAIProvider(apiKey ?? '', model);
      case 'anthropic':
        return new AnthropicProvider(apiKey ?? '', model);
      case 'google':
        return new GoogleProvider(apiKey ?? '', model);
      case 'ollama':
        return new OllamaProvider(ollamaBaseUrl, model);
    }
  }

  isConfigured(): boolean {
    if (this.config.ai.provider === 'ollama') return true;
    return Boolean(this.config.ai.apiKey);
  }

  async deepScan(findings: Finding[], files: FileContent[]): Promise<AIFinding[]> {
    return this.provider.analyze({ findings, files });
  }

  async generateFixes(
    findings: Finding[],
    files: FileContent[],
  ): Promise<Map<string, string>> {
    const fixes = new Map<string, string>();
    const fileMap = new Map(files.map(f => [f.path, f.content]));

    for (const finding of findings) {
      const content = fileMap.get(finding.file);
      if (!content) continue;

      const fix = await this.provider.generateFix(finding, content);
      fixes.set(finding.ruleId, fix);
    }

    return fixes;
  }

  async analyzeDataFlow(files: FileContent[]): Promise<DataFlowResult[]> {
    return this.provider.analyzeDataFlow(files);
  }

  async evaluateCustomRules(
    rules: string[],
    files: FileContent[],
  ): Promise<AIFinding[]> {
    const allFindings: AIFinding[] = [];

    for (const rule of rules) {
      const findings = await this.provider.evaluateCustomRule(rule, files);
      allFindings.push(...findings);
    }

    return allFindings;
  }
}
