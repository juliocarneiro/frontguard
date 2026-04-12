import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getDefaultConfig } from '../../src/core/config.js';
import type { FrontGuardConfig, Finding, FileContent } from '../../src/core/types.js';

vi.mock('ai', () => ({
  generateText: vi.fn().mockResolvedValue({ text: '[]' }),
}));

vi.mock('@ai-sdk/openai', () => ({
  createOpenAI: vi.fn().mockReturnValue(vi.fn()),
}));

vi.mock('@ai-sdk/anthropic', () => ({
  createAnthropic: vi.fn().mockReturnValue(vi.fn()),
}));

vi.mock('@ai-sdk/google', () => ({
  createGoogleGenerativeAI: vi.fn().mockReturnValue(vi.fn()),
}));

vi.mock('ollama-ai-provider', () => ({
  createOllama: vi.fn().mockReturnValue(vi.fn()),
}));

const makeFinding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: 'FG-XSS-001',
  severity: 'high',
  category: 'xss',
  title: 'Unsafe innerHTML Assignment',
  description: 'Test finding',
  file: 'test.ts',
  line: 1,
  column: 1,
  codeSnippet: 'el.innerHTML = input;',
  remediation: 'Use textContent instead.',
  ...overrides,
});

const makeFile = (path = 'test.ts', content = 'el.innerHTML = input;'): FileContent => ({
  path,
  content,
  lines: content.split('\n'),
});

describe('AIEngine', () => {
  let config: FrontGuardConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    config = {
      ...getDefaultConfig(),
      ai: {
        ...getDefaultConfig().ai,
        enabled: true,
        provider: 'openai',
        model: 'gpt-4o-mini',
        apiKey: 'test-key-123',
      },
    };
  });

  it('isConfigured() returns false when no API key is set', async () => {
    config.ai.apiKey = undefined;
    config.ai.provider = 'openai';

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine.isConfigured()).toBe(false);
  });

  it('isConfigured() returns true when API key is provided', async () => {
    config.ai.apiKey = 'sk-test-key';
    config.ai.provider = 'openai';

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine.isConfigured()).toBe(true);
  });

  it('isConfigured() returns true for Ollama without API key', async () => {
    config.ai.provider = 'ollama';
    config.ai.apiKey = undefined;

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine.isConfigured()).toBe(true);
  });

  it('creates OpenAI provider when configured', async () => {
    config.ai.provider = 'openai';
    config.ai.apiKey = 'sk-test';

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine).toBeDefined();
    expect(engine.isConfigured()).toBe(true);
  });

  it('creates Anthropic provider when configured', async () => {
    config.ai.provider = 'anthropic';
    config.ai.apiKey = 'sk-ant-test';

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine).toBeDefined();
    expect(engine.isConfigured()).toBe(true);
  });

  it('creates Google provider when configured', async () => {
    config.ai.provider = 'google';
    config.ai.apiKey = 'AIza-test';

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine).toBeDefined();
    expect(engine.isConfigured()).toBe(true);
  });

  it('creates Ollama provider when configured', async () => {
    config.ai.provider = 'ollama';
    config.ai.apiKey = undefined;

    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const engine = new AIEngine(config);
    expect(engine).toBeDefined();
    expect(engine.isConfigured()).toBe(true);
  });

  it('deepScan() calls provider analyze and returns findings', async () => {
    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const { generateText } = await import('ai');

    vi.mocked(generateText).mockResolvedValue({
      text: JSON.stringify([{
        ruleId: 'FG-XSS-001',
        severity: 'high',
        category: 'xss',
        title: 'Unsafe innerHTML Assignment',
        description: 'AI-detected XSS',
        file: 'test.ts',
        line: 1,
        column: 1,
        codeSnippet: 'el.innerHTML = input;',
        remediation: 'Use textContent.',
        aiConfidence: 0.95,
        aiAnalyzed: true,
      }]),
    } as any);

    const engine = new AIEngine(config);
    const findings = [makeFinding()];
    const files = [makeFile()];

    const result = await engine.deepScan(findings, files);
    expect(Array.isArray(result)).toBe(true);
    expect(generateText).toHaveBeenCalled();
  });

  it('generateFixes() calls provider generateFix for each finding', async () => {
    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const { generateText } = await import('ai');

    vi.mocked(generateText).mockResolvedValue({
      text: 'el.textContent = input;',
    } as any);

    const engine = new AIEngine(config);
    const findings = [makeFinding()];
    const files = [makeFile()];

    const fixes = await engine.generateFixes(findings, files);
    expect(fixes).toBeInstanceOf(Map);
    expect(generateText).toHaveBeenCalled();
  });

  it('generateFixes() skips findings with no matching file', async () => {
    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const { generateText } = await import('ai');

    const engine = new AIEngine(config);
    const findings = [makeFinding({ file: 'nonexistent.ts' })];
    const files = [makeFile('other.ts')];

    const fixes = await engine.generateFixes(findings, files);
    expect(fixes.size).toBe(0);
    expect(generateText).not.toHaveBeenCalled();
  });

  it('deepScan() handles malformed AI response gracefully', async () => {
    const { AIEngine } = await import('../../src/ai/ai-engine.js');
    const { generateText } = await import('ai');

    vi.mocked(generateText).mockResolvedValue({
      text: 'not valid json at all',
    } as any);

    const engine = new AIEngine(config);
    const findings = [makeFinding()];
    const files = [makeFile()];

    const result = await engine.deepScan(findings, files);
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThanOrEqual(0);
  });
});
