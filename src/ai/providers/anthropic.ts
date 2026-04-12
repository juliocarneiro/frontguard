import { createAnthropic } from '@ai-sdk/anthropic';
import { generateText } from 'ai';
import { BaseAIProvider } from './base-provider.js';

export class AnthropicProvider extends BaseAIProvider {
  name = 'anthropic';
  private provider: ReturnType<typeof createAnthropic>;
  private model: string;

  constructor(apiKey: string, model = 'claude-sonnet-4-20250514') {
    super();
    this.provider = createAnthropic({ apiKey });
    this.model = model;
  }

  protected async chat(systemPrompt: string, userPrompt: string): Promise<string> {
    const { text } = await generateText({
      model: this.provider(this.model),
      system: systemPrompt,
      prompt: userPrompt,
    });
    return text;
  }
}
