import { createOpenAI } from '@ai-sdk/openai';
import { generateText } from 'ai';
import { BaseAIProvider } from './base-provider.js';

export class OpenAIProvider extends BaseAIProvider {
  name = 'openai';
  private provider: ReturnType<typeof createOpenAI>;
  private model: string;

  constructor(apiKey: string, model = 'gpt-4o-mini') {
    super();
    this.provider = createOpenAI({ apiKey });
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
