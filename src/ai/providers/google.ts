import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { generateText } from 'ai';
import { BaseAIProvider } from './base-provider.js';

export class GoogleProvider extends BaseAIProvider {
  name = 'google';
  private provider: ReturnType<typeof createGoogleGenerativeAI>;
  private model: string;

  constructor(apiKey: string, model = 'gemini-2.0-flash') {
    super();
    this.provider = createGoogleGenerativeAI({ apiKey });
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
