import { createOllama } from 'ollama-ai-provider';
import { generateText } from 'ai';
import { BaseAIProvider } from './base-provider.js';

export class OllamaProvider extends BaseAIProvider {
  name = 'ollama';
  private provider: ReturnType<typeof createOllama>;
  private model: string;

  constructor(baseUrl = 'http://localhost:11434', model = 'llama3') {
    super();
    this.provider = createOllama({ baseURL: `${baseUrl}/api` });
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
