import { Command } from 'commander';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import chalk from 'chalk';
import { createInterface } from 'node:readline';

const CONFIG_DIR = join(homedir(), '.frontguard');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

interface StoredConfig {
  aiProvider?: string;
  aiApiKey?: string;
  aiModel?: string;
  githubToken?: string;
  nvdApiKey?: string;
}

function loadStoredConfig(): StoredConfig {
  if (!existsSync(CONFIG_FILE)) return {};
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8'));
  } catch {
    return {};
  }
}

function saveStoredConfig(config: StoredConfig): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
}

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export const authCommand = new Command('auth')
  .description('Configure AI provider and API keys')
  .option('--provider <name>', 'Set AI provider (openai, anthropic, google, ollama)')
  .option('--key <apiKey>', 'Set API key')
  .option('--model <model>', 'Set AI model')
  .option('--github-token <token>', 'Set GitHub token for advisory feed')
  .option('--nvd-key <key>', 'Set NVD API key')
  .option('--show', 'Show current configuration')
  .action(async (options: Record<string, string | boolean | undefined>) => {
    const stored = loadStoredConfig();

    if (options.show) {
      console.log(chalk.cyan('\n  FrontGuard Authentication Config\n'));
      console.log(`  AI Provider:   ${chalk.white(stored.aiProvider ?? 'not set')}`);
      console.log(`  AI API Key:    ${chalk.white(stored.aiApiKey ? '****' + stored.aiApiKey.slice(-4) : 'not set')}`);
      console.log(`  AI Model:      ${chalk.white(stored.aiModel ?? 'not set')}`);
      console.log(`  GitHub Token:  ${chalk.white(stored.githubToken ? '****' + stored.githubToken.slice(-4) : 'not set')}`);
      console.log(`  NVD API Key:   ${chalk.white(stored.nvdApiKey ? '****' + stored.nvdApiKey.slice(-4) : 'not set')}\n`);
      return;
    }

    if (options.provider || options.key || options.model || options.githubToken || options.nvdKey) {
      if (options.provider) stored.aiProvider = options.provider as string;
      if (options.key) stored.aiApiKey = options.key as string;
      if (options.model) stored.aiModel = options.model as string;
      if (options.githubToken) stored.githubToken = options.githubToken as string;
      if (options.nvdKey) stored.nvdApiKey = options.nvdKey as string;
      saveStoredConfig(stored);
      console.log(chalk.green('\n  ✓ Configuration saved\n'));
      return;
    }

    console.log(chalk.cyan('\n  FrontGuard Authentication Setup\n'));

    const provider = await prompt('  AI Provider (openai/anthropic/google/ollama): ');
    if (provider) stored.aiProvider = provider;

    if (provider !== 'ollama') {
      const key = await prompt('  API Key: ');
      if (key) stored.aiApiKey = key;
    }

    const model = await prompt('  Model (leave blank for default): ');
    if (model) stored.aiModel = model;

    saveStoredConfig(stored);
    console.log(chalk.green(`\n  ✓ Configuration saved to ${CONFIG_FILE}\n`));
  });
