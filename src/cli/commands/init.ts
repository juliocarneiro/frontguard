import { Command } from 'commander';
import { writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import chalk from 'chalk';
import { generateConfigTemplate } from '../../core/config.js';

export const initCommand = new Command('init')
  .description('Generate a frontguard.config.ts configuration file')
  .option('-f, --force', 'Overwrite existing config file')
  .action((options: { force?: boolean }) => {
    const configPath = resolve(process.cwd(), 'frontguard.config.ts');

    if (existsSync(configPath) && !options.force) {
      console.log(chalk.yellow(`\n  ⚠ Config file already exists: ${configPath}`));
      console.log(chalk.dim('  Use --force to overwrite\n'));
      return;
    }

    writeFileSync(configPath, generateConfigTemplate(), 'utf-8');
    console.log(chalk.green(`\n  ✓ Created ${configPath}\n`));
    console.log(chalk.dim('  Edit this file to customize your scan settings.\n'));
  });
