import { Command } from 'commander';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { exec } from 'node:child_process';
import chalk from 'chalk';

export const reportCommand = new Command('report')
  .description('Open the HTML report in your browser')
  .argument('[path]', 'Path to the report directory', './frontguard-report')
  .action((reportPath: string) => {
    const htmlPath = resolve(reportPath, 'frontguard-report.html');

    if (!existsSync(htmlPath)) {
      console.log(chalk.red(`\n  ✗ Report not found: ${htmlPath}`));
      console.log(chalk.dim('  Run "frontguard scan --reporter html" first.\n'));
      return;
    }

    console.log(chalk.cyan(`\n  Opening report: ${htmlPath}\n`));

    const platform = process.platform;
    const cmd = platform === 'win32' ? 'start' : platform === 'darwin' ? 'open' : 'xdg-open';
    exec(`${cmd} "${htmlPath}"`);
  });
