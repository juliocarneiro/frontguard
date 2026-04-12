import { Command } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { loadConfig } from '../../core/config.js';
import { FeedManager } from '../../feed/feed-manager.js';

export const updateCommand = new Command('update')
  .description('Update the local vulnerability database')
  .option('--verbose', 'Show detailed output')
  .option('--status', 'Show cache status without updating')
  .action(async (options: { verbose?: boolean; status?: boolean }) => {
    const config = await loadConfig();
    const feedManager = new FeedManager(config);

    if (options.status) {
      const status = await feedManager.getStatus();
      console.log(chalk.cyan('\n  Vulnerability Database Status\n'));
      console.log(`  Total CVEs:    ${chalk.white.bold(status.totalEntries)}`);
      console.log(`  Last update:   ${chalk.white(status.lastUpdate ?? 'never')}`);
      console.log(`  Cache TTL:     ${chalk.white(config.feed.ttl)}`);
      console.log(`  Sources:       ${chalk.white(config.feed.sources.join(', '))}`);
      console.log(`  Cache expired: ${status.isExpired ? chalk.yellow('yes') : chalk.green('no')}\n`);
      return;
    }

    const spinner = ora('Updating vulnerability database...').start();

    try {
      const count = await feedManager.update(options.verbose);
      spinner.succeed(`Updated vulnerability database (${count} entries)`);
    } catch (error: any) {
      spinner.fail('Update failed');
      console.error(chalk.red(`\n  Error: ${error.message}\n`));
    }
  });
