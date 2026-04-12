import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { initCommand } from './commands/init.js';
import { reportCommand } from './commands/report.js';
import { updateCommand } from './commands/update.js';
import { authCommand } from './commands/auth.js';

const program = new Command()
  .name('frontguard')
  .description('Open-source frontend security scanner')
  .version('0.1.0');

program.addCommand(scanCommand);
program.addCommand(initCommand);
program.addCommand(reportCommand);
program.addCommand(updateCommand);
program.addCommand(authCommand);

program.parse();
