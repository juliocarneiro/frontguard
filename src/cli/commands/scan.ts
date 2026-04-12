import { Command } from 'commander';
import ora from 'ora';
import chalk from 'chalk';
import { resolve, join } from 'node:path';
import { execSync } from 'node:child_process';
import { loadConfig } from '../../core/config.js';
import { ScanEngine } from '../../core/engine.js';
import { printBanner, printFinding, printSummary } from '../ui.js';
import { XSSScanner } from '../../scanners/xss/index.js';
import { SecretsScanner } from '../../scanners/secrets/index.js';
import { DependencyScanner } from '../../scanners/dependencies/index.js';
import { AuthPatternsScanner } from '../../scanners/auth-patterns/index.js';
import { MisconfigScanner } from '../../scanners/misconfig/index.js';
import { ConsoleReporter } from '../../reporters/console-reporter.js';
import { JsonReporter } from '../../reporters/json-reporter.js';
import { HtmlReporter } from '../../reporters/html-reporter.js';
import { SarifReporter } from '../../reporters/sarif-reporter.js';

function openInBrowser(filePath: string): void {
  try {
    if (process.platform === 'win32') {
      execSync(`start "" "${filePath}"`, { stdio: 'ignore', shell: 'cmd.exe' });
    } else if (process.platform === 'darwin') {
      execSync(`open "${filePath}"`, { stdio: 'ignore' });
    } else {
      execSync(`xdg-open "${filePath}"`, { stdio: 'ignore' });
    }
  } catch {
    // silently fail if browser can't open
  }
}

export const scanCommand = new Command('scan')
  .description('Scan frontend code for security vulnerabilities')
  .argument('[target]', 'Target directory to scan', '.')
  .option('-c, --config <path>', 'Path to config file')
  .option('-s, --scanners <list>', 'Comma-separated list of scanners to run')
  .option('-r, --report', 'Generate HTML report and open in browser')
  .option('--reporter <type>', 'Reporter type for CI (json, sarif)')
  .option('-o, --output <path>', 'Output directory for reports')
  .option('--fail-on <severity>', 'Exit with error if findings meet severity threshold')
  .option('--ai-deep', 'Enable AI deep scan analysis')
  .option('--ai-fix', 'Generate AI-powered fix suggestions')
  .option('--ai-flow', 'Enable AI cross-file data flow analysis')
  .option('--ai-rule <rule>', 'Custom rule described in natural language')
  .option('--ai-provider <provider>', 'AI provider (openai, anthropic, google, ollama)')
  .option('--ai-model <model>', 'AI model to use')
  .option('--ai-no-confirm', 'Skip confirmation before sending code to AI')
  .action(async (target: string, options: Record<string, string | boolean | undefined>) => {
    printBanner();

    const config = await loadConfig(options.config as string | undefined);
    const targetPath = resolve(target);

    const outputDir = options.output
      ? resolve(options.output as string)
      : join(targetPath, 'frontguard-report');
    config.output = outputDir;

    if (options.scanners) {
      const enabled = (options.scanners as string).split(',');
      config.scanners.xss = enabled.includes('xss');
      config.scanners.dependencies = enabled.includes('dependencies');
      config.scanners.secrets = enabled.includes('secrets');
      config.scanners.misconfig = enabled.includes('misconfig');
      config.scanners.authPatterns = enabled.includes('auth-patterns');
    }

    if (options.failOn) {
      config.severity.failOn = options.failOn as any;
    }

    if (options.aiDeep || options.aiFix || options.aiFlow || options.aiRule) {
      config.ai.enabled = true;
      if (options.aiDeep) config.ai.features.deepScan = true;
      if (options.aiFix) config.ai.features.autoFix = true;
      if (options.aiFlow) config.ai.features.crossFileFlow = true;
      if (options.aiRule) config.ai.features.customRules = [options.aiRule as string];
      if (options.aiProvider) config.ai.provider = options.aiProvider as any;
      if (options.aiModel) config.ai.model = options.aiModel as string;
      if (options.aiNoConfirm) config.ai.confirmBeforeSend = false;
    }

    const engine = new ScanEngine();

    engine.registerScanner(new XSSScanner());
    engine.registerScanner(new SecretsScanner());
    engine.registerScanner(new DependencyScanner());
    engine.registerScanner(new AuthPatternsScanner());
    engine.registerScanner(new MisconfigScanner());

    const wantsReport = !!options.report;
    const ciReporter = options.reporter as string | undefined;

    engine.registerReporter(new ConsoleReporter());

    if (wantsReport) {
      engine.registerReporter(new HtmlReporter(outputDir));
    }

    if (ciReporter) {
      switch (ciReporter) {
        case 'json': engine.registerReporter(new JsonReporter(outputDir)); break;
        case 'html': engine.registerReporter(new HtmlReporter(outputDir)); break;
        case 'sarif': engine.registerReporter(new SarifReporter(outputDir)); break;
      }
    }

    const spinner = ora({
      text: chalk.dim('Scanning for vulnerabilities...'),
      color: 'cyan',
    }).start();

    try {
      const result = await engine.scan(targetPath, config);
      spinner.succeed(chalk.dim(`Scanned ${result.scannedFiles} files in ${result.scanDuration}ms`));

      for (let i = 0; i < result.findings.length; i++) {
        printFinding(result.findings[i], i);
      }
      printSummary(result);

      if (wantsReport) {
        const htmlPath = join(outputDir, 'frontguard-report.html');
        console.log(chalk.hex('#38bdf8')(`  Report saved: ${htmlPath}`));
        console.log(chalk.dim('  Opening in browser...\n'));
        openInBrowser(htmlPath);
      }

      if (engine.hasFailures(result)) {
        console.log(chalk.red.bold(`  ✗ Found vulnerabilities at or above "${config.severity.failOn}" severity\n`));
        process.exit(1);
      }
    } catch (error: any) {
      spinner.fail(chalk.red('Scan failed'));
      console.error(chalk.red(`\n  Error: ${error.message}\n`));
      process.exit(2);
    }
  });
