import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { Command, InvalidArgumentError, Option } from 'commander';
import yoctoSpinner from 'yocto-spinner';
import { findConfigFile, loadConfig } from '../config/load.ts';
import {
  CATEGORIES,
  ConfigError,
  REPORTERS,
  SEVERITIES,
  type ReporterName,
  type ResolvedConfig,
} from '../config/schema.ts';
import { scan } from '../core/scan.ts';
import { meetsThreshold } from '../core/severity.ts';
import { DEPENDENCY_RULE } from '../dependencies/audit.ts';
import { toConsole, writeReports } from '../reporters/index.ts';
import { builtinRules } from '../rules/index.ts';
import type { ScanResult } from '../types.ts';
import { PACKAGE_NAME, VERSION } from '../version.ts';
import { runInit, terminalInitIO, type InitIO, type PackageManager } from './init.ts';

export const EXIT = { ok: 0, findings: 1, error: 2 } as const;

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd: string;
  color: boolean;
  interactive: boolean;
  /** Prompt/exec hooks for `init`; defaults to the terminal. */
  init?: InitIO;
}

interface InitFlags {
  yes?: boolean;
  json?: boolean;
  ts?: boolean;
  pm?: PackageManager;
  install: boolean;
  script: boolean;
  ci: boolean;
  force?: boolean;
}

function defaultIO(): CliIO {
  const colorEnv = process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0';
  return {
    stdout: (text) => process.stdout.write(`${text}\n`),
    stderr: (text) => process.stderr.write(`${text}\n`),
    cwd: process.cwd(),
    color: colorEnv || (process.stdout.isTTY && !process.env.NO_COLOR),
    interactive: process.stderr.isTTY && !process.env.CI,
  };
}

function list<T extends string>(allowed: readonly T[], label: string) {
  return (value: string): T[] => {
    const items = value
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const invalid = items.filter((item) => !allowed.includes(item as T));
    if (invalid.length > 0) {
      throw new InvalidArgumentError(
        `Unknown ${label}: ${invalid.join(', ')}. Expected: ${allowed.join(', ')}.`,
      );
    }
    return items as T[];
  };
}

function openFile(path: string): void {
  const [cmd, args] =
    process.platform === 'win32'
      ? ['explorer.exe', [path]]
      : process.platform === 'darwin'
        ? ['open', [path]]
        : ['xdg-open', [path]];
  spawn(cmd, args, { stdio: 'ignore', detached: true })
    .on('error', () => undefined)
    .unref();
}

interface ScanFlags {
  config?: string;
  reporter?: ReporterName[];
  outputDir?: string;
  failOn?: ResolvedConfig['failOn'];
  categories?: (typeof CATEGORIES)[number][];
  includeDev?: boolean;
  offline?: boolean;
  quiet?: boolean;
  open?: boolean;
  color: boolean;
}

function hasFailures(result: ScanResult, failOn: ResolvedConfig['failOn']): boolean {
  return result.findings.some((f) => f.level === 'error' && meetsThreshold(f.severity, failOn));
}

async function runScan(target: string, flags: ScanFlags, io: CliIO): Promise<number> {
  const root = resolve(io.cwd, target);
  if (!existsSync(root)) throw new ConfigError(`Target directory not found: ${root}`);

  const configDir = findConfigFile(root) ? root : io.cwd;
  const { config, file } = await loadConfig(configDir, flags.config);

  if (flags.reporter) config.reporters = flags.reporter;
  if (flags.open && !config.reporters.includes('html')) config.reporters.push('html');
  if (flags.failOn) config.failOn = flags.failOn;
  if (flags.includeDev) config.dependencies.includeDev = true;
  if (flags.offline) config.dependencies.offline = true;
  if (flags.categories) {
    for (const category of CATEGORIES)
      config.categories[category] = flags.categories.includes(category);
  }

  const color = io.color && flags.color;
  const spinner = io.interactive
    ? yoctoSpinner({ text: 'Scanning…', stream: process.stderr }).start()
    : undefined;

  let result: ScanResult;
  try {
    result = await scan({ cwd: root, config });
  } finally {
    spinner?.stop();
  }

  if (file && !flags.quiet) io.stderr(`Using config ${relative(io.cwd, file) || file}`);
  if (config.reporters.includes('console')) {
    io.stdout(toConsole(result, { color, compact: flags.quiet ?? false }));
  }

  const outputDir = flags.outputDir
    ? resolve(io.cwd, flags.outputDir)
    : resolve(root, config.outputDir);
  const written = await writeReports(result, config.reporters, outputDir);
  for (const path of Object.values(written))
    io.stderr(`Report written to ${relative(io.cwd, path) || path}`);
  if (flags.open && written.html) openFile(written.html);

  return hasFailures(result, config.failOn) ? EXIT.findings : EXIT.ok;
}

function createProgram(io: CliIO, setExitCode: (code: number) => void): Command {
  const program = new Command('frontguard')
    .description('Static security scanner for frontend code.')
    .version(VERSION, '-v, --version')
    .showHelpAfterError()
    .configureOutput({
      writeOut: (text) => {
        io.stdout(text.trimEnd());
      },
      writeErr: (text) => {
        io.stderr(text.trimEnd());
      },
    })
    .exitOverride();

  program
    .command('scan', { isDefault: true })
    .description('scan a directory (default command)')
    .argument('[target]', 'directory to scan', '.')
    .option('-c, --config <path>', 'path to a config file')
    .option(
      '-r, --reporter <list>',
      `comma-separated reporters: ${REPORTERS.join(', ')}`,
      list(REPORTERS, 'reporter'),
    )
    .option('-o, --output-dir <dir>', 'directory for json/sarif/html reports')
    .addOption(
      new Option('--fail-on <severity>', 'lowest severity that fails the scan').choices([
        ...SEVERITIES,
        'none',
      ]),
    )
    .option(
      '--categories <list>',
      `only run these categories: ${CATEGORIES.join(', ')}`,
      list(CATEGORIES, 'category'),
    )
    .option('--include-dev', 'also audit devDependencies')
    .option('--offline', 'skip the OSV.dev dependency lookup')
    .option('-q, --quiet', 'print only warnings and the summary')
    .option('--open', 'write the HTML report and open it')
    .option('--no-color', 'disable colored output')
    .action(async (target: string, flags: ScanFlags) => {
      setExitCode(await runScan(target, flags, io));
    });

  program
    .command('init')
    .description('set up frontguard in this project (install, config, script, CI)')
    .option('-y, --yes', 'accept all defaults without prompting')
    .option('--json', 'write .frontguardrc.json instead of frontguard.config.ts')
    .option('--ts', 'write frontguard.config.ts')
    .addOption(
      new Option('--pm <name>', 'package manager to use').choices(['npm', 'pnpm', 'yarn', 'bun']),
    )
    .option('--no-install', 'do not install frontguard')
    .option('--no-script', 'do not add a package.json script')
    .option('--no-ci', 'do not create a GitHub Actions workflow')
    .option('-f, --force', 'overwrite existing files')
    .action(async (flags: InitFlags) => {
      const initIO = io.init ?? terminalInitIO(io.stdout, io.stderr);
      const format = flags.json ? 'json' : flags.ts ? 'ts' : undefined;
      const code = await runInit(
        {
          cwd: io.cwd,
          yes: flags.yes ?? !io.interactive,
          install: flags.install,
          script: flags.script,
          ci: flags.ci,
          force: flags.force ?? false,
          ...(format && { format }),
          ...(flags.pm && { pm: flags.pm }),
        },
        initIO,
      );
      setExitCode(code);
    });

  program
    .command('rules')
    .description('list available rules')
    .option('--json', 'print rules as JSON')
    .action((flags: { json?: boolean }) => {
      const metas = [...builtinRules.map((rule) => rule.meta), DEPENDENCY_RULE];
      if (flags.json) {
        io.stdout(JSON.stringify(metas, null, 2));
        return;
      }
      for (const meta of metas) {
        io.stdout(
          `${meta.id.padEnd(12)} ${meta.severity.padEnd(9)} ${meta.name.padEnd(32)} ${meta.title}`,
        );
      }
    });

  program
    .command('report')
    .description('open a previously generated HTML report')
    .argument('[dir]', 'report directory', 'frontguard-report')
    .action((dir: string) => {
      const path = resolve(io.cwd, dir, 'frontguard-report.html');
      if (!existsSync(path)) {
        io.stderr(`No report at ${path}. Run "npx ${PACKAGE_NAME} --reporter html" first.`);
        setExitCode(EXIT.error);
        return;
      }
      openFile(path);
    });

  return program;
}

/** Runs the CLI and resolves with the process exit code. Never calls `process.exit`. */
export async function run(argv: string[], io: CliIO = defaultIO()): Promise<number> {
  let exitCode: number = EXIT.ok;
  const program = createProgram(io, (code) => {
    exitCode = code;
  });
  try {
    await program.parseAsync(argv, { from: 'user' });
    return exitCode;
  } catch (error) {
    if (error instanceof Error && 'exitCode' in error && 'code' in error) {
      // Commander already printed help/version/usage errors.
      const code = (error as { code: string }).code;
      return code === 'commander.helpDisplayed' || code === 'commander.version'
        ? EXIT.ok
        : EXIT.error;
    }
    io.stderr(
      error instanceof ConfigError
        ? error.message
        : `Error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
    );
    return EXIT.error;
  }
}
