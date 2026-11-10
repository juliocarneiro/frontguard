import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { PACKAGE_NAME } from '../version.ts';
import { configTemplate, workflowTemplate } from './templates.ts';

export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun';

export interface InitOptions {
  cwd: string;
  /** Accept every default without prompting. */
  yes: boolean;
  install: boolean;
  ci: boolean;
  script: boolean;
  format?: 'ts' | 'json';
  force: boolean;
  pm?: PackageManager;
}

export interface InitIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** Asks a yes/no question; resolves with the default when not interactive. */
  confirm: (question: string, defaultValue: boolean) => Promise<boolean>;
  /** Runs a command; resolves with its exit code. */
  exec: (command: string, args: string[], cwd: string) => Promise<number>;
}

const LOCKFILES: [string, PackageManager][] = [
  ['pnpm-lock.yaml', 'pnpm'],
  ['bun.lock', 'bun'],
  ['bun.lockb', 'bun'],
  ['yarn.lock', 'yarn'],
  ['package-lock.json', 'npm'],
];

function detectPackageManager(cwd: string, userAgent = process.env.npm_config_user_agent) {
  for (const [file, pm] of LOCKFILES) if (existsSync(join(cwd, file))) return pm;
  try {
    const pkg = JSON.parse(readFileSync(join(cwd, 'package.json'), 'utf8')) as {
      packageManager?: string;
    };
    const name = pkg.packageManager?.split('@')[0];
    if (name === 'pnpm' || name === 'yarn' || name === 'bun' || name === 'npm') return name;
  } catch {
    // no package.json or invalid JSON: fall through
  }
  const fromAgent = userAgent?.split('/')[0];
  if (fromAgent === 'pnpm' || fromAgent === 'yarn' || fromAgent === 'bun') return fromAgent;
  return 'npm';
}

function installCommand(pm: PackageManager): [string, string[]] {
  switch (pm) {
    case 'npm':
      return ['npm', ['install', '--save-dev', PACKAGE_NAME]];
    case 'pnpm':
      return ['pnpm', ['add', '--save-dev', PACKAGE_NAME]];
    case 'yarn':
      return ['yarn', ['add', '--dev', PACKAGE_NAME]];
    case 'bun':
      return ['bun', ['add', '--dev', PACKAGE_NAME]];
  }
}

function runCommand(pm: PackageManager, script: string): string {
  return pm === 'npm' ? `npm run ${script}` : `${pm} ${script}`;
}

/** Keeps the file's existing indentation when rewriting package.json. */
function detectIndent(text: string): string {
  return /^(\s+)"/m.exec(text)?.[1] ?? '  ';
}

async function writeIfAllowed(path: string, content: string, force: boolean): Promise<boolean> {
  if (existsSync(path) && !force) return false;
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, 'utf8');
  return true;
}

/** Interactive project setup. Every step is idempotent and can be skipped. */
export async function runInit(options: InitOptions, io: InitIO): Promise<number> {
  const { cwd } = options;
  const pkgPath = join(cwd, 'package.json');
  const hasPackageJson = existsSync(pkgPath);
  const pm = options.pm ?? detectPackageManager(cwd);
  const ask = (question: string, def: boolean) =>
    options.yes ? Promise.resolve(def) : io.confirm(question, def);
  const done: string[] = [];

  io.stdout('FrontGuard setup\n');

  // 1. Install locally so the config can import `frontguard` and CI uses a pinned version.
  let installed = false;
  if (options.install && hasPackageJson && (await ask(`Install frontguard with ${pm}?`, true))) {
    const [command, args] = installCommand(pm);
    io.stdout(`$ ${command} ${args.join(' ')}`);
    const code = await io.exec(command, args, cwd);
    if (code !== 0) {
      io.stderr(`Install failed (exit ${code}). You can run it yourself later.`);
    } else {
      installed = true;
      done.push('installed frontguard as a devDependency');
    }
  }

  // 2. Config file. A .ts config needs the package installed locally to resolve its import.
  const format = options.format ?? (installed ? 'ts' : 'json');
  const configName = format === 'ts' ? 'frontguard.config.ts' : '.frontguardrc.json';
  if (await writeIfAllowed(join(cwd, configName), configTemplate(format), options.force)) {
    done.push(`created ${configName}`);
  } else {
    io.stdout(`${configName} already exists, keeping it (use --force to overwrite).`);
  }

  // 3. package.json script.
  const scriptName = 'security';
  if (options.script && hasPackageJson) {
    const raw = await readFile(pkgPath, 'utf8');
    const pkg = JSON.parse(raw) as { scripts?: Record<string, string> };
    if (pkg.scripts?.[scriptName]) {
      io.stdout(`package.json already has a "${scriptName}" script, keeping it.`);
    } else if (await ask(`Add a "${scriptName}" script to package.json?`, true)) {
      pkg.scripts = {
        ...pkg.scripts,
        [scriptName]: installed ? 'frontguard' : `npx ${PACKAGE_NAME}`,
      };
      await writeFile(pkgPath, `${JSON.stringify(pkg, null, detectIndent(raw))}\n`, 'utf8');
      done.push(`added the "${scriptName}" script`);
    }
  }

  // 4. GitHub Actions workflow uploading SARIF to code scanning.
  const isGitHub = existsSync(join(cwd, '.git')) || existsSync(join(cwd, '.github'));
  if (
    options.ci &&
    (await ask('Add a GitHub Actions workflow (results in the Security tab)?', isGitHub))
  ) {
    const workflow = join(cwd, '.github', 'workflows', 'frontguard.yml');
    if (await writeIfAllowed(workflow, workflowTemplate(pm, installed), options.force)) {
      done.push('created .github/workflows/frontguard.yml');
    } else {
      io.stdout('.github/workflows/frontguard.yml already exists, keeping it.');
    }
  }

  // 5. Keep generated reports out of git.
  const gitignore = join(cwd, '.gitignore');
  const ignoreLine = 'frontguard-report/';
  const current = existsSync(gitignore) ? await readFile(gitignore, 'utf8') : '';
  if (!current.split(/\r?\n/).includes(ignoreLine) && (existsSync(gitignore) || isGitHub)) {
    const prefix = current && !current.endsWith('\n') ? '\n' : '';
    await writeFile(gitignore, `${current}${prefix}${ignoreLine}\n`, 'utf8');
    done.push('ignored frontguard-report/ in .gitignore');
  }

  io.stdout('');
  for (const item of done) io.stdout(`✔ ${item}`);
  const run = hasPackageJson && options.script ? runCommand(pm, scriptName) : `npx ${PACKAGE_NAME}`;
  io.stdout(`\nNext: run \`${run}\` to scan your project.`);
  return 0;
}

export function terminalInitIO(stdout: InitIO['stdout'], stderr: InitIO['stderr']): InitIO {
  return {
    stdout,
    stderr,
    async confirm(question, defaultValue) {
      if (!process.stdin.isTTY) return defaultValue;
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      try {
        const answer = (await rl.question(`${question} ${defaultValue ? '(Y/n)' : '(y/N)'} `))
          .trim()
          .toLowerCase();
        return answer === '' ? defaultValue : answer === 'y' || answer === 'yes';
      } finally {
        rl.close();
      }
    },
    exec(command, args, cwd) {
      return new Promise((resolve) => {
        // Package managers are .cmd shims on Windows, which need a shell; arguments are constants.
        const child = spawn(command, args, {
          cwd,
          stdio: 'inherit',
          shell: process.platform === 'win32',
        });
        child.on('error', () => {
          resolve(127);
        });
        child.on('close', (code) => {
          resolve(code ?? 1);
        });
      });
    },
  };
}
