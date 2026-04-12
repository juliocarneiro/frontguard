import chalk from 'chalk';
import type { Finding, ScanResult, Severity } from '../core/types.js';

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '●',
  high: '●',
  medium: '●',
  low: '●',
  info: '○',
};

const SEVERITY_LABEL: Record<Severity, (text: string) => string> = {
  critical: (t: string) => chalk.bgRed.white.bold(` ${t} `),
  high: (t: string) => chalk.bgHex('#dc2626').white.bold(` ${t} `),
  medium: (t: string) => chalk.bgHex('#d97706').white.bold(` ${t} `),
  low: (t: string) => chalk.bgHex('#2563eb').white(` ${t} `),
  info: (t: string) => chalk.bgHex('#4b5563').white(` ${t} `),
};

const SEV_COLOR: Record<Severity, (t: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.redBright,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const DIM = chalk.dim;
const BOLD = chalk.white.bold;
const ACCENT = chalk.hex('#38bdf8');
const BORDER = chalk.hex('#334155');

const LINE_H = BORDER('─');
const BOX_W = 56;

function hline(char = '─'): string {
  return BORDER(char.repeat(BOX_W));
}

function pad(text: string, width: number): string {
  const stripped = text.replace(/\x1b\[[0-9;]*m/g, '');
  const diff = width - stripped.length;
  return diff > 0 ? text + ' '.repeat(diff) : text;
}

export function printBanner(): void {
  const t = BORDER;
  const a = ACCENT;
  console.log('');
  console.log(`  ${t('┌')}${hline()}${t('┐')}`);
  console.log(`  ${t('│')}${pad('', BOX_W)}${t('│')}`);
  console.log(`  ${t('│')}${pad(`    ${a('FrontGuard')}  ${DIM('Security Scanner')}`, BOX_W)}${t('│')}`);
  console.log(`  ${t('│')}${pad(`    ${DIM('Catch vulnerabilities before they ship')}`, BOX_W)}${t('│')}`);
  console.log(`  ${t('│')}${pad('', BOX_W)}${t('│')}`);
  console.log(`  ${t('└')}${hline()}${t('┘')}`);
  console.log('');
}

export function printFinding(finding: Finding, index: number): void {
  const badge = SEVERITY_LABEL[finding.severity](finding.severity.toUpperCase());
  const rule = DIM(`${finding.ruleId}`);
  const title = BOLD(finding.title);

  const relativePath = finding.file.replace(/\\/g, '/');
  const loc = DIM(`${relativePath}:${finding.line}:${finding.column}`);

  if (index > 0) console.log(DIM(`  ${LINE_H.repeat(3)}`));
  console.log(`\n  ${badge} ${rule}  ${title}`);
  console.log(`  ${loc}`);

  if (finding.codeSnippet) {
    console.log('');
    for (const line of finding.codeSnippet.split('\n')) {
      if (line.startsWith('>')) {
        console.log(`    ${chalk.red(line)}`);
      } else {
        console.log(`    ${DIM(line)}`);
      }
    }
  }

  const refs: string[] = [];
  if (finding.cwe) refs.push(ACCENT(finding.cwe));
  if (finding.owasp) refs.push(DIM(finding.owasp));
  if (refs.length) {
    console.log(`\n  ${DIM('Ref:')} ${refs.join(DIM(' | '))}`);
  }

  console.log(`  ${chalk.green('Fix:')} ${DIM(finding.remediation)}`);
}

export function printSummary(result: ScanResult): void {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) counts[f.severity]++;

  console.log(`\n  ${hline()}`);
  console.log(`  ${BOLD('  SCAN RESULTS')}`);
  console.log(`  ${hline()}\n`);

  const duration = result.scanDuration < 1000
    ? `${result.scanDuration}ms`
    : `${(result.scanDuration / 1000).toFixed(1)}s`;

  console.log(`  ${DIM('Files')}    ${ACCENT(String(result.scannedFiles))}`);
  console.log(`  ${DIM('Time')}     ${ACCENT(duration)}`);
  console.log(`  ${DIM('Findings')} ${result.findings.length > 0 ? chalk.white.bold(String(result.findings.length)) : chalk.green.bold('0')}`);
  console.log('');

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  for (const sev of severities) {
    if (counts[sev] === 0) continue;
    const icon = SEV_COLOR[sev](SEVERITY_ICONS[sev]);
    const label = SEV_COLOR[sev](sev.toUpperCase().padEnd(9));
    const count = BOLD(String(counts[sev]));
    const bar = SEV_COLOR[sev]('█'.repeat(Math.min(counts[sev], 30)));
    console.log(`  ${icon} ${label} ${count}  ${bar}`);
  }

  if (result.findings.length === 0) {
    console.log(chalk.green.bold('  ✓ No vulnerabilities found!'));
  }

  console.log(`\n  ${hline()}\n`);
}
