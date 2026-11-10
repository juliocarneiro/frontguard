import type { ResolvedConfig } from '../config/schema.ts';
import { buildSnippet } from '../core/snippet.ts';
import type { Finding, RuleMeta } from '../types.ts';
import {
  findPackageLine,
  packagesFromManifest,
  readLockfile,
  readManifest,
  type InstalledPackage,
} from './lockfiles.ts';
import { fetchVulnerabilities, queryVulnerabilityIds, toAdvisory } from './osv.ts';

export const DEPENDENCY_RULE: RuleMeta = {
  id: 'FG-DEP-001',
  name: 'no-vulnerable-dependencies',
  title: 'Vulnerable dependency',
  description: 'An installed package version has a published security advisory (source: OSV.dev).',
  severity: 'high',
  category: 'dependencies',
  cwe: 'CWE-1395',
  owasp: 'A06:2021 - Vulnerable and Outdated Components',
  remediation: 'Upgrade the package to a patched version, or replace it.',
};

export interface AuditOutcome {
  findings: Omit<Finding, 'level'>[];
  warnings: string[];
}

export async function auditDependencies(
  root: string,
  options: ResolvedConfig['dependencies'],
  fetchImpl: typeof globalThis.fetch = globalThis.fetch,
): Promise<AuditOutcome> {
  const warnings: string[] = [];
  if (options.offline) return { findings: [], warnings };

  let manifest;
  try {
    manifest = readManifest(root);
  } catch (error) {
    return { findings: [], warnings: [`package.json could not be parsed: ${String(error)}`] };
  }
  if (!manifest) return { findings: [], warnings };

  let file = 'package.json';
  let text: string;
  let packages: InstalledPackage[];
  try {
    const lockfile = readLockfile(root, manifest);
    if (lockfile) {
      ({ file, text, packages } = lockfile);
    } else {
      warnings.push(
        'No lockfile found: auditing the lowest versions allowed by package.json. Commit a lockfile for accurate results.',
      );
      text = JSON.stringify(manifest, null, 2);
      packages = packagesFromManifest(manifest);
    }
  } catch (error) {
    return { findings: [], warnings: [`Lockfile could not be parsed: ${String(error)}`] };
  }

  const audited = options.includeDev ? packages : packages.filter((p) => !p.dev);
  if (audited.length === 0) return { findings: [], warnings };

  const client = { fetch: fetchImpl, timeoutMs: options.timeoutMs };
  let idsPerPackage: string[][];
  let details: Awaited<ReturnType<typeof fetchVulnerabilities>>;
  try {
    idsPerPackage = await queryVulnerabilityIds(audited, client);
    details = await fetchVulnerabilities(idsPerPackage.flat(), client);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    warnings.push(
      `Dependency audit skipped: OSV.dev request failed (${reason}). Use --offline to silence.`,
    );
    return { findings: [], warnings };
  }

  const lines = text.split(/\r?\n/);
  const findings: Omit<Finding, 'level'>[] = [];

  audited.forEach((pkg, index) => {
    const ids = idsPerPackage[index] ?? [];
    if (ids.length === 0) return;
    const line = findPackageLine(lines, pkg.name, pkg.version);
    for (const id of ids) {
      const raw = details.get(id);
      if (!raw) continue;
      const advisory = toAdvisory(raw, pkg.name, pkg.version);
      const cve = advisory.aliases.find((a) => a.startsWith('CVE-'));
      findings.push({
        ruleId: DEPENDENCY_RULE.id,
        ruleName: DEPENDENCY_RULE.name,
        severity: advisory.severity,
        category: 'dependencies',
        title: DEPENDENCY_RULE.title,
        message: `${pkg.name}@${pkg.version}: ${advisory.summary} (${[advisory.id, cve].filter(Boolean).join(', ')})`,
        description: DEPENDENCY_RULE.description,
        remediation: advisory.fixedIn
          ? `Upgrade ${pkg.name} to ${advisory.fixedIn} or later. Details: ${advisory.url}`
          : `No patched version is listed. Consider replacing ${pkg.name}. Details: ${advisory.url}`,
        file,
        line,
        column: 1,
        snippet: buildSnippet(lines, line),
        cwe: DEPENDENCY_RULE.cwe!,
        owasp: DEPENDENCY_RULE.owasp!,
        data: {
          package: pkg.name,
          version: pkg.version,
          dev: pkg.dev,
          advisory: advisory.id,
          aliases: advisory.aliases,
          fixedIn: advisory.fixedIn,
          url: advisory.url,
        },
      });
    }
  });

  return { findings, warnings };
}
