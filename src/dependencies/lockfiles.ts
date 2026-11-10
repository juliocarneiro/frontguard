import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export interface InstalledPackage {
  name: string;
  version: string;
  /** Only reachable from devDependencies. */
  dev: boolean;
}

export interface Lockfile {
  /** File name relative to the project root, e.g. `pnpm-lock.yaml`. */
  file: string;
  text: string;
  packages: InstalledPackage[];
}

interface Manifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

type Dict = Record<string, unknown>;

const SEMVER_RE = /^\d+\.\d+\.\d+(?:[-+][\w.+-]*)?$/;

const isDict = (value: unknown): value is Dict =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const asDict = (value: unknown): Dict => (isDict(value) ? value : {});

const stringEntries = (value: unknown): [string, string][] =>
  Object.entries(asDict(value)).filter((e): e is [string, string] => typeof e[1] === 'string');

/** Splits `name@version` / `@scope/name@version`, ignoring a leading `@`. */
function splitNameVersion(spec: string): [string, string] | null {
  const at = spec.lastIndexOf('@');
  return at > 0 ? [spec.slice(0, at), spec.slice(at + 1)] : null;
}

/** Removes pnpm peer-dependency suffixes: `1.0.0(react@19.0.0)` -> `1.0.0`. */
const stripPeers = (version: string) => version.replace(/[(_].*$/, '');

// ─── Dependency graph shared by pnpm v9, yarn and bun ────────────────────────

class Graph {
  readonly nodes = new Map<string, { name: string; version: string }>();
  readonly edges = new Map<string, string[]>();
  readonly prodRoots: string[] = [];
  readonly devRoots: string[] = [];

  add(key: string, name: string, version: string, deps: string[] = []) {
    this.nodes.set(key, { name, version });
    this.edges.set(key, deps);
  }

  private reach(roots: string[]): Set<string> {
    const seen = new Set<string>();
    const stack = [...roots];
    while (stack.length > 0) {
      const key = stack.pop()!;
      if (seen.has(key) || !this.nodes.has(key)) continue;
      seen.add(key);
      stack.push(...(this.edges.get(key) ?? []));
    }
    return seen;
  }

  /** A package is `dev` only when it is reachable from dev roots and not from prod roots. */
  classify(): InstalledPackage[] {
    const prod = this.reach(this.prodRoots);
    const dev = this.reach(this.devRoots);
    return [...this.nodes].map(([key, { name, version }]) => ({
      name,
      version,
      dev: dev.has(key) && !prod.has(key),
    }));
  }
}

// ─── npm ─────────────────────────────────────────────────────────────────────

function parseNpm(text: string): InstalledPackage[] {
  const lock = asDict(JSON.parse(text));
  const result: InstalledPackage[] = [];

  if (isDict(lock.packages)) {
    for (const [path, raw] of Object.entries(lock.packages)) {
      const entry = asDict(raw);
      if (!path || entry.link === true || typeof entry.version !== 'string') continue;
      const name =
        typeof entry.name === 'string'
          ? entry.name
          : path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
      result.push({
        name,
        version: entry.version,
        dev: entry.dev === true || entry.devOptional === true,
      });
    }
    return result;
  }

  // lockfileVersion 1 (npm 6): nested `dependencies`.
  const walk = (deps: unknown) => {
    for (const [name, raw] of Object.entries(asDict(deps))) {
      const entry = asDict(raw);
      if (typeof entry.version === 'string') {
        result.push({ name, version: entry.version, dev: entry.dev === true });
      }
      walk(entry.dependencies);
    }
  };
  walk(lock.dependencies);
  return result;
}

// ─── pnpm ────────────────────────────────────────────────────────────────────

function parsePnpm(text: string): InstalledPackage[] {
  const lock = asDict(parseYaml(text));
  const major = Number.parseInt(
    String((lock.lockfileVersion as string | number | undefined) ?? '0'),
    10,
  );

  if (major < 9) {
    // v5/v6 entries carry their own `dev` flag.
    const result: InstalledPackage[] = [];
    for (const [key, raw] of Object.entries(asDict(lock.packages))) {
      const spec = stripPeers(key.replace(/^\//, ''));
      const parts =
        splitNameVersion(spec) ??
        (() => {
          const slash = spec.lastIndexOf('/');
          return slash > 0
            ? ([spec.slice(0, slash), spec.slice(slash + 1)] as [string, string])
            : null;
        })();
      if (!parts) continue;
      result.push({ name: parts[0], version: parts[1], dev: asDict(raw).dev === true });
    }
    return result;
  }

  const graph = new Graph();
  // Refs are versions (`1.2.3(peer@1.0.0)`) or, for aliases, full keys (`real-name@1.2.3`).
  const resolveRef = (name: string, ref: string): string | null => {
    if (/^(link|file|workspace):/.test(ref)) return null;
    return /^\d/.test(ref) ? `${name}@${ref}` : ref;
  };

  for (const [key, raw] of Object.entries(asDict(lock.snapshots))) {
    const parts = splitNameVersion(stripPeers(key));
    if (!parts) continue;
    const entry = asDict(raw);
    const deps = [
      ...stringEntries(entry.dependencies),
      ...stringEntries(entry.optionalDependencies),
    ]
      .map(([name, ref]) => resolveRef(name, ref))
      .filter((k): k is string => k !== null);
    graph.add(key, parts[0], parts[1], deps);
  }

  for (const importer of Object.values(asDict(lock.importers))) {
    const imp = asDict(importer);
    const roots = (field: unknown) =>
      Object.entries(asDict(field))
        .map(([name, v]) => resolveRef(name, String(asDict(v).version ?? v)))
        .filter((k): k is string => k !== null);
    graph.prodRoots.push(...roots(imp.dependencies), ...roots(imp.optionalDependencies));
    graph.devRoots.push(...roots(imp.devDependencies));
  }

  return graph.classify();
}

// ─── yarn ────────────────────────────────────────────────────────────────────

interface YarnEntry {
  descriptors: string[];
  version: string;
  dependencies: [string, string][];
}

/** Parses the custom yarn v1 lockfile format. */
function parseYarnV1Entries(text: string): YarnEntry[] {
  const entries: YarnEntry[] = [];
  let current: YarnEntry | null = null;
  let inDeps = false;
  const unquote = (s: string) => s.trim().replace(/^"|"$/g, '');

  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (!line.startsWith(' ')) {
      current = {
        descriptors: line.replace(/:$/, '').split(',').map(unquote),
        version: '',
        dependencies: [],
      };
      entries.push(current);
      inDeps = false;
    } else if (current && /^ {2}\S/.test(line)) {
      const trimmed = line.trim();
      inDeps = /^(dependencies|optionalDependencies):$/.test(trimmed);
      const version = /^version\s+"?([^"\s]+)"?/.exec(trimmed);
      if (version) current.version = version[1]!;
    } else if (current && inDeps && /^ {4}\S/.test(line)) {
      const match = /^\s*("?[^"\s]+"?)\s+"?([^"]+)"?$/.exec(line);
      if (match) current.dependencies.push([unquote(match[1]!), match[2]!]);
    }
  }
  return entries;
}

function parseYarnBerryEntries(text: string): YarnEntry[] {
  const lock = asDict(parseYaml(text));
  const entries: YarnEntry[] = [];
  for (const [key, raw] of Object.entries(lock)) {
    // Workspaces are local packages, not registry dependencies.
    if (key === '__metadata' || /@(?:workspace|link|portal|file):/.test(key)) continue;
    const entry = asDict(raw);
    entries.push({
      descriptors: key.split(',').map((d) => d.trim()),
      version: String((entry.version as string | number | undefined) ?? ''),
      dependencies: [
        ...stringEntries(entry.dependencies),
        ...stringEntries(entry.optionalDependencies),
      ],
    });
  }
  return entries;
}

function parseYarn(text: string, manifest: Manifest): InstalledPackage[] {
  const entries = text.includes('__metadata:')
    ? parseYarnBerryEntries(text)
    : parseYarnV1Entries(text);
  const graph = new Graph();
  const byDescriptor = new Map<string, string>();

  for (const entry of entries) {
    const first = entry.descriptors[0];
    const parts = first ? splitNameVersion(first) : null;
    if (!parts || !SEMVER_RE.test(entry.version)) continue;
    const key = `${parts[0]}@${entry.version}`;
    for (const d of entry.descriptors) byDescriptor.set(d, key);
  }

  const lookup = (name: string, range: string) =>
    byDescriptor.get(`${name}@${range}`) ?? byDescriptor.get(`${name}@npm:${range}`);

  for (const entry of entries) {
    const first = entry.descriptors[0];
    const parts = first ? splitNameVersion(first) : null;
    if (!parts || !SEMVER_RE.test(entry.version)) continue;
    const deps = entry.dependencies
      .map(([name, range]) => lookup(name, range))
      .filter((k): k is string => k !== undefined);
    graph.add(`${parts[0]}@${entry.version}`, parts[0], entry.version, deps);
  }

  const roots = (deps?: Record<string, string>) =>
    Object.entries(deps ?? {})
      .map(([name, range]) => lookup(name, range))
      .filter((k): k is string => k !== undefined);
  graph.prodRoots.push(...roots(manifest.dependencies), ...roots(manifest.optionalDependencies));
  graph.devRoots.push(...roots(manifest.devDependencies));
  return graph.classify();
}

// ─── bun ─────────────────────────────────────────────────────────────────────

function parseBun(text: string): InstalledPackage[] {
  // bun.lock is JSONC with trailing commas.
  const lock = asDict(JSON.parse(text.replace(/,(\s*[}\]])/g, '$1')));
  const packages = asDict(lock.packages);
  const graph = new Graph();

  /**
   * Bun keys nested packages like node_modules paths (`parent/dep`, `@s/parent/@s/dep`).
   * Resolution walks up from the most nested location to the hoisted `dep`.
   */
  const resolveKey = (from: string, dep: string): string | null => {
    const segments = from ? (from.match(/(?:@[^/]+\/)?[^/]+/g) ?? []) : [];
    for (let depth = segments.length; depth >= 0; depth--) {
      const candidate = [...segments.slice(0, depth), dep].join('/');
      if (candidate in packages) return candidate;
    }
    return null;
  };

  for (const [key, raw] of Object.entries(packages)) {
    if (!Array.isArray(raw) || typeof raw[0] !== 'string') continue;
    const parts = splitNameVersion(raw[0]);
    if (!parts || !SEMVER_RE.test(parts[1])) continue;
    const meta = asDict(raw[2]);
    const deps = [...stringEntries(meta.dependencies), ...stringEntries(meta.optionalDependencies)]
      .map(([name]) => resolveKey(key, name))
      .filter((k): k is string => k !== null);
    graph.add(key, parts[0], parts[1], deps);
  }

  for (const workspace of Object.values(asDict(lock.workspaces))) {
    const ws = asDict(workspace);
    const roots = (field: unknown) =>
      Object.keys(asDict(field))
        .map((name) => resolveKey('', name))
        .filter((k): k is string => k !== null);
    graph.prodRoots.push(...roots(ws.dependencies), ...roots(ws.optionalDependencies));
    graph.devRoots.push(...roots(ws.devDependencies));
  }
  return graph.classify();
}

// ─── Discovery ───────────────────────────────────────────────────────────────

const PARSERS: [string, (text: string, manifest: Manifest) => InstalledPackage[]][] = [
  ['package-lock.json', parseNpm],
  ['npm-shrinkwrap.json', parseNpm],
  ['pnpm-lock.yaml', parsePnpm],
  ['yarn.lock', parseYarn],
  ['bun.lock', parseBun],
];

export function readManifest(root: string): Manifest | null {
  const file = join(root, 'package.json');
  if (!existsSync(file)) return null;
  return JSON.parse(readFileSync(file, 'utf8')) as Manifest;
}

/** Finds and parses the first supported lockfile in `root`. Duplicates are removed. */
export function readLockfile(root: string, manifest: Manifest = {}): Lockfile | null {
  for (const [file, parse] of PARSERS) {
    const path = join(root, file);
    if (!existsSync(path)) continue;
    const text = readFileSync(path, 'utf8');
    const unique = new Map<string, InstalledPackage>();
    for (const pkg of parse(text, manifest)) {
      if (!SEMVER_RE.test(pkg.version)) continue;
      const key = `${pkg.name}@${pkg.version}`;
      const existing = unique.get(key);
      // Prefer the prod classification when a version appears in both trees.
      if (!existing || (existing.dev && !pkg.dev)) unique.set(key, pkg);
    }
    return { file, text, packages: [...unique.values()] };
  }
  return null;
}

/** Without a lockfile, approximate versions with the lower bound of each range. */
export function packagesFromManifest(manifest: Manifest): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  const add = (deps: Record<string, string> | undefined, dev: boolean) => {
    for (const [name, range] of Object.entries(deps ?? {})) {
      if (/^(file|link|workspace|git|github|https?):/.test(range)) continue;
      const version = /\d+\.\d+\.\d+(?:-[\w.]+)?/.exec(range)?.[0];
      if (version) out.push({ name, version, dev });
    }
  };
  add(manifest.dependencies, false);
  add(manifest.optionalDependencies, false);
  add(manifest.devDependencies, true);
  return out;
}

/** Best-effort 1-based line where a package version is declared in the lockfile. */
export function findPackageLine(lines: readonly string[], name: string, version: string): number {
  const needles = [
    `node_modules/${name}"`,
    `${name}@${version}`,
    `/${name}/${version}`,
    `"${name}@`,
    `${name}@`,
  ];
  for (const needle of needles) {
    const index = lines.findIndex((line) => line.includes(needle));
    if (index !== -1) return index + 1;
  }
  return 1;
}
