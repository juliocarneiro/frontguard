import { parse, type ParserPlugin } from '@babel/parser';
import type { File as BabelFile } from '@babel/types';

const SCRIPT_BLOCK_RE = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const LANG_RE = /\blang\s*=\s*["']?([\w-]+)/i;
const TYPE_RE = /\btype\s*=\s*["']?([\w/+-]+)/i;

const EXECUTABLE_SCRIPT_TYPES = new Set([
  'module',
  'text/javascript',
  'application/javascript',
  'text/babel',
  'text/jsx',
]);

type Dialect = 'ts' | 'tsx' | 'js' | 'jsx';

export interface ExtractedScript {
  /** Same length as the original text: non-script regions are blanked, so AST positions map 1:1. */
  code: string;
  dialect: Dialect;
}

function dialectFromExtension(filename: string): Dialect | 'markup' {
  const ext = filename.slice(filename.lastIndexOf('.') + 1).toLowerCase();
  switch (ext) {
    case 'ts':
    case 'mts':
    case 'cts':
      return 'ts';
    case 'tsx':
      return 'tsx';
    case 'jsx':
      return 'jsx';
    case 'js':
    case 'mjs':
    case 'cjs':
      return 'js';
    default:
      return 'markup';
  }
}

/** Replaces everything except newlines with spaces so line/column positions are preserved. */
function blank(text: string): string {
  return text.replace(/[^\n]/g, ' ');
}

/**
 * Returns the executable script portion of a file. Vue, Svelte and HTML files keep only
 * their `<script>` blocks; everything else is blanked so reported positions stay accurate.
 */
export function extractScript(filename: string, text: string): ExtractedScript | null {
  const fromExtension = dialectFromExtension(filename);
  if (fromExtension !== 'markup') return { code: text, dialect: fromExtension };

  let code = '';
  let cursor = 0;
  let dialect: Dialect = 'js';
  let found = false;

  for (const match of text.matchAll(SCRIPT_BLOCK_RE)) {
    const attrs = match[1] ?? '';
    const body = match[2] ?? '';
    const type = TYPE_RE.exec(attrs)?.[1]?.toLowerCase();
    if (type && !EXECUTABLE_SCRIPT_TYPES.has(type)) continue;

    const lang = LANG_RE.exec(attrs)?.[1]?.toLowerCase();
    if (lang === 'ts' || lang === 'typescript') dialect = 'ts';
    else if (lang === 'tsx') dialect = 'tsx';
    else if (lang === 'jsx') dialect = 'jsx';

    const bodyStart = match.index + match[0].indexOf('>') + 1;
    code += blank(text.slice(cursor, bodyStart)) + body;
    cursor = bodyStart + body.length;
    found = true;
  }

  if (!found) return null;
  code += blank(text.slice(cursor));
  return { code, dialect };
}

function pluginsFor(dialect: Dialect): ParserPlugin[] {
  switch (dialect) {
    case 'ts':
      return ['typescript', 'decorators'];
    case 'tsx':
      return ['typescript', 'jsx', 'decorators'];
    case 'jsx':
    case 'js':
      return ['jsx', 'decorators'];
  }
}

export interface ParseOutcome {
  ast: BabelFile | null;
  error?: string;
}

export function parseScript(script: ExtractedScript): ParseOutcome {
  try {
    const ast = parse(script.code, {
      sourceType: 'unambiguous',
      plugins: pluginsFor(script.dialect),
      errorRecovery: true,
    });
    return { ast };
  } catch (error) {
    return { ast: null, error: error instanceof Error ? error.message : String(error) };
  }
}
