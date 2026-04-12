import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type {
  FileContent,
  Finding,
  FrontGuardConfig,
  RuleDefinition,
  ScannerCategory,
} from '../../core/types.js';
import { BaseScanner } from '../base-scanner.js';

import {
  rule as noLocalstorageTokenRule,
  check as checkNoLocalstorageToken,
} from './rules/no-localstorage-token.js';
import {
  rule as noTokenInUrlRule,
  check as checkNoTokenInUrl,
} from './rules/no-token-in-url.js';
import {
  rule as noHardcodedCredentialsRule,
  check as checkNoHardcodedCredentials,
} from './rules/no-hardcoded-credentials.js';

export const traverse: typeof _traverse =
  typeof _traverse === 'function' ? _traverse : (_traverse as any).default;

type ParsedAST = ReturnType<typeof parse>;

const PARSER_PLUGINS = ['typescript', 'jsx', 'decorators'] as const;

let cachedContent: string | null = null;
let cachedAst: ParsedAST | null = null;

export function parseFile(content: string): ParsedAST | null {
  if (content === cachedContent && cachedAst) return cachedAst;

  try {
    cachedAst = parse(content, {
      sourceType: 'module',
      plugins: [...PARSER_PLUGINS],
      errorRecovery: true,
    });
    cachedContent = content;
    return cachedAst;
  } catch {
    cachedContent = null;
    cachedAst = null;
    return null;
  }
}

export interface RuleHit {
  line: number;
  column: number;
}

type RuleCheckFn = (file: FileContent) => RuleHit[];

interface RuleEntry {
  rule: RuleDefinition;
  check: RuleCheckFn;
}

const ALL_RULES: RuleEntry[] = [
  { rule: noLocalstorageTokenRule, check: checkNoLocalstorageToken },
  { rule: noTokenInUrlRule, check: checkNoTokenInUrl },
  { rule: noHardcodedCredentialsRule, check: checkNoHardcodedCredentials },
];

export class AuthPatternsScanner extends BaseScanner {
  readonly name = 'Auth Patterns Scanner';
  readonly category: ScannerCategory = 'auth-patterns';

  getRules(): RuleDefinition[] {
    return ALL_RULES.map(entry => entry.rule);
  }

  scanFile(file: FileContent, _config: FrontGuardConfig): Finding[] {
    const findings: Finding[] = [];

    for (const { rule, check } of ALL_RULES) {
      try {
        const hits = check(file);
        for (const hit of hits) {
          findings.push(this.createFinding(rule, file, hit.line, hit.column));
        }
      } catch {
        // skip rule on failure
      }
    }

    return findings;
  }
}
