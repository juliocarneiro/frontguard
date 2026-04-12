import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import type { FileContent, Finding, FrontGuardConfig, RuleDefinition, ScannerCategory } from '../../core/types.js';
import { BaseScanner } from '../base-scanner.js';

import { rule as noInnerHtmlRule, check as checkNoInnerHtml } from './rules/no-inner-html.js';
import { rule as noEvalRule, check as checkNoEval } from './rules/no-eval.js';
import { rule as noDocumentWriteRule, check as checkNoDocumentWrite } from './rules/no-document-write.js';
import { rule as noDangerousSetInnerHtmlRule, check as checkNoDangerousSetInnerHtml } from './rules/no-dangerous-set-inner-html.js';
import { rule as noVHtmlRule, check as checkNoVHtml } from './rules/no-v-html.js';
import { rule as noBypassSecurityRule, check as checkNoBypassSecurity } from './rules/no-bypass-security.js';
import { rule as noOuterHtmlRule, check as checkNoOuterHtml } from './rules/no-outer-html.js';
import { rule as noUnsafeUrlSchemeRule, check as checkNoUnsafeUrlScheme } from './rules/no-unsafe-url-scheme.js';

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
  { rule: noInnerHtmlRule, check: checkNoInnerHtml },
  { rule: noEvalRule, check: checkNoEval },
  { rule: noDocumentWriteRule, check: checkNoDocumentWrite },
  { rule: noDangerousSetInnerHtmlRule, check: checkNoDangerousSetInnerHtml },
  { rule: noVHtmlRule, check: checkNoVHtml },
  { rule: noBypassSecurityRule, check: checkNoBypassSecurity },
  { rule: noOuterHtmlRule, check: checkNoOuterHtml },
  { rule: noUnsafeUrlSchemeRule, check: checkNoUnsafeUrlScheme },
];

export class XSSScanner extends BaseScanner {
  readonly name = 'XSS Scanner';
  readonly category: ScannerCategory = 'xss';

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
