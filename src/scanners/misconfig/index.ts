import type {
  FileContent,
  Finding,
  FrontGuardConfig,
  RuleDefinition,
  ScannerCategory,
} from '../../core/types.js';
import { BaseScanner } from '../base-scanner.js';

import {
  rule as sourcemapExposedRule,
  check as checkSourcemapExposed,
} from './rules/sourcemap-exposed.js';
import {
  rule as mixedContentRule,
  check as checkMixedContent,
} from './rules/mixed-content.js';
import {
  rule as insecureCdnRule,
  check as checkInsecureCdn,
} from './rules/insecure-cdn.js';

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
  { rule: sourcemapExposedRule, check: checkSourcemapExposed },
  { rule: mixedContentRule, check: checkMixedContent },
  { rule: insecureCdnRule, check: checkInsecureCdn },
];

export class MisconfigScanner extends BaseScanner {
  readonly name = 'Misconfig Scanner';
  readonly category: ScannerCategory = 'misconfig';

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
