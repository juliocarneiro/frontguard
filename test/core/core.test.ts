import { describe, expect, it } from 'vitest';
import { analyzeFile } from '../../src/core/analyze.ts';
import { defineRule, positionAt } from '../../src/core/rule.ts';
import { meetsThreshold, severityFromScore } from '../../src/core/severity.ts';
import { buildSnippet, mask } from '../../src/core/snippet.ts';
import { extractScript } from '../../src/core/source.ts';
import { parseSuppressions } from '../../src/core/suppressions.ts';
import { analyze } from '../helpers.ts';

describe('extractScript', () => {
  it('keeps the original length and line structure', () => {
    const text = '<template>\n<p/>\n</template>\n<script lang="ts">\nlet a = 1;\n</script>\n';
    const script = extractScript('A.vue', text)!;
    expect(script.code).toHaveLength(text.length);
    expect(script.code.split('\n')[4]).toBe('let a = 1;');
    expect(script.dialect).toBe('ts');
  });

  it('returns null for markup without scripts', () => {
    expect(extractScript('index.html', '<p>hello</p>')).toBeNull();
  });
});

describe('suppressions', () => {
  const lines = [
    '// frontguard-ignore-next-line FG-XSS-002',
    'eval(a)',
    'eval(b) // frontguard-ignore-line',
    '/* frontguard-ignore-next-line no-eval, FG-XSS-001 */',
    'eval(c)',
  ];
  const s = parseSuppressions(lines);

  it('supports next-line, same-line, ids and names', () => {
    expect(s.isSuppressed(2, 'FG-XSS-002', 'no-eval')).toBe(true);
    expect(s.isSuppressed(2, 'FG-XSS-003', 'no-document-write')).toBe(false);
    expect(s.isSuppressed(3, 'ANY', 'any')).toBe(true);
    expect(s.isSuppressed(5, 'FG-XSS-002', 'no-eval')).toBe(true);
  });

  it('supports file-wide suppressions', () => {
    const findings = analyze(
      '/* frontguard-ignore-file FG-XSS-002 */\neval(a);\nel.innerHTML = x;',
      'a.ts',
    );
    expect(findings.map((f) => f.ruleId)).toEqual(['FG-XSS-001']);
  });
});

describe('snippets', () => {
  it('marks the reported line and masks secrets', () => {
    const snippet = buildSnippet(['a', 'b secret-value-123', 'c'], 2, ['secret-value-123']);
    expect(snippet).toContain('> 2 | b secr');
    expect(snippet).not.toContain('secret-value-123');
  });

  it('never reveals short secrets', () => {
    expect(mask('abcd1234')).toBe('********');
  });
});

describe('analyzeFile', () => {
  it('runs custom rules and reports crashes as warnings', () => {
    const custom = defineRule({
      meta: {
        id: 'ACME-001',
        name: 'no-alert',
        title: 'alert() call',
        description: 'd',
        remediation: 'r',
        severity: 'low',
        category: 'xss',
      },
      create: (context) => ({
        CallExpression({ node }) {
          if (node.callee.type === 'Identifier' && node.callee.name === 'alert') {
            context.report({ line: node.loc!.start.line, column: node.loc!.start.column + 1 });
          }
        },
      }),
    });
    const crashing = defineRule({
      meta: { ...custom.meta, id: 'ACME-002', name: 'boom' },
      create: () => {
        throw new Error('boom');
      },
    });
    const outcome = analyzeFile('a.js', 'alert(1)', [
      { rule: custom, level: 'warn' },
      { rule: crashing, level: 'error' },
    ]);
    expect(outcome.findings).toMatchObject([
      { ruleId: 'ACME-001', level: 'warn', line: 1, column: 1 },
    ]);
    expect(outcome.warnings[0]).toContain('ACME-002 crashed');
  });

  it('keeps going on syntax errors', () => {
    const outcome = analyzeFile('a.ts', 'const = ;\neval(x)', []);
    expect(outcome.findings).toEqual([]);
  });
});

describe('helpers', () => {
  it('positionAt converts offsets to 1-based positions', () => {
    expect(positionAt('ab\ncd', 4)).toEqual({ line: 2, column: 2 });
  });

  it('severity thresholds', () => {
    expect(meetsThreshold('high', 'medium')).toBe(true);
    expect(meetsThreshold('low', 'medium')).toBe(false);
    expect(meetsThreshold('critical', 'none')).toBe(false);
    expect(severityFromScore(9.8)).toBe('critical');
    expect(severityFromScore(5)).toBe('medium');
  });
});
