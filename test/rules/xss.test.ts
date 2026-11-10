import { describe, expect, it } from 'vitest';
import { analyze, ruleIds } from '../helpers.ts';

describe('FG-XSS-001 no-inner-html', () => {
  it('reports dynamic innerHTML and outerHTML', () => {
    expect(ruleIds('el.innerHTML = userInput;')).toEqual(['FG-XSS-001']);
    expect(ruleIds('el.outerHTML = html;')).toEqual(['FG-XSS-001']);
    expect(ruleIds("el['innerHTML'] = html;")).toEqual(['FG-XSS-001']);
    expect(ruleIds('el.innerHTML += `<li>${item}</li>`;')).toEqual(['FG-XSS-001']);
  });

  it('ignores static strings', () => {
    expect(ruleIds("el.innerHTML = '';")).toEqual([]);
    expect(ruleIds('el.innerHTML = `<span class="x"></span>`;')).toEqual([]);
  });

  it('reports the exact position', () => {
    const [finding] = analyze('const a = 1;\n  el.innerHTML = x;');
    expect(finding).toMatchObject({ line: 2, column: 3, file: 'file.tsx' });
  });
});

describe('FG-XSS-002 no-eval', () => {
  it.each([
    'eval(code)',
    'window.eval(code)',
    'new Function("return " + x)',
    'Function("a", body)',
    'setTimeout("alert(1)", 10)',
    'globalThis.setInterval(`tick()`, 10)',
  ])('reports %s', (code) => {
    expect(ruleIds(code)).toEqual(['FG-XSS-002']);
  });

  it('ignores timers with function arguments and unrelated members', () => {
    expect(ruleIds('setTimeout(() => run(), 10)')).toEqual([]);
    expect(ruleIds('obj.eval(code)')).toEqual([]);
  });
});

describe('FG-XSS-003 no-document-write', () => {
  it('reports document.write and writeln', () => {
    expect(ruleIds('document.write(x)')).toEqual(['FG-XSS-003']);
    expect(ruleIds('window.document.writeln(x)')).toEqual(['FG-XSS-003']);
    expect(ruleIds('stream.write(x)')).toEqual([]);
  });
});

describe('FG-XSS-004 no-dangerously-set-inner-html', () => {
  it('reports JSX attribute and createElement props', () => {
    expect(ruleIds('<div dangerouslySetInnerHTML={{ __html: html }} />')).toEqual(['FG-XSS-004']);
    expect(ruleIds('createElement("div", { dangerouslySetInnerHTML: { __html: x } })')).toEqual([
      'FG-XSS-004',
    ]);
  });
});

describe('FG-XSS-005 no-v-html', () => {
  it('reports v-html in Vue templates only', () => {
    expect(ruleIds('<template><p v-html="bio"></p></template>', 'A.vue')).toEqual(['FG-XSS-005']);
    expect(ruleIds('const doc = "use v-html carefully";', 'a.ts')).toEqual([]);
  });
});

describe('FG-XSS-006 no-bypass-security-trust', () => {
  it('reports Angular sanitizer bypasses', () => {
    const code = 'this.sanitizer.bypassSecurityTrustHtml(html);';
    expect(ruleIds(code, 'a.component.ts')).toEqual(['FG-XSS-006']);
  });

  it('parses decorators', () => {
    const code =
      '@Component({ selector: "x" })\nclass A { constructor(private s: DomSanitizer) { s.bypassSecurityTrustUrl(u); } }';
    expect(ruleIds(code, 'a.component.ts')).toEqual(['FG-XSS-006']);
  });
});

describe('FG-XSS-007 no-html-sink-call', () => {
  it('reports dynamic HTML parsing APIs', () => {
    expect(ruleIds('el.insertAdjacentHTML("beforeend", html)')).toEqual(['FG-XSS-007']);
    expect(ruleIds('range.createContextualFragment(html)')).toEqual(['FG-XSS-007']);
    expect(ruleIds('el.insertAdjacentHTML("beforeend", "<hr>")')).toEqual([]);
  });
});

describe('FG-XSS-008 no-javascript-url', () => {
  it('reports javascript: URLs', () => {
    expect(ruleIds('<a href="javascript:alert(1)">x</a>')).toEqual(['FG-XSS-008']);
    expect(ruleIds('link.href = `javascript:${code}`')).toEqual(['FG-XSS-008']);
    expect(ruleIds('<a href="https://example.com">x</a>')).toEqual([]);
  });
});

describe('FG-XSS-009 no-svelte-html', () => {
  it('reports {@html} in Svelte files', () => {
    expect(ruleIds('<p>{@html body}</p>', 'A.svelte')).toEqual(['FG-XSS-009']);
  });
});

describe('script extraction', () => {
  it('analyzes <script> blocks of Vue, Svelte and HTML with original positions', () => {
    const vue =
      '<template>\n  <p>{{ a }}</p>\n</template>\n<script setup lang="ts">\nconst x: number = 1;\neval(code);\n</script>';
    expect(analyze(vue, 'A.vue')).toMatchObject([{ ruleId: 'FG-XSS-002', line: 6, column: 1 }]);

    const svelte = '<script>\n  eval(x);\n</script>\n<p>hi</p>';
    expect(analyze(svelte, 'B.svelte')).toMatchObject([
      { ruleId: 'FG-XSS-002', line: 2, column: 3 },
    ]);

    const html = '<html><body><script>document.write(location.hash)</script></body></html>';
    expect(analyze(html, 'index.html')).toMatchObject([
      { ruleId: 'FG-XSS-003', line: 1, column: 21 },
    ]);
  });

  it('skips non-executable script types', () => {
    const html = '<script type="application/ld+json">{"eval": "eval(x)"}</script>';
    expect(ruleIds(html, 'index.html')).toEqual([]);
  });
});
