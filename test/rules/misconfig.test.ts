import { describe, expect, it } from 'vitest';
import { analyze, ruleIds } from '../helpers.ts';

describe('FG-CFG-001 no-public-sourcemaps', () => {
  it('reports public source maps in build configs only', () => {
    expect(ruleIds('export default { build: { sourcemap: true } }', 'vite.config.ts')).toEqual([
      'FG-CFG-001',
    ]);
    expect(ruleIds("module.exports = { devtool: 'source-map' }", 'webpack.config.js')).toEqual([
      'FG-CFG-001',
    ]);
    expect(
      ruleIds('module.exports = { productionBrowserSourceMaps: true }', 'next.config.js'),
    ).toEqual(['FG-CFG-001']);
    expect(ruleIds("export default { build: { sourcemap: 'hidden' } }", 'vite.config.ts')).toEqual(
      [],
    );
    expect(ruleIds('const opts = { sourcemap: true }', 'src/app.ts')).toEqual([]);
  });
});

describe('FG-CFG-002 no-mixed-content', () => {
  it('reports insecure resource URLs', () => {
    expect(ruleIds('fetch("http://api.example.com/data")', 'a.ts')).toEqual(['FG-CFG-002']);
    expect(ruleIds('axios.get("http://api.example.com")', 'a.ts')).toEqual(['FG-CFG-002']);
    expect(ruleIds('new WebSocket("ws://chat.example.com")', 'a.ts')).toEqual(['FG-CFG-002']);
    expect(ruleIds('<img src="http://cdn.example.com/a.png">', 'index.html')).toEqual([
      'FG-CFG-002',
    ]);
  });

  it('ignores localhost and navigation links', () => {
    expect(ruleIds('fetch("http://localhost:3000/api")', 'a.ts')).toEqual([]);
    expect(ruleIds('<a href="http://example.com">x</a>', 'index.html')).toEqual([]);
  });
});

describe('FG-CFG-003 require-sri', () => {
  it('reports third-party scripts and stylesheets without integrity, across lines', () => {
    const html = '<script\n  src="https://cdn.example.com/lib.js"></script>';
    expect(analyze(html, 'index.html')).toMatchObject([{ ruleId: 'FG-CFG-003', line: 1 }]);
    expect(
      ruleIds('<link rel="stylesheet" href="https://cdn.example.com/a.css">', 'index.html'),
    ).toEqual(['FG-CFG-003']);
  });

  it('ignores tags with integrity, first-party paths and non-stylesheet links', () => {
    expect(
      ruleIds(
        '<script src="https://cdn.example.com/lib.js" integrity="sha384-x"></script>',
        'index.html',
      ),
    ).toEqual([]);
    expect(ruleIds('<script type="module" src="/src/main.ts"></script>', 'index.html')).toEqual([]);
    expect(
      ruleIds('<link rel="icon" href="https://cdn.example.com/favicon.ico">', 'index.html'),
    ).toEqual([]);
  });
});

describe('FG-CFG-004 no-wildcard-postmessage', () => {
  it('reports postMessage to any origin', () => {
    expect(ruleIds('window.parent.postMessage(data, "*")', 'a.ts')).toEqual(['FG-CFG-004']);
    expect(ruleIds('window.parent.postMessage(data, "https://app.example.com")', 'a.ts')).toEqual(
      [],
    );
  });
});
