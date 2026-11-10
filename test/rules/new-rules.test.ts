import { describe, expect, it } from 'vitest';
import { analyze, ruleIds } from '../helpers.ts';

const only = (id: string, code: string, file = 'a.ts') =>
  ruleIds(code, file).filter((r) => r === id);
const findings = (id: string, code: string, file = 'a.ts') =>
  analyze(code, file).filter((f) => f.ruleId === id);

describe('FG-XSS-010 no-open-redirect', () => {
  it('reports navigation to URL-controlled values', () => {
    expect(
      only('FG-XSS-010', 'location.href = new URLSearchParams(location.search).get("next")'),
    ).toHaveLength(1);
    expect(
      only(
        'FG-XSS-010',
        'const p = new URLSearchParams(window.location.search);\nconst next = p.get("r");\nwindow.location = next;',
      ),
    ).toHaveLength(1);
    expect(
      only('FG-XSS-010', 'window.location.assign(decodeURIComponent(location.hash.slice(1)))'),
    ).toHaveLength(1);
    expect(
      only(
        'FG-XSS-010',
        'const [params] = useSearchParams();\nwindow.open(params.get("url"))',
        'a.tsx',
      ),
    ).toHaveLength(1);
    expect(only('FG-XSS-010', 'location.replace(`${document.referrer}`)')).toHaveLength(1);
  });

  it('ignores constant and unrelated targets', () => {
    expect(only('FG-XSS-010', 'location.href = "/login"')).toEqual([]);
    expect(only('FG-XSS-010', 'location.href = `/items/${id}`')).toEqual([]);
    expect(only('FG-XSS-010', 'const url = location.search;\nconsole.log(url)')).toEqual([]);
    expect(only('FG-XSS-010', 'function go(u) { location.href = u }')).toEqual([]);
    expect(only('FG-XSS-010', 'open(new URLSearchParams(location.search).get("x"))')).toEqual([]);
  });
});

describe('FG-XSS-011 no-dangerous-attribute', () => {
  it('reports dynamic event handlers, srcdoc and URL attributes from the address', () => {
    expect(only('FG-XSS-011', 'el.setAttribute("onclick", handler)')).toHaveLength(1);
    expect(only('FG-XSS-011', 'frame.srcdoc = html')).toHaveLength(1);
    expect(only('FG-XSS-011', 'btn.onclick = "go(" + id + ")"')).toHaveLength(1);
    expect(only('FG-XSS-011', 'a.setAttribute("href", location.hash.slice(1))')).toHaveLength(1);
    expect(only('FG-XSS-011', '<iframe srcDoc={content} />', 'a.tsx')).toHaveLength(1);
  });

  it('ignores static values and function handlers', () => {
    expect(only('FG-XSS-011', 'el.setAttribute("onclick", "track()")')).toEqual([]);
    expect(only('FG-XSS-011', 'el.onclick = () => go(id)')).toEqual([]);
    expect(only('FG-XSS-011', 'a.setAttribute("href", `/user/${id}`)')).toEqual([]);
    expect(only('FG-XSS-011', '<iframe srcDoc="<p>hi</p>" />', 'a.tsx')).toEqual([]);
  });
});

describe('FG-XSS-012 no-prototype-pollution', () => {
  const unsafe = [
    'function deepMerge(target, source) {',
    '  for (const key in source) {',
    "    if (typeof source[key] === 'object') deepMerge(target[key] ??= {}, source[key]);",
    '    else target[key] = source[key];',
    '  }',
    '  return target;',
    '}',
  ].join('\n');
  const guarded = (guard: string) =>
    unsafe.replace('for (const key in source) {', `for (const key in source) {\n    ${guard}`);

  it('reports unguarded recursive merges, once per function', () => {
    expect(only('FG-XSS-012', unsafe)).toHaveLength(1);
    expect(
      only(
        'FG-XSS-012',
        'const extend = (a, b) => { for (const [k, v] of Object.entries(b)) a[k] = v; return a; }',
      ),
    ).toHaveLength(1);
    expect(only('FG-XSS-012', 'obj.__proto__.isAdmin = true')).toHaveLength(1);
  });

  it('ignores guarded merges and ordinary loops', () => {
    expect(
      only('FG-XSS-012', guarded("if (key === '__proto__' || key === 'constructor') continue;")),
    ).toEqual([]);
    expect(only('FG-XSS-012', guarded('if (!Object.hasOwn(source, key)) continue;'))).toEqual([]);
    expect(
      only(
        'FG-XSS-012',
        'function count(list) { const out = {}; for (const k in list) out[k] = list[k].length; return out; }',
      ),
    ).toEqual([]);
    expect(only('FG-XSS-012', 'for (let i = 0; i < n; i++) grid[i][j] = 0;')).toEqual([]);
  });
});

describe('FG-SEC-007 no-secret-in-public-env', () => {
  it('reports secret-looking public variables', () => {
    expect(
      only('FG-SEC-007', 'const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY'),
    ).toHaveLength(1);
    expect(only('FG-SEC-007', 'stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY)')).toHaveLength(1);
    expect(only('FG-SEC-007', 'const db = process.env.REACT_APP_DATABASE_URL')).toHaveLength(1);
    expect(
      only('FG-SEC-007', 'import { PUBLIC_ADMIN_PASSWORD } from "$env/static/public"'),
    ).toHaveLength(1);
  });

  it('ignores public-by-design keys and server-only variables', () => {
    expect(only('FG-SEC-007', 'process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY')).toEqual([]);
    expect(only('FG-SEC-007', 'import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY')).toEqual([]);
    expect(only('FG-SEC-007', 'process.env.STRIPE_SECRET_KEY')).toEqual([]);
    expect(only('FG-SEC-007', 'import.meta.env.VITE_MAPBOX_TOKEN')).toEqual([]);
  });
});

describe('FG-AUTH-004 no-insecure-random', () => {
  it('reports Math.random() feeding security values', () => {
    expect(only('FG-AUTH-004', 'const token = Math.random().toString(36).slice(2)')).toHaveLength(
      1,
    );
    expect(only('FG-AUTH-004', 'const params = { state: "x", nonce: Math.random() }')).toHaveLength(
      1,
    );
    expect(
      only('FG-AUTH-004', 'function generateCsrf() { return String(Math.random()) }'),
    ).toHaveLength(1);
    expect(
      only(
        'FG-AUTH-004',
        'const codeVerifier = [...Array(43)].map(() => chars[Math.floor(Math.random() * 62)]).join("")',
      ),
    ).toHaveLength(1);
  });

  it('ignores non-security uses', () => {
    expect(only('FG-AUTH-004', 'const delay = Math.random() * 1000')).toEqual([]);
    expect(only('FG-AUTH-004', 'items.sort(() => Math.random() - 0.5)')).toEqual([]);
    expect(only('FG-AUTH-004', '<li key={Math.random()} />', 'a.tsx')).toEqual([]);
    expect(only('FG-AUTH-004', 'const token = crypto.randomUUID()')).toEqual([]);
  });
});

describe('FG-AUTH-005 no-insecure-cookie', () => {
  it('reports auth cookies written from JS', () => {
    expect(findings('FG-AUTH-005', 'document.cookie = "token=" + jwt')).toMatchObject([
      { message: expect.stringContaining('without Secure/SameSite') },
    ]);
    expect(only('FG-AUTH-005', 'document.cookie = `session_id=${id}; path=/`')).toHaveLength(1);
    expect(
      findings('FG-AUTH-005', 'document.cookie = `access_token=${t}; Secure; SameSite=Strict`'),
    ).toMatchObject([{ message: expect.stringContaining('not httpOnly') }]);
  });

  it('ignores non-auth cookies and reads', () => {
    expect(only('FG-AUTH-005', 'document.cookie = "theme=dark; path=/"')).toEqual([]);
    expect(only('FG-AUTH-005', 'const c = document.cookie')).toEqual([]);
    expect(only('FG-AUTH-005', 'document.cookie = `${name}=${value}`')).toEqual([]);
  });
});

describe('FG-CFG-005 require-message-origin-check', () => {
  it('reports window message handlers that never look at the origin', () => {
    expect(
      only('FG-CFG-005', 'window.addEventListener("message", (e) => { el.innerHTML = e.data })'),
    ).toHaveLength(1);
    expect(
      only(
        'FG-CFG-005',
        'function onMsg(event) { run(event.data) }\naddEventListener("message", onMsg)',
      ),
    ).toHaveLength(1);
    expect(
      only('FG-CFG-005', 'window.onmessage = function (ev) { save(ev.data.token) }'),
    ).toHaveLength(1);
  });

  it('ignores checked handlers, workers and other targets', () => {
    expect(
      only(
        'FG-CFG-005',
        'window.addEventListener("message", (e) => { if (e.origin !== ORIGIN) return; use(e.data) })',
      ),
    ).toEqual([]);
    expect(
      only(
        'FG-CFG-005',
        'window.addEventListener("message", ({ origin, data }) => allowed.has(origin) && use(data))',
      ),
    ).toEqual([]);
    expect(
      only(
        'FG-CFG-005',
        'self.addEventListener("message", (e) => run(e.data))',
        'src/search.worker.ts',
      ),
    ).toEqual([]);
    expect(only('FG-CFG-005', 'worker.addEventListener("message", (e) => run(e.data))')).toEqual(
      [],
    );
    expect(only('FG-CFG-005', 'window.addEventListener("message", () => refresh())')).toEqual([]);
  });
});

describe('FG-CFG-006 no-exposed-dev-server', () => {
  it('reports disabled dev server protections in config files', () => {
    expect(
      only('FG-CFG-006', 'export default { server: { allowedHosts: true } }', 'vite.config.ts'),
    ).toHaveLength(1);
    expect(
      only(
        'FG-CFG-006',
        'export default {\n  server: {\n    fs: {\n      strict: false,\n    },\n  },\n}',
        'vite.config.ts',
      ),
    ).toHaveLength(1);
    expect(
      only(
        'FG-CFG-006',
        "module.exports = { devServer: { allowedHosts: 'all' } }",
        'webpack.config.js',
      ),
    ).toHaveLength(1);
    expect(
      only('FG-CFG-006', 'export default { server: { cors: true } }', 'vite.config.mts'),
    ).toHaveLength(1);
  });

  it('ignores safe settings and other files', () => {
    expect(
      only(
        'FG-CFG-006',
        "export default { server: { allowedHosts: ['app.local'] } }",
        'vite.config.ts',
      ),
    ).toEqual([]);
    expect(
      only('FG-CFG-006', 'export default { compilerOptions: { strict: false } }', 'vite.config.ts'),
    ).toEqual([]);
    expect(only('FG-CFG-006', 'app.use(cors({ cors: true }))', 'server.ts')).toEqual([]);
  });
});
