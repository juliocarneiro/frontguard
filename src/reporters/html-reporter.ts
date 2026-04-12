import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding, Reporter, ScanResult, Severity, ScannerCategory } from '../core/types.js';

export class HtmlReporter implements Reporter {
  name = 'html';

  constructor(private outputDir: string) {}

  async generate(result: ScanResult): Promise<string> {
    await mkdir(this.outputDir, { recursive: true });
    const html = generateHtml(result);
    const filePath = join(this.outputDir, 'frontguard-report.html');
    await writeFile(filePath, html, 'utf-8');
    return filePath;
  }
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function countByCategory(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.category] = (counts[f.category] ?? 0) + 1;
  return counts;
}

function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateHtml(result: ScanResult): string {
  const sevCounts = countBySeverity(result.findings);
  const catCounts = countByCategory(result.findings);
  const total = result.findings.length;
  const categories: ScannerCategory[] = ['xss', 'dependencies', 'secrets', 'misconfig', 'auth-patterns'];
  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  const findingsJson = JSON.stringify(
    result.findings.map((f) => ({
      ...f,
      codeSnippet: f.codeSnippet,
    })),
  );

  const maxCat = Math.max(...Object.values(catCounts), 1);

  const donutSegments = buildDonutSegments(sevCounts, total);
  const barHtml = categories
    .map((cat) => {
      const count = catCounts[cat] ?? 0;
      const pct = maxCat > 0 ? (count / maxCat) * 100 : 0;
      return `<div class="bar-row"><span class="bar-label">${esc(cat)}</span><div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div><span class="bar-value">${count}</span></div>`;
    })
    .join('');

  const findingCardsHtml = result.findings
    .map(
      (f, i) => `
    <div class="finding-card" data-severity="${esc(f.severity)}" data-category="${esc(f.category)}" data-rule="${esc(f.ruleId)}" data-file="${esc(f.file)}" data-index="${i}">
      <div class="finding-header" onclick="toggleFinding(${i})">
        <div class="finding-header-left">
          <span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span>
          ${f.aiAnalyzed ? `<span class="ai-badge" title="AI confidence: ${f.aiConfidence ?? 0}%">AI Verified ${f.aiConfidence ?? 0}%</span>` : ''}
          <span class="finding-rule">${esc(f.ruleId)}</span>
          <span class="finding-title">${esc(f.title)}</span>
        </div>
        <div class="finding-header-right">
          <span class="finding-file">${esc(f.file)}:${f.line}</span>
          <span class="chevron" id="chevron-${i}">&#9662;</span>
        </div>
      </div>
      <div class="finding-body" id="body-${i}">
        <pre class="code-snippet"><code>${esc(f.codeSnippet)}</code></pre>
        <p class="finding-desc">${esc(f.description)}</p>
        <div class="finding-remediation"><strong>Remediation:</strong> ${esc(f.remediation)}</div>
        ${f.cwe || f.owasp ? `<div class="finding-refs">${f.cwe ? `<span class="ref-tag">${esc(f.cwe)}</span>` : ''}${f.owasp ? `<span class="ref-tag">${esc(f.owasp)}</span>` : ''}</div>` : ''}
      </div>
    </div>`,
    )
    .join('');

  const sevCheckboxes = severities
    .map(
      (s) =>
        `<label class="filter-check"><input type="checkbox" checked onchange="applyFilters()" data-sev="${s}"><span class="sev-dot sev-${s}"></span>${s}</label>`,
    )
    .join('');

  const catCheckboxes = categories
    .map(
      (c) =>
        `<label class="filter-check"><input type="checkbox" checked onchange="applyFilters()" data-cat="${c}">${c}</label>`,
    )
    .join('');

  const rulesMap = new Map<string, { title: string; severity: Severity; count: number; category: string }>();
  for (const f of result.findings) {
    const existing = rulesMap.get(f.ruleId);
    if (existing) {
      existing.count++;
    } else {
      rulesMap.set(f.ruleId, { title: f.title, severity: f.severity, count: 1, category: f.category });
    }
  }
  const rulesHtml = [...rulesMap.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .map(
      ([id, r]) =>
        `<tr><td><span class="sev-badge sev-${esc(r.severity)}">${esc(r.severity)}</span></td><td>${esc(id)}</td><td>${esc(r.title)}</td><td>${esc(r.category)}</td><td>${r.count}</td></tr>`,
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FrontGuard Security Report</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--surface:#1e293b;--surface2:#334155;--text:#e2e8f0;--text-muted:#94a3b8;
  --border:#475569;--accent:#6366f1;
  --critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6;--info-color:#6b7280;
  --radius:8px;--shadow:0 1px 3px rgba(0,0,0,.4);
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
}
[data-theme="light"]{
  --bg:#f1f5f9;--surface:#ffffff;--surface2:#e2e8f0;--text:#0f172a;--text-muted:#475569;
  --border:#cbd5e1;--shadow:0 1px 3px rgba(0,0,0,.1);
}
html{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}
body{display:flex;min-height:100vh}

.sidebar{width:220px;background:var(--surface);border-right:1px solid var(--border);padding:1rem 0;position:fixed;top:0;left:0;bottom:0;display:flex;flex-direction:column;z-index:10}
.sidebar-brand{padding:0 1rem 1rem;border-bottom:1px solid var(--border);margin-bottom:.5rem}
.sidebar-brand h1{font-size:1.2rem;font-weight:700;background:linear-gradient(135deg,var(--accent),#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sidebar-brand small{color:var(--text-muted);font-size:.75rem}
.sidebar-nav{flex:1;display:flex;flex-direction:column;gap:2px;padding:0 .5rem}
.sidebar-nav a{display:flex;align-items:center;gap:.5rem;padding:.55rem .75rem;border-radius:var(--radius);color:var(--text-muted);text-decoration:none;font-weight:500;transition:all .15s}
.sidebar-nav a:hover,.sidebar-nav a.active{background:var(--surface2);color:var(--text)}
.sidebar-footer{padding:1rem;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.theme-toggle{background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--radius);padding:.35rem .65rem;cursor:pointer;font-size:.8rem;transition:all .15s}
.theme-toggle:hover{border-color:var(--accent)}

.main{margin-left:220px;flex:1;padding:1.5rem 2rem;max-width:1200px}
.section{display:none}
.section.active{display:block}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow);transition:transform .15s}
.stat-card:hover{transform:translateY(-2px)}
.stat-card .stat-value{font-size:2rem;font-weight:700}
.stat-card .stat-label{color:var(--text-muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.5px}
.stat-card.critical .stat-value{color:var(--critical)}
.stat-card.high .stat-value{color:var(--high)}
.stat-card.medium .stat-value{color:var(--medium)}
.stat-card.low .stat-value{color:var(--low)}
.stat-card.info .stat-value{color:var(--info-color)}

.charts{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:2rem}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;box-shadow:var(--shadow)}
.chart-card h3{font-size:.9rem;margin-bottom:1rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px}
.donut-container{display:flex;align-items:center;justify-content:center;gap:2rem}
.donut-legend{display:flex;flex-direction:column;gap:.4rem}
.donut-legend-item{display:flex;align-items:center;gap:.5rem;font-size:.85rem}
.donut-legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}

.bar-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.6rem}
.bar-label{width:100px;text-align:right;font-size:.85rem;color:var(--text-muted);flex-shrink:0}
.bar-track{flex:1;height:22px;background:var(--surface2);border-radius:4px;overflow:hidden}
.bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),#a78bfa);border-radius:4px;transition:width .5s ease}
.bar-value{width:30px;font-size:.85rem;font-weight:600;flex-shrink:0}

.meta-row{display:flex;gap:2rem;margin-bottom:1rem;color:var(--text-muted);font-size:.85rem;flex-wrap:wrap}
.meta-item strong{color:var(--text)}

.filter-bar{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;margin-bottom:1rem;display:flex;flex-wrap:wrap;gap:1rem;align-items:center;box-shadow:var(--shadow)}
.filter-group{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.filter-group-label{font-size:.75rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:.5px;font-weight:600}
.filter-check{display:flex;align-items:center;gap:.3rem;font-size:.85rem;cursor:pointer;white-space:nowrap}
.filter-check input{accent-color:var(--accent)}
.sev-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.sev-dot.sev-critical{background:var(--critical)}.sev-dot.sev-high{background:var(--high)}.sev-dot.sev-medium{background:var(--medium)}.sev-dot.sev-low{background:var(--low)}.sev-dot.sev-info{background:var(--info-color)}
.search-input{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:.4rem .75rem;color:var(--text);font-size:.85rem;width:200px;transition:border-color .15s}
.search-input:focus{outline:none;border-color:var(--accent)}
.sort-select{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:.4rem .5rem;color:var(--text);font-size:.85rem}
.sort-select:focus{outline:none;border-color:var(--accent)}

.action-bar{display:flex;gap:.5rem;margin-left:auto}
.btn{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:.4rem .75rem;color:var(--text);font-size:.8rem;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn:hover{border-color:var(--accent);background:var(--accent);color:#fff}

.finding-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:.6rem;box-shadow:var(--shadow);overflow:hidden;transition:border-color .15s}
.finding-card:hover{border-color:var(--accent)}
.finding-card.hidden{display:none}
.finding-header{display:flex;justify-content:space-between;align-items:center;padding:.75rem 1rem;cursor:pointer;gap:.5rem;user-select:none}
.finding-header-left{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;min-width:0}
.finding-header-right{display:flex;align-items:center;gap:.75rem;flex-shrink:0}
.finding-file{color:var(--text-muted);font-size:.8rem;font-family:monospace}
.chevron{font-size:.8rem;transition:transform .2s;color:var(--text-muted)}
.chevron.open{transform:rotate(180deg)}
.finding-rule{font-family:monospace;font-size:.8rem;color:var(--text-muted)}
.finding-title{font-weight:600;font-size:.9rem}

.sev-badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#fff}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}.sev-low{background:var(--low)}.sev-info{background:var(--info-color)}
.ai-badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:600;background:linear-gradient(135deg,#6366f1,#a78bfa);color:#fff}

.finding-body{display:none;padding:0 1rem 1rem;border-top:1px solid var(--border)}
.finding-body.open{display:block}
.code-snippet{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:.75rem 1rem;overflow-x:auto;margin:.75rem 0;font-size:.8rem;line-height:1.5}
.code-snippet code{font-family:"Fira Code",Consolas,"Courier New",monospace;color:var(--text)}
.finding-desc{color:var(--text-muted);margin-bottom:.5rem;font-size:.85rem}
.finding-remediation{background:var(--surface2);border-radius:var(--radius);padding:.6rem .75rem;font-size:.85rem;margin-bottom:.5rem}
.finding-refs{display:flex;gap:.5rem;flex-wrap:wrap}
.ref-tag{background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:.1rem .4rem;font-size:.75rem;color:var(--text-muted)}

.count-label{font-size:.8rem;color:var(--text-muted);margin-bottom:1rem}

.rules-table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow)}
.rules-table th{background:var(--surface2);text-align:left;padding:.6rem .75rem;font-size:.75rem;text-transform:uppercase;color:var(--text-muted);letter-spacing:.5px;border-bottom:1px solid var(--border)}
.rules-table td{padding:.6rem .75rem;border-bottom:1px solid var(--border);font-size:.85rem}
.rules-table tr:last-child td{border-bottom:none}
.rules-table tr:hover td{background:var(--surface2)}

@media(max-width:900px){
  .sidebar{width:60px}.sidebar-brand small,.sidebar-nav a span,.sidebar-footer span{display:none}
  .sidebar-brand h1{font-size:.9rem}.sidebar-nav a{justify-content:center;padding:.5rem}
  .main{margin-left:60px;padding:1rem}
  .charts{grid-template-columns:1fr}
  .stat-grid{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}
}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="sidebar-brand">
    <h1>FrontGuard</h1>
    <small>Security Report</small>
  </div>
  <div class="sidebar-nav">
    <a href="#" class="active" onclick="showSection('summary',this);return false"><span>Summary</span></a>
    <a href="#" onclick="showSection('findings',this);return false"><span>Findings</span></a>
    <a href="#" onclick="showSection('rules',this);return false"><span>Rules</span></a>
  </div>
  <div class="sidebar-footer">
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">Toggle Theme</button>
  </div>
</nav>

<main class="main">

<section id="section-summary" class="section active">
  <h2 style="margin-bottom:1rem">Summary</h2>
  <div class="meta-row">
    <span class="meta-item"><strong>${result.scannedFiles}</strong> files scanned</span>
    <span class="meta-item"><strong>${(result.scanDuration / 1000).toFixed(2)}s</strong> duration</span>
    <span class="meta-item">${esc(result.timestamp)}</span>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-value">${total}</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card critical"><div class="stat-value">${sevCounts.critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card high"><div class="stat-value">${sevCounts.high}</div><div class="stat-label">High</div></div>
    <div class="stat-card medium"><div class="stat-value">${sevCounts.medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card low"><div class="stat-value">${sevCounts.low}</div><div class="stat-label">Low</div></div>
  </div>

  <div class="charts">
    <div class="chart-card">
      <h3>By Severity</h3>
      <div class="donut-container">
        <svg viewBox="0 0 36 36" width="140" height="140">${donutSegments.svg}</svg>
        <div class="donut-legend">
          ${donutSegments.legend}
        </div>
      </div>
    </div>
    <div class="chart-card">
      <h3>By Category</h3>
      ${barHtml}
    </div>
  </div>
</section>

<section id="section-findings" class="section">
  <h2 style="margin-bottom:1rem">Findings</h2>
  <div class="filter-bar">
    <div class="filter-group">
      <span class="filter-group-label">Severity</span>
      ${sevCheckboxes}
    </div>
    <div class="filter-group">
      <span class="filter-group-label">Category</span>
      ${catCheckboxes}
    </div>
    <input type="text" class="search-input" id="search" placeholder="Search..." oninput="applyFilters()">
    <select class="sort-select" id="sort-by" onchange="sortFindings()">
      <option value="severity">Sort: Severity</option>
      <option value="file">Sort: File</option>
      <option value="rule">Sort: Rule</option>
    </select>
    <div class="action-bar">
      <button class="btn" onclick="exportCsv()">Export CSV</button>
    </div>
  </div>
  <div class="count-label" id="findings-count">${total} findings</div>
  <div id="findings-list">
    ${findingCardsHtml}
  </div>
</section>

<section id="section-rules" class="section">
  <h2 style="margin-bottom:1rem">Rules Triggered</h2>
  <table class="rules-table">
    <thead><tr><th>Severity</th><th>Rule ID</th><th>Title</th><th>Category</th><th>Count</th></tr></thead>
    <tbody>${rulesHtml}</tbody>
  </table>
</section>

</main>

<script>
(function(){
  var FINDINGS = ${findingsJson};
  var SEV_ORDER = {critical:0,high:1,medium:2,low:3,info:4};

  var savedTheme = localStorage.getItem('fg-theme');
  if(savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);

  window.toggleTheme = function(){
    var cur = document.documentElement.getAttribute('data-theme');
    var next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('fg-theme', next);
  };

  window.showSection = function(id, el){
    document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active')});
    document.getElementById('section-' + id).classList.add('active');
    document.querySelectorAll('.sidebar-nav a').forEach(function(a){a.classList.remove('active')});
    if(el) el.classList.add('active');
  };

  window.toggleFinding = function(i){
    var body = document.getElementById('body-' + i);
    var chev = document.getElementById('chevron-' + i);
    if(body){
      body.classList.toggle('open');
      chev.classList.toggle('open');
    }
  };

  window.applyFilters = function(){
    var sevs = [];
    document.querySelectorAll('[data-sev]').forEach(function(cb){ if(cb.checked) sevs.push(cb.getAttribute('data-sev')); });
    var cats = [];
    document.querySelectorAll('[data-cat]').forEach(function(cb){ if(cb.checked) cats.push(cb.getAttribute('data-cat')); });
    var q = (document.getElementById('search').value || '').toLowerCase();
    var visible = 0;
    document.querySelectorAll('.finding-card').forEach(function(card){
      var s = card.getAttribute('data-severity');
      var c = card.getAttribute('data-category');
      var matchSev = sevs.indexOf(s) !== -1;
      var matchCat = cats.indexOf(c) !== -1;
      var text = card.textContent.toLowerCase();
      var matchSearch = !q || text.indexOf(q) !== -1;
      if(matchSev && matchCat && matchSearch){
        card.classList.remove('hidden');
        visible++;
      } else {
        card.classList.add('hidden');
      }
    });
    document.getElementById('findings-count').textContent = visible + ' finding' + (visible !== 1 ? 's' : '');
  };

  window.sortFindings = function(){
    var by = document.getElementById('sort-by').value;
    var list = document.getElementById('findings-list');
    var cards = Array.from(list.querySelectorAll('.finding-card'));
    cards.sort(function(a, b){
      if(by === 'severity'){
        return (SEV_ORDER[a.getAttribute('data-severity')] || 0) - (SEV_ORDER[b.getAttribute('data-severity')] || 0);
      } else if(by === 'file'){
        return (a.getAttribute('data-file') || '').localeCompare(b.getAttribute('data-file') || '');
      } else {
        return (a.getAttribute('data-rule') || '').localeCompare(b.getAttribute('data-rule') || '');
      }
    });
    cards.forEach(function(c){ list.appendChild(c); });
  };

  window.exportCsv = function(){
    var header = ['severity','category','ruleId','title','file','line','column','description','remediation','cwe','owasp'];
    var rows = [header.join(',')];
    FINDINGS.forEach(function(f){
      rows.push(header.map(function(h){ return '"' + String(f[h] || '').replace(/"/g, '""') + '"'; }).join(','));
    });
    var blob = new Blob([rows.join('\\n')], {type:'text/csv'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'frontguard-findings.csv';
    a.click();
    URL.revokeObjectURL(a.href);
  };
})();
</script>
</body>
</html>`;
}

function buildDonutSegments(
  counts: Record<Severity, number>,
  total: number,
): { svg: string; legend: string } {
  const colors: Record<Severity, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#6b7280',
  };
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

  if (total === 0) {
    return {
      svg: '<circle cx="18" cy="18" r="15.9" fill="none" stroke="#334155" stroke-width="3"/>',
      legend: '<div class="donut-legend-item" style="color:var(--text-muted)">No findings</div>',
    };
  }

  let offset = 0;
  let svgParts = '';
  let legendParts = '';
  const circumference = 100;

  for (const sev of order) {
    const count = counts[sev];
    if (count === 0) continue;
    const pct = (count / total) * circumference;
    svgParts += `<circle cx="18" cy="18" r="15.9" fill="none" stroke="${colors[sev]}" stroke-width="3" stroke-dasharray="${pct} ${circumference - pct}" stroke-dashoffset="${-offset}" transform="rotate(-90 18 18)"/>`;
    offset += pct;
    legendParts += `<div class="donut-legend-item"><span class="donut-legend-dot" style="background:${colors[sev]}"></span>${sev}: ${count}</div>`;
  }

  return { svg: svgParts, legend: legendParts };
}
