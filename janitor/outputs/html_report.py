"""Self-contained HTML Security Report Generator."""

import json
import html
from pathlib import Path
from typing import Dict, Any, List, Tuple


def generate_html_report(result: Dict[str, Any], output_path: str = "security_report.html") -> str:
    findings = result.get('findings', [])
    score, grade = _calculate_score(result)
    html_content = _build_html(result, findings, score, grade)
    output = Path(output_path)
    output.write_text(html_content, encoding='utf-8')
    return str(output.resolve())


def _calculate_score(result: Dict[str, Any]) -> Tuple[int, str]:
    critical = result.get('critical', 0)
    high = result.get('high', 0)
    medium = result.get('medium', 0)
    low = result.get('low', 0)

    score = 100 - (critical * 15) - (high * 8) - (medium * 4) - (low * 1)
    score = max(0, min(100, score))

    if score >= 90:
        grade = 'A'
    elif score >= 75:
        grade = 'B'
    elif score >= 55:
        grade = 'C'
    elif score >= 30:
        grade = 'D'
    else:
        grade = 'F'

    return score, grade


def _grade_color(grade: str) -> str:
    return {'A': '#22c55e', 'B': '#84cc16', 'C': '#eab308', 'D': '#f97316', 'F': '#ef4444'}.get(grade, '#6b7280')


def _build_html(result: Dict[str, Any], findings: List[Dict[str, Any]], score: int, grade: str) -> str:
    root_path = html.escape(result.get('root_path', ''))
    timestamp = html.escape(result.get('timestamp', ''))
    files_scanned = result.get('files_scanned', 0)
    total_analyzed = result.get('total_files_analyzed', 0)
    critical = result.get('critical', 0)
    high = result.get('high', 0)
    medium = result.get('medium', 0)
    low = result.get('low', 0)
    total = result.get('total_issues', 0)
    grade_col = _grade_color(grade)
    lang_dist = result.get('language_distribution', {})
    deps = result.get('dependency_scan')
    findings_json = json.dumps(findings)

    lang_rows_builder = []
    for k, v in sorted(lang_dist.items(), key=lambda x: x[1], reverse=True):
        lang_rows_builder.append(f"<tr><td>{html.escape(k)}</td><td>{v:.1f}%</td></tr>")
    lang_rows = '\n'.join(lang_rows_builder)

    deps_section = ""
    if deps:
        deps_section = f"""<section class="section"><h2>Dependency Vulnerabilities</h2>
<div class="deps">
<div class="dep"><span class="n">{deps.get('vulnerabilities_found', 0)}</span><span class="l">Vulnerabilities</span></div>
<div class="dep"><span class="n">{deps.get('dependencies_tracked', 0)}</span><span class="l">Dependencies</span></div>
<div class="dep"><span class="n">{deps.get('ecosystems', 1)}</span><span class="l">Ecosystems</span></div>
</div></section>"""

    score_grade = f'<span class="grade-letter">{grade}</span><span class="grade-score">{score}/100</span>'

    page = _HTML_TEMPLATE.replace('__ROOT_PATH__', root_path)
    page = page.replace('__TIMESTAMP__', timestamp)
    page = page.replace('__FILES_SCANNED__', str(files_scanned))
    page = page.replace('__FILES_ANALYZED__', str(total_analyzed))
    page = page.replace('__CRITICAL__', str(critical))
    page = page.replace('__HIGH__', str(high))
    page = page.replace('__MEDIUM__', str(medium))
    page = page.replace('__LOW__', str(low))
    page = page.replace('__TOTAL__', str(total))
    page = page.replace('__GRADE_COL__', grade_col)
    page = page.replace('__SCORE_GRADE__', score_grade)
    page = page.replace('__LANG_COUNT__', str(len(lang_dist)))
    page = page.replace('__LANG_ROWS__', lang_rows)
    page = page.replace('__DEPS_SECTION__', deps_section)
    page = page.replace('__FINDINGS_JSON__', findings_json)

    return page


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report - repo-janitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
:root { --bg:#0f172a; --bg2:#1e293b; --bg3:#334155; --text:#f1f5f9; --text2:#94a3b8; --border:#334155; --accent:#3b82f6; --radius:8px; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }
.container { max-width:1200px; margin:0 auto; padding:20px; }
header { background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%); padding:30px 20px; border-bottom:1px solid var(--border); }
.header-inner { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; max-width:1200px; margin:0 auto; }
header h1 { font-size:1.8rem; }
header .sub { color:var(--text2); font-size:0.9rem; }
.grade { display:inline-flex; flex-direction:column; align-items:center; padding:15px 25px; border-radius:12px; color:#fff; min-width:100px; background:__GRADE_COL__; }
.grade-letter { font-size:2.5rem; font-weight:800; line-height:1; }
.grade-score { font-size:0.8rem; opacity:0.9; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:16px; margin:24px 0; }
.card { background:var(--bg2); border-radius:var(--radius); padding:20px; text-align:center; border:1px solid var(--border); }
.card .num { font-size:2rem; font-weight:700; }
.card .lbl { font-size:0.85rem; color:var(--text2); margin-top:4px; }
.cr .num { color:#ef4444; } .hi .num { color:#f97316; } .md .num { color:#eab308; } .lo .num { color:#22c55e; } .to .num { color:var(--accent); }
.charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:20px; margin:24px 0; }
.chart-box { background:var(--bg2); border-radius:var(--radius); padding:20px; border:1px solid var(--border); }
.chart-box h3 { font-size:0.9rem; margin-bottom:12px; color:var(--text2); text-transform:uppercase; letter-spacing:0.5px; }
.section { margin:24px 0; }
.section h2 { font-size:1.2rem; margin-bottom:16px; }
table { width:100%; border-collapse:collapse; font-size:0.9rem; }
th,td { padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }
th { color:var(--text2); font-weight:600; text-transform:uppercase; font-size:0.75rem; letter-spacing:0.5px; cursor:pointer; user-select:none; }
.controls { display:flex; gap:12px; margin-bottom:16px; flex-wrap:wrap; }
.controls input,.controls select { background:var(--bg3); color:var(--text); border:1px solid var(--border); padding:8px 14px; border-radius:6px; font-size:0.9rem; outline:none; }
.controls input { flex:1; min-width:200px; }
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; text-transform:uppercase; color:#fff; }
.bc { background:#ef4444; } .bh { background:#f97316; } .bm { background:#eab308; color:#1e293b; } .bl { background:#22c55e; }
.exp { cursor:pointer; color:var(--accent); font-size:0.8rem; }
.dr { display:none; }
.dr.sh { display:table-row; }
.dc { background:var(--bg3) !important; padding:16px 20px !important; }
.dc pre { background:#0f172a; padding:12px; border-radius:4px; overflow-x:auto; font-size:0.8rem; margin:8px 0; font-family:'JetBrains Mono','Fira Code',monospace; white-space:pre-wrap; }
.dc .fx { color:#22c55e; margin-top:8px; font-size:0.85rem; }
.dc .mt { color:var(--text2); font-size:0.8rem; margin-bottom:4px; }
.deps { display:flex; gap:16px; flex-wrap:wrap; }
.dep { background:var(--bg2); border:1px solid var(--border); border-radius:var(--radius); padding:20px; text-align:center; flex:1; min-width:120px; }
.dep .n { display:block; font-size:1.8rem; font-weight:700; color:var(--accent); }
.dep .l { font-size:0.8rem; color:var(--text2); }
.empty { text-align:center; padding:60px 20px; }
.empty h3 { color:var(--text); margin-bottom:8px; }
.empty p { color:var(--text2); }
footer { text-align:center; padding:24px; color:var(--text2); font-size:0.8rem; border-top:1px solid var(--border); margin-top:40px; }
@media (max-width:640px) { .header-inner { flex-direction:column; } .cards { grid-template-columns:repeat(2,1fr); } .charts { grid-template-columns:1fr; } }
</style>
</head>
<body>
<header>
<div class="header-inner">
<div><h1>repo-janitor Security Report</h1><div class="sub">__ROOT_PATH__ &middot; __TIMESTAMP__</div></div>
<div class="grade">__SCORE_GRADE__</div>
</div>
</header>
<div class="container">

<div class="cards">
<div class="card to"><div class="num">__TOTAL__</div><div class="lbl">Total Issues</div></div>
<div class="card cr"><div class="num">__CRITICAL__</div><div class="lbl">Critical</div></div>
<div class="card hi"><div class="num">__HIGH__</div><div class="lbl">High</div></div>
<div class="card md"><div class="num">__MEDIUM__</div><div class="lbl">Medium</div></div>
<div class="card lo"><div class="num">__LOW__</div><div class="lbl">Low</div></div>
</div>

<div class="section">
<h2>Overview</h2>
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Files Scanned</td><td>__FILES_SCANNED__</td></tr>
<tr><td>Files Analyzed</td><td>__FILES_ANALYZED__</td></tr>
<tr><td>Languages Detected</td><td>__LANG_COUNT__</td></tr>
<tr><td>Security Score</td><td><strong style="color:__GRADE_COL__">__SCORE_GRADE__</strong></td></tr>
</table>
</div>

<div class="section">
<h2>Language Distribution</h2>
<table><tr><th>Language</th><th>Percentage</th></tr>
__LANG_ROWS__
</table>
</div>

<div class="charts">
<div class="chart-box"><h3>Severity Distribution</h3><canvas id="cSeverity"></canvas></div>
<div class="chart-box"><h3>Issues by Language</h3><canvas id="cLang"></canvas></div>
<div class="chart-box"><h3>Top Files</h3><canvas id="cFiles"></canvas></div>
</div>

__DEPS_SECTION__

<div class="section">
<h2>Findings</h2>
<div class="controls">
<input type="text" id="searchInput" placeholder="Search files, issues, messages..." oninput="render()">
<select id="severityFilter" onchange="render()">
<option value="all">All Severities</option>
<option value="critical">Critical</option><option value="high">High</option>
<option value="medium">Medium</option><option value="low">Low</option>
</select>
</div>
<div style="overflow-x:auto">
<table>
<thead><tr><th onclick="sort('file')">File</th><th onclick="sort('line')">Line</th><th onclick="sort('risk_level')">Severity</th><th onclick="sort('issue_type')">Issue</th><th>Details</th></tr></thead>
<tbody id="tbody"></tbody>
</table>
</div>
<div id="empty" class="empty" style="display:none"><h3>No findings match your filter</h3><p>Try adjusting search or severity.</p></div>
<div id="noneFindings" class="empty" style="display:none"><h3>No issues found</h3><p>Your codebase looks clean!</p></div>
</div>

</div>
<footer>repo-janitor v0.1.0 &middot; __TIMESTAMP__</footer>

<script>
var DATA = __FINDINGS_JSON__;
var sortField = null, sortAsc = true;

function esc(s) { if(!s)return''; var d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }

function sevW(s) { return {'critical':0,'high':1,'medium':2,'low':3}[(s||'').toLowerCase()]||99; }

function render() {
    var q = document.getElementById('searchInput').value.toLowerCase();
    var sf = document.getElementById('severityFilter').value;
    var tb = document.getElementById('tbody');
    var em = document.getElementById('empty');
    var nn = document.getElementById('noneFindings');

    var f = DATA.filter(function(x) {
        if(sf!=='all' && x.risk_level!==sf) return false;
        if(q) { var t=(x.file+' '+x.issue_type+' '+x.message+' '+(x.suggestion||'')).toLowerCase(); if(t.indexOf(q)===-1) return false; }
        return true;
    });

    if(sortField) {
        f.sort(function(a,b) {
            var va=a[sortField], vb=b[sortField];
            if(sortField==='line') { va=Number(va); vb=Number(vb); }
            else if(sortField==='risk_level') { va=sevW(va); vb=sevW(vb); }
            else { va=String(va).toLowerCase(); vb=String(vb).toLowerCase(); }
            return va<vb ? (sortAsc?-1:1) : (va>vb ? (sortAsc?1:-1) : 0);
        });
    }

    if(DATA.length===0) { nn.style.display='block'; em.style.display='none'; tb.innerHTML=''; return; }
    if(f.length===0) { em.style.display='block'; nn.style.display='none'; tb.innerHTML='<tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text2)">No matches.</td></tr>'; return; }
    em.style.display='none'; nn.style.display='none';

    var h = '';
    for(var i=0;i<f.length;i++) {
        var x=f[i];
        var sb = 'badge bc'; if(x.risk_level==='high') sb='badge bh'; else if(x.risk_level==='medium') sb='badge bm'; else if(x.risk_level==='low') sb='badge bl';
        var ic = '&#128308;'; if(x.risk_level==='high') ic='&#128992;'; else if(x.risk_level==='medium') ic='&#128993;'; else if(x.risk_level==='low') ic='&#128994;';
        var snip = x.code_snippet ? esc(x.code_snippet) : '';
        var sug = x.suggestion ? esc(x.suggestion) : '';
        h += '<tr><td>'+esc(x.file)+'</td><td>'+(x.line||'-')+'</td>';
        h += '<td><span class="'+sb+'">'+ic+' '+esc(x.risk_level)+'</span></td>';
        h += '<td>'+esc(x.issue_type)+'</td>';
        h += '<td><span class="exp" onclick="tog(this)">Show details</span></td></tr>';
        h += '<tr class="dr" id="d'+i+'"><td colspan="5" class="dc">';
        h += '<div class="mt"><strong>Message:</strong> '+esc(x.message)+'</div>';
        if(snip) h += '<pre>'+snip+'</pre>';
        if(sug) h += '<div class="fx"><strong>Fix:</strong> '+sug+'</div>';
        h += '</td></tr>';
    }
    tb.innerHTML = h;
}

function tog(el) {
    var r = el.parentNode.parentNode.nextElementSibling;
    if(r && r.classList.contains('dr')) {
        r.classList.toggle('sh');
        el.textContent = r.classList.contains('sh') ? 'Hide details' : 'Show details';
    }
}

function sort(field) {
    if(sortField===field) sortAsc=!sortAsc; else { sortField=field; sortAsc=true; }
    render();
}

function chartSev() {
    var c = {critical:0,high:0,medium:0,low:0};
    DATA.forEach(function(x) { var s=(x.risk_level||'').toLowerCase(); if(s in c) c[s]++; });
    return { labels:Object.keys(c), values:Object.values(c), colors:['#ef4444','#f97316','#eab308','#22c55e'] };
}

function chartLang() {
    var d = {};
    DATA.forEach(function(x) { if(x.file) { var e=x.file.split('.').pop(); d[e]=(d[e]||0)+1; } });
    var s = Object.entries(d).sort(function(a,b){return b[1]-a[1];});
    return { labels:s.map(function(x){return '.'+x[0];}), values:s.map(function(x){return x[1];}) };
}

function chartFiles() {
    var d = {};
    DATA.forEach(function(x) { if(x.file) { var n=x.file.split(/[/\\\\]/).pop(); d[n]=(d[n]||0)+1; } });
    var s = Object.entries(d).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
    return { labels:s.map(function(x){return x[0];}), values:s.map(function(x){return x[1];}) };
}

document.addEventListener('DOMContentLoaded',function() {
    render();

    var s=chartSev();
    new Chart(document.getElementById('cSeverity'),{type:'doughnut',data:{labels:s.labels,datasets:[{data:s.values,backgroundColor:s.colors,borderWidth:0}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:'#94a3b8'}}}}});

    var l=chartLang();
    if(l.labels.length) new Chart(document.getElementById('cLang'),{type:'bar',data:{labels:l.labels,datasets:[{label:'Issues',data:l.values,backgroundColor:'#3b82f6',borderRadius:4}]},options:{responsive:true,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}});

    var f=chartFiles();
    if(f.labels.length) new Chart(document.getElementById('cFiles'),{type:'bar',data:{labels:f.labels,datasets:[{label:'Issues',data:f.values,backgroundColor:'#8b5cf6',borderRadius:4}]},options:{responsive:true,indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#94a3b8'}},y:{ticks:{color:'#94a3b8'}}}}});
});
</script>
</body>
</html>"""
