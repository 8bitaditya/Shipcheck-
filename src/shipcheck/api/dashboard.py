"""The single-page dashboard HTML, served at GET /.

Kept deliberately lean (vanilla HTML/CSS/JS, no build step) per the build
plan: the polish goes into the evidence timeline (attack lands -> fix ->
attack fails), which is the demo's key moment.
"""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShipCheck</title>
<style>
  :root {
    --bg:#0b0f17; --panel:#141b26; --panel2:#1b2432; --line:#263142;
    --text:#e6edf3; --muted:#8b98a9; --accent:#4cc2ff; --ok:#3fb950;
    --bad:#f85149; --warn:#d29922;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--line);
    display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; font-weight:650; }
  header .tag { color:var(--muted); font-size:13px; }
  main { max-width:960px; margin:0 auto; padding:24px 16px; }
  .panel { background:var(--panel); border:1px solid var(--line);
    border-radius:12px; padding:16px; margin-bottom:18px; }
  textarea { width:100%; background:var(--bg); color:var(--text);
    border:1px solid var(--line); border-radius:8px; padding:10px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-top:10px; }
  button { background:var(--accent); color:#04121c; border:0; border-radius:8px;
    padding:9px 16px; font-weight:650; cursor:pointer; }
  button.secondary { background:var(--panel2); color:var(--text); border:1px solid var(--line); }
  button:disabled { opacity:.5; cursor:default; }
  .summary { display:flex; gap:20px; flex-wrap:wrap; }
  .stat { background:var(--panel2); border:1px solid var(--line); border-radius:10px;
    padding:12px 16px; min-width:120px; }
  .stat .n { font-size:24px; font-weight:700; }
  .stat .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .finding { border:1px solid var(--line); border-radius:12px; margin-bottom:14px; overflow:hidden; }
  .finding h3 { margin:0; padding:12px 16px; background:var(--panel2);
    display:flex; align-items:center; gap:10px; font-size:15px; }
  .score { font-weight:700; border-radius:999px; padding:3px 10px; font-size:13px; color:#04121c; }
  .finding .body { padding:14px 16px; }
  .kv { color:var(--muted); font-size:13px; }
  .kv code, .excerpt { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .excerpt { display:block; background:var(--bg); border:1px solid var(--line);
    border-radius:8px; padding:10px; margin:8px 0; white-space:pre-wrap; font-size:12.5px; color:#cfe3f2; }
  pre.diff { background:var(--bg); border:1px solid var(--line); border-radius:8px;
    padding:10px; overflow:auto; font-size:12.5px; }
  pre.diff .add { color:var(--ok); } pre.diff .del { color:var(--bad); }
  .timeline { display:flex; gap:8px; align-items:center; margin:12px 0; flex-wrap:wrap; }
  .step { padding:6px 12px; border-radius:999px; border:1px solid var(--line);
    background:var(--panel2); font-size:13px; }
  .step.ok { border-color:var(--ok); color:var(--ok); }
  .step.bad { border-color:var(--bad); color:var(--bad); }
  .arrow { color:var(--muted); }
  .gate { font-weight:650; }
  .gate.pass { color:var(--ok); } .gate.fail { color:var(--bad); }
  a { color:var(--accent); }
  .muted { color:var(--muted); }
  .grounding { border-left:3px solid var(--accent); padding:4px 0 4px 10px; margin:10px 0; }
  .pill { font-size:12px; padding:2px 8px; border-radius:999px; border:1px solid var(--line); color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>🛡️ ShipCheck</h1>
  <span class="tag">Adversarial verification gate — a human always merges</span>
</header>
<main>
  <div class="panel">
    <div class="kv">Paste a PR diff and the changed files (JSON: path → content), or load the recorded demo.</div>
    <div class="row"><textarea id="diff" rows="3" placeholder="diff --git a/app.py b/app.py ..."></textarea></div>
    <div class="row"><textarea id="files" rows="4" placeholder='{ "app.py": "def login(): ..." }'></textarea></div>
    <div class="row">
      <button id="scan">Run scan</button>
      <button id="demo" class="secondary">Load demo</button>
      <span id="status" class="muted"></span>
    </div>
  </div>
  <div id="results"></div>
</main>
<script>
const $ = s => document.querySelector(s);
const esc = s => (s==null?"":String(s)).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl = u => /^https?:\/\/[^\s"'<>`]+$/i.test(u||'') ? u : '#';
function scoreColor(n){ if(n>=70) return '#f85149'; if(n>=40) return '#d29922'; if(n>0) return '#3fb950'; return '#8b98a9'; }

function diffHtml(fix){
  if(!fix || !fix.hunks || !fix.hunks.length) return '<span class="muted">No patch.</span>';
  let out=[];
  for(const h of fix.hunks){
    out.push('--- a/'+esc(h.file)); out.push('+++ b/'+esc(h.file));
    for(const l of (h.search||'').split('\n')) out.push('<span class="del">- '+esc(l)+'</span>');
    for(const l of (h.replace||'').split('\n')) out.push('<span class="add">+ '+esc(l)+'</span>');
  }
  return out.join('\n');
}

function timeline(f){
  const ev=f.evidence, fix=f.fix;
  const landed = ev && ev.marker_found;
  const steps=[`<span class="step ${landed?'ok':''}">1 · Exploit ${landed?'landed ✅':'not confirmed'}</span>`];
  if(fix){
    steps.push('<span class="arrow">→</span>');
    steps.push(`<span class="step ${fix.recheck_attack_marker_absent?'ok':'bad'}">2 · Patched & re-attacked: marker ${fix.recheck_attack_marker_absent?'gone ✅':'still present ❌'}</span>`);
    steps.push('<span class="arrow">→</span>');
    steps.push(`<span class="step ${fix.repo_tests_passed?'ok':'bad'}">3 · Repo tests ${fix.repo_tests_passed?'pass ✅':'fail ❌'}</span>`);
  }
  return '<div class="timeline">'+steps.join('')+'</div>';
}

function groundingHtml(g){
  if(!g) return '';
  const live = g.provider === 'tavily';
  const ids = (g.advisory_ids||[]).map(i=>`<code>${esc(i)}</code>`).join(' ') || '<span class="muted">none found</span>';
  const vers = (g.affected_versions||[]).length ? g.affected_versions.map(v=>`<code>${esc(v)}</code>`).join(' ')
    : '<span class="muted">n/a — first-party code</span>';
  const srcs = (g.sources||[]).map(s=>`<a href="${esc(safeUrl(s.url))}" target="_blank" rel="noopener noreferrer">${esc(s.title)}</a>`).join(' · ');
  return `<div class="grounding">
    <div class="kv"><strong>Advisory grounding</strong> <span class="pill">${live?'Tavily':'offline reference'}</span></div>
    <div class="kv">IDs: ${ids} · affected versions: ${vers}</div>
    <div class="kv">Canonical fix: ${esc(g.canonical_fix||'n/a')}</div>
    ${srcs?`<div class="kv">Sources: ${srcs}</div>`:''}
    ${g.note?`<div class="kv muted">${esc(g.note)}</div>`:''}
  </div>`;
}

function findingCard(f, prs){
  const score = f.verdict ? f.verdict.score : 0;
  const sev = f.severity || (f.verdict && f.verdict.score_breakdown && f.verdict.score_breakdown.severity) || '';
  const ev = f.evidence || {};
  const fix = f.fix;
  const verified = fix && fix.recheck_attack_marker_absent && fix.repo_tests_passed;
  const pr = (prs||[]).find(p => p.finding_id === f.finding_id);
  return `<div class="finding">
    <h3>
      <span class="score" style="background:${scoreColor(score)}">${score}/100</span>
      <span>${esc(f.vuln_class)}</span>
      <span class="muted">· ${esc(f.target && f.target.file)}${f.target&&f.target.endpoint?' ('+esc(f.target.endpoint)+')':''}</span>
      <span class="pill">${esc(sev)}</span>
    </h3>
    <div class="body">
      <div><strong>${esc(f.title||'')}</strong></div>
      ${timeline(f)}
      <div class="kv"><strong>Evidence</strong> — verdict: <code>${esc(ev.verdict||'')}</code></div>
      <div class="kv">Payload: <code>${esc(ev.payload||'')}</code> · marker: <code>${esc(ev.matched_text||ev.target_marker||'')}</code> · status: <code>${esc(ev.response_status||'')}</code></div>
      <span class="excerpt">${esc((ev.response_excerpt||'').slice(0,500))}</span>
      ${groundingHtml(f.grounding)}
      ${fix?`<div class="kv"><strong>Fix</strong> — ${esc(fix.root_cause||'')}</div>
      <pre class="diff">${diffHtml(fix)}</pre>
      <div class="gate ${verified?'pass':'fail'}">${verified?'PASS · draft PR eligible':'NO PASS · no PR (human gate)'}</div>`:''}
      ${pr?`<div class="kv">Draft PR: <a href="${esc(safeUrl(pr.url))}" target="_blank" rel="noopener noreferrer">#${esc(pr.number)}</a></div>`:''}
    </div>
  </div>`;
}

function render(r){
  const findings=(r.findings||[]).slice().sort((a,b)=>((b.verdict?b.verdict.score:0)-(a.verdict?a.verdict.score:0)));
  let html=`<div class="panel summary">
    <div class="stat"><div class="n">${r.overall_risk_score??0}</div><div class="l">Top risk</div></div>
    <div class="stat"><div class="n">${r.findings_count??0}</div><div class="l">Findings</div></div>
    <div class="stat"><div class="n">${r.confirmed_count??0}</div><div class="l">Confirmed</div></div>
    <div class="stat"><div class="n">${r.fixed_count??0}</div><div class="l">Fixed</div></div>
    <div class="stat"><div class="n">${(r.pull_requests||[]).length}</div><div class="l">Draft PRs</div></div>
  </div>`;
  html += findings.length ? findings.map(f=>findingCard(f, r.pull_requests)).join('')
    : '<div class="panel muted">No findings.</div>';
  $('#results').innerHTML = html;
}

async function load(url, opts){
  $('#status').textContent='Scanning…';
  $('#scan').disabled=true; $('#demo').disabled=true;
  try{
    const res=await fetch(url, opts);
    if(!res.ok) throw new Error('HTTP '+res.status);
    render(await res.json());
    const src=res.headers.get('X-ShipCheck-Demo-Source');
    $('#status').textContent = src==='golden' ? 'Replayed a recorded real scan (golden run).'
      : src==='sample' ? 'Showing a hand-built sample (no golden run recorded).' : 'Done.';
  }catch(e){ $('#status').textContent='Error: '+e.message; }
  finally{ $('#scan').disabled=false; $('#demo').disabled=false; }
}

$('#demo').onclick = () => load('/api/demo');
$('#scan').onclick = () => {
  let files={};
  try{ files = $('#files').value.trim() ? JSON.parse($('#files').value) : {}; }
  catch(e){ $('#status').textContent='source files must be valid JSON'; return; }
  load('/scan', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ diff:$('#diff').value, source_files:files })
  });
};
</script>
</body>
</html>
"""
