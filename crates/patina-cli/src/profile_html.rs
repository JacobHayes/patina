//! Self-contained, zero-CDN interactive HTML dashboards for `patina profile --format html`
//! and `patina profile --serve`.
//!
//! Renders BOTH:
//! - Single-run dashboard: 4-bucket attribution cards & breakdown bar, interactive Canvas
//!   virtual-time swimlane timeline (zoom/pan/search/filter/hover), interactive click-to-zoom
//!   CPU flamegraph, SVG memory (`mmap`/`brk`) timeline chart, virtual tail-latency (p50/p95/p99)
//!   chart & table, edge-coverage summary, and embedded one-click Perfetto/Profile JSON downloads.
//! - Sweep / campaign dashboard: outcome breakdown, grouped findings with copyable `patina replay`
//!   and `patina run` commands, per-seed distribution charts, and searchable/sortable seed table.

/// Safely escape embedded JSON for placement inside a `<script type="application/json">` tag
/// so `</script>` or HTML comments inside guest paths/args can never break the document.
fn safe_json_embed(json: &str) -> String {
    json.replace("</", "<\\/").replace("<!--", "<\\!--")
}

const SHARED_CSS: &str = r#"
:root {
  --bg: #0b0f17;
  --surface: #121826;
  --surface2: #192234;
  --border: #263248;
  --text: #e6edf7;
  --muted: #8b9bb4;
  --accent: #38bdf8;
  --ok: #22c55e;
  --warn: #f59e0b;
  --bad: #ef4444;
  --purple: #a78bfa;
  --pink: #f472b6;
  --teal: #2dd4bf;
  --orange: #fb923c;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  --sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
html[data-theme="light"] {
  --bg: #f4f6fa;
  --surface: #ffffff;
  --surface2: #eef2f8;
  --border: #d5deeb;
  --text: #0f172a;
  --muted: #52627a;
  --accent: #0284c7;
  --ok: #16a34a;
  --warn: #d97706;
  --bad: #dc2626;
  --purple: #7c3aed;
  --pink: #db2777;
  --teal: #0d9488;
  --orange: #ea580c;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--text);
  font-family: var(--sans); font-size: 14px; line-height: 1.5;
}
.wrap { max-width: 1440px; margin: 0 auto; padding: 20px 24px 64px; }
header {
  display: flex; flex-wrap: wrap; justify-content: space-between; align-items: flex-start;
  gap: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--border); margin-bottom: 20px;
}
.title-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
h1 { margin: 0; font-size: 20px; font-weight: 700; letter-spacing: -0.02em; }
.meta { color: var(--muted); font-family: var(--mono); font-size: 12px; margin-top: 6px; word-break: break-all; }
.badge {
  display: inline-flex; align-items: center; padding: 2px 9px; border-radius: 999px;
  font-size: 12px; font-weight: 600; font-family: var(--mono); text-transform: uppercase;
}
.badge.ok { background: rgba(34,197,94,.16); color: var(--ok); border: 1px solid rgba(34,197,94,.35); }
.badge.bad { background: rgba(239,68,68,.16); color: var(--bad); border: 1px solid rgba(239,68,68,.35); }
.badge.warn { background: rgba(245,158,11,.16); color: var(--warn); border: 1px solid rgba(245,158,11,.35); }
.badge.info { background: rgba(56,189,248,.14); color: var(--accent); border: 1px solid rgba(56,189,248,.35); }
.actions { display: flex; gap: 8px; flex-wrap: wrap; }
button, .btn {
  background: var(--surface2); color: var(--text); border: 1px solid var(--border);
  border-radius: 7px; padding: 6px 12px; font-size: 12.5px; font-weight: 500;
  cursor: pointer; transition: background .12s, border-color .12s;
}
button:hover, .btn:hover { border-color: var(--accent); background: var(--surface); }
button.primary { background: var(--accent); color: #04131c; border-color: transparent; font-weight: 600; }
button.primary:hover { opacity: 0.92; }
.grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; margin-bottom: 18px; }
.grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap: 16px; margin-bottom: 18px; }
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 16px 18px; margin-bottom: 16px;
}
.grid-4 .card, .grid-2 .card { margin-bottom: 0; }
.card h2 {
  margin: 0 0 12px 0; font-size: 14px; font-weight: 600;
  display: flex; justify-content: space-between; align-items: center; gap: 8px;
}
.card-kicker {
  font-size: 11px; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); font-weight: 600; margin-bottom: 4px;
}
.metric { font-size: 26px; font-weight: 700; font-family: var(--mono); letter-spacing: -0.02em; }
.sub { font-size: 12px; color: var(--muted); margin-top: 6px; font-family: var(--mono); }
.stack-bar {
  display: flex; height: 14px; border-radius: 7px; overflow: hidden;
  background: var(--surface2); border: 1px solid var(--border); margin: 10px 0 8px;
}
.legend { display: flex; flex-wrap: wrap; gap: 12px; font-size: 12px; color: var(--muted); }
.legend-item { display: inline-flex; align-items: center; gap: 6px; }
.swatch { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }
.toolbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px;
}
input[type="text"], select {
  background: var(--surface2); color: var(--text); border: 1px solid var(--border);
  border-radius: 6px; padding: 5px 10px; font-size: 12.5px; font-family: var(--mono);
}
input[type="text"]:focus, select:focus { outline: none; border-color: var(--accent); }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td {
  text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--border);
  font-family: var(--mono);
}
th { color: var(--muted); font-weight: 600; font-size: 11.5px; text-transform: uppercase; letter-spacing: .04em; cursor: pointer; user-select: none; }
tr:hover td { background: rgba(56,189,248,.05); }
.num { text-align: right; }
.canvas-box {
  position: relative; width: 100%; overflow: hidden;
  border: 1px solid var(--border); border-radius: 8px; background: var(--bg);
}
canvas { display: block; width: 100%; }
.tooltip {
  position: fixed; pointer-events: none; z-index: 9999; display: none;
  background: rgba(11,15,23,.96); color: #e6edf7; border: 1px solid #38bdf8;
  border-radius: 7px; padding: 8px 10px; font-family: var(--mono); font-size: 12px;
  max-width: 440px; box-shadow: 0 8px 24px rgba(0,0,0,.4); white-space: pre-wrap;
}
.cmd-box {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  background: var(--surface2); border: 1px solid var(--border); border-radius: 6px;
  padding: 6px 10px; font-family: var(--mono); font-size: 12px; margin-top: 6px;
  overflow-x: auto;
}
.cmd-box code { white-space: nowrap; }
.hint {
  background: var(--surface2); border: 1px dashed var(--border); border-radius: 8px;
  padding: 14px; color: var(--muted); font-size: 13px;
}
.pill-list { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.pill {
  background: var(--surface2); border: 1px solid var(--border); border-radius: 5px;
  padding: 2px 7px; font-family: var(--mono); font-size: 11px; color: var(--muted);
}
"#;

const THEME_JS: &str = r#"
(function(){
  const saved = localStorage.getItem('patina-theme');
  const pref = saved || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  document.documentElement.setAttribute('data-theme', pref);
  window.toggleTheme = function(){
    const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', cur);
    localStorage.setItem('patina-theme', cur);
    if (window._patinaRedraw) window._patinaRedraw();
  };
  window.downloadBlob = function(filename, text, mime){
    const blob = new Blob([text], {type: mime || 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 250);
  };
  window.copyText = function(btn, txt){
    navigator.clipboard.writeText(txt).then(()=>{
      const old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(()=> btn.textContent = old, 1100);
    }).catch(()=>{});
  };
})();
"#;

/// Render the self-contained single-run interactive HTML dashboard.
pub fn render_run_html(profile_json: &str, trace_json: &str) -> String {
    let safe_profile = safe_json_embed(profile_json);
    let safe_trace = safe_json_embed(trace_json);

    r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Patina Deterministic Guest Profile</title>
<style>__SHARED_CSS__</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="title-row">
        <h1>Patina Deterministic Guest Profile</h1>
        <span id="hdr-badge" class="badge info">run</span>
      </div>
      <div id="hdr-meta" class="meta"></div>
    </div>
    <div class="actions">
      <button class="primary" onclick="downloadTrace()">Download Perfetto Trace JSON</button>
      <button onclick="downloadProfile()">Download Profile JSON</button>
      <button onclick="toggleTheme()">Toggle Theme</button>
    </div>
  </header>

  <div class="grid-4" id="bucket-cards"></div>

  <div class="card">
    <h2>Modeled Virtual Time Attribution <span id="vtime-total" class="sub"></span></h2>
    <div id="vtime-bar" class="stack-bar"></div>
    <div id="vtime-legend" class="legend"></div>
  </div>

  <div class="card">
    <h2>Interactive Virtual-Time Swimlane Timeline <span id="tl-stats" class="sub"></span></h2>
    <div class="toolbar">
      <input type="text" id="tl-search" placeholder="Filter syscall / path / fault..." oninput="redrawTimeline()">
      <select id="tl-cat" onchange="redrawTimeline()">
        <option value="">All categories</option>
        <option value="io">io</option>
        <option value="fsync">fsync</option>
        <option value="futex">futex</option>
        <option value="net">net</option>
        <option value="sleep">sleep</option>
        <option value="memory">memory</option>
        <option value="compute">compute</option>
        <option value="fault">fault</option>
        <option value="other">other</option>
      </select>
      <button onclick="zoomTimeline(0.6)">Zoom In</button>
      <button onclick="zoomTimeline(1.6)">Zoom Out</button>
      <button onclick="resetTimeline()">Reset View</button>
      <span class="sub">Scroll to zoom &middot; drag to pan &middot; hover for details</span>
    </div>
    <div class="canvas-box">
      <canvas id="tl-canvas" height="260"></canvas>
    </div>
  </div>

  <div class="card">
    <h2>Deterministic Compute-Point CPU Flamegraph <span id="fg-stats" class="sub"></span></h2>
    <div id="fg-controls" class="toolbar" style="display:none">
      <input type="text" id="fg-search" placeholder="Search symbol..." oninput="redrawFlame()">
      <button onclick="resetFlame()">Reset Zoom</button>
      <span id="fg-match" class="sub"></span>
    </div>
    <div id="fg-wrap"></div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Memory Timeline (mmap / munmap / mremap / brk) <span id="mem-stats" class="sub"></span></h2>
      <div id="mem-chart"></div>
      <div id="mem-table-wrap" style="margin-top:12px"></div>
    </div>
    <div class="card">
      <h2>Virtual Tail Latency (p50 / p95 / p99 / max)</h2>
      <div id="lat-chart"></div>
      <div id="lat-table-wrap" style="margin-top:12px"></div>
    </div>
  </div>

  <div class="card" id="cov-card" style="display:none">
    <h2>Black-Box ELF Edge Coverage <span id="cov-stats" class="sub"></span></h2>
    <div id="cov-body"></div>
  </div>

  <div class="card">
    <h2>Top Syscalls &amp; Logical I/O Breakdown</h2>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>Syscall</th><th>Category</th><th class="num">Calls</th><th class="num">Errors</th>
            <th class="num">Bytes</th><th class="num">Total vTime</th>
            <th class="num">p50</th><th class="num">p95</th><th class="num">p99</th><th class="num">max</th>
          </tr>
        </thead>
        <tbody id="sc-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<div id="tooltip" class="tooltip"></div>

<script id="patina-profile-data" type="application/json">__SAFE_PROFILE__</script>
<script id="patina-trace-data" type="application/json">__SAFE_TRACE__</script>
<script>__THEME_JS__</script>
<script>
const P = JSON.parse(document.getElementById('patina-profile-data').textContent);
const T_RAW = document.getElementById('patina-trace-data').textContent;
const tip = document.getElementById('tooltip');

function downloadProfile(){ downloadBlob('patina-profile-seed-' + P.seed + '.json', JSON.stringify(P, null, 2)); }
function downloadTrace(){ downloadBlob('patina-trace-seed-' + P.seed + '.json', T_RAW); }

function fmtNs(ns){
  if (ns >= 1e9) return (ns/1e9).toFixed(3) + ' s';
  if (ns >= 1e6) return (ns/1e6).toFixed(2) + ' ms';
  if (ns >= 1e3) return (ns/1e3).toFixed(1) + ' µs';
  return Math.round(ns) + ' ns';
}
function fmtUs(us){ return fmtNs(us * 1000); }
function fmtBytes(b){
  const u = ['B','KiB','MiB','GiB','TiB'];
  let v = b, i = 0;
  while (v >= 1024 && i < u.length - 1){ v /= 1024; i++; }
  return i === 0 ? (b + ' B') : (v.toFixed(1) + ' ' + u[i]);
}
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function showTip(e, text){
  tip.textContent = text;
  tip.style.display = 'block';
  const x = Math.min(window.innerWidth - tip.offsetWidth - 12, e.clientX + 14);
  const y = Math.min(window.innerHeight - tip.offsetHeight - 12, e.clientY + 14);
  tip.style.left = Math.max(8, x) + 'px';
  tip.style.top = Math.max(8, y) + 'px';
}
function hideTip(){ tip.style.display = 'none'; }

const CAT_COLORS = {
  compute: '#38bdf8', io: '#22c55e', fsync: '#f59e0b', futex: '#a78bfa',
  net: '#2dd4bf', sleep: '#64748b', memory: '#f472b6', fault: '#ef4444', other: '#94a3b8'
};

// Header
const badge = document.getElementById('hdr-badge');
badge.textContent = P.outcome + (P.stop ? ' (' + P.stop + ')' : '');
badge.className = 'badge ' + (P.outcome === 'ok' ? 'ok' : (P.outcome === 'error' ? 'warn' : 'bad'));
document.getElementById('hdr-meta').textContent =
  'program: ' + P.program + '  |  seed: ' + P.seed + '  |  boots: ' + P.boots +
  '  |  vtime: ' + fmtNs(P.virtual_duration_ns) + '  |  wall: ' + P.wall_ms + ' ms' +
  (P.digest ? '  |  digest: ' + P.digest : '');

// 4-Bucket Cards
const gc = P.guest_compute, io = P.logical_io, vl = P.virtual_latency, tax = P.patina_tax;
document.getElementById('bucket-cards').innerHTML = [
  {
    k: '1. Guest User Compute',
    m: gc.compute_events.toLocaleString() + ' pts',
    s: 'vtime: ' + fmtNs(vl.compute_ns) + ' (' + gc.virtual_share_pct.toFixed(1) + '%)\n' +
       'switches: ' + gc.compute_switches + ' | spin: ' + gc.spin_yields + ' | pause: ' + gc.pause_points
  },
  {
    k: '2. Logical I/O & Syscalls',
    m: io.total_syscalls.toLocaleString() + ' calls',
    s: 'R: ' + fmtBytes(io.read_bytes) + ' (' + io.read_ops + ') | W: ' + fmtBytes(io.write_bytes) + ' (' + io.write_ops + ')\n' +
       'fsync: ' + io.fsync_ops + ' | futex: ' + io.futex_total_ops + ' | faults: ' + io.faults_injected
  },
  {
    k: '3. Modeled Virtual Latency',
    m: fmtNs(vl.total_ns),
    s: 'io: ' + fmtNs(vl.io_ns + vl.fsync_ns) + ' | futex: ' + fmtNs(vl.futex_ns) + '\n' +
       'net: ' + fmtNs(vl.net_ns) + ' | sleep: ' + fmtNs(vl.wait_sleep_ns)
  },
  {
    k: '4. Patina Runtime Tax',
    m: tax.wall_ms + ' ms wall',
    s: 'rate: ' + Math.round(tax.traps_per_sec).toLocaleString() + ' traps/s | v/w: ' + tax.virtual_to_wall_ratio.toFixed(2) + 'x\n' +
       'plans: ' + tax.plans_loaded + ' | log: ' + fmtBytes(tax.boundary_log_bytes)
  }
].map(c => `<div class="card"><div class="card-kicker">${esc(c.k)}</div><div class="metric">${esc(c.m)}</div><div class="sub" style="white-space:pre-line">${esc(c.s)}</div></div>`).join('');

// Stacked Virtual-Time Bar
const vparts = [
  ['compute', vl.compute_ns], ['io', vl.io_ns], ['fsync', vl.fsync_ns],
  ['futex', vl.futex_ns], ['net', vl.net_ns], ['sleep', vl.wait_sleep_ns],
  ['memory', vl.memory_ns], ['fault', vl.fault_ns], ['other', vl.other_ns]
].filter(x => x[1] > 0);
const vtot = Math.max(1, vparts.reduce((a,b)=>a+b[1], 0));
document.getElementById('vtime-total').textContent = fmtNs(vl.total_ns) + ' total virtual time';
document.getElementById('vtime-bar').innerHTML = vparts.map(([k,v]) =>
  `<div style="width:${(v/vtot*100).toFixed(2)}%;background:${CAT_COLORS[k]}" title="${k}: ${fmtNs(v)} (${(v/vtot*100).toFixed(1)}%)"></div>`
).join('');
document.getElementById('vtime-legend').innerHTML = vparts.map(([k,v]) =>
  `<span class="legend-item"><span class="swatch" style="background:${CAT_COLORS[k]}"></span>${k}: <b>${fmtNs(v)}</b> (${(v/vtot*100).toFixed(1)}%)</span>`
).join('');

// Interactive Swimlane Timeline
const tlEvents = P.timeline_events || [];
const lanes = [];
const laneMap = new Map();
tlEvents.forEach(ev => {
  const key = 'B' + ev.boot + ':S' + ev.slot;
  if (!laneMap.has(key)){ laneMap.set(key, lanes.length); lanes.push({key, label: 'boot-' + ev.boot + ' slot-' + ev.slot}); }
});
const tlMaxT = Math.max(10, ...tlEvents.map(e => e.ts_us + e.dur_us));
let tlStart = 0, tlEnd = tlMaxT;
let tlHitRects = [];
const tlCanvas = document.getElementById('tl-canvas');
const tlCtx = tlCanvas.getContext('2d');
document.getElementById('tl-stats').textContent = tlEvents.length.toLocaleString() + ' spans across ' + lanes.length + ' lanes';

function zoomTimeline(factor, anchorFrac){
  const span = tlEnd - tlStart;
  const f = anchorFrac === undefined ? 0.5 : anchorFrac;
  const mid = tlStart + span * f;
  const nspan = Math.max(1, Math.min(tlMaxT, span * factor));
  tlStart = Math.max(0, mid - nspan * f);
  tlEnd = Math.min(tlMaxT, tlStart + nspan);
  if (tlEnd - tlStart < nspan) tlStart = Math.max(0, tlEnd - nspan);
  redrawTimeline();
}
function resetTimeline(){ tlStart = 0; tlEnd = tlMaxT; redrawTimeline(); }

function redrawTimeline(){
  const q = (document.getElementById('tl-search').value || '').toLowerCase();
  const cat = document.getElementById('tl-cat').value;
  const dpr = window.devicePixelRatio || 1;
  const W = tlCanvas.parentElement.clientWidth;
  const laneH = 26, padTop = 28, padLeft = 116, padRight = 14;
  const H = Math.max(120, padTop + Math.max(1, lanes.length) * laneH + 14);
  tlCanvas.width = W * dpr; tlCanvas.height = H * dpr;
  tlCanvas.style.height = H + 'px';
  tlCtx.setTransform(dpr, 0, 0, dpr, 0, 0);

  const style = getComputedStyle(document.documentElement);
  const bg = style.getPropertyValue('--bg').trim();
  const border = style.getPropertyValue('--border').trim();
  const muted = style.getPropertyValue('--muted').trim();
  const text = style.getPropertyValue('--text').trim();

  tlCtx.fillStyle = bg; tlCtx.fillRect(0, 0, W, H);
  const plotW = Math.max(40, W - padLeft - padRight);
  const span = Math.max(1e-6, tlEnd - tlStart);

  // Time axis grid
  tlCtx.font = '11px ' + style.getPropertyValue('--mono');
  for (let i = 0; i <= 6; i++){
    const frac = i / 6;
    const x = padLeft + frac * plotW;
    const t = tlStart + frac * span;
    tlCtx.strokeStyle = border; tlCtx.lineWidth = 1;
    tlCtx.beginPath(); tlCtx.moveTo(x, padTop - 4); tlCtx.lineTo(x, H); tlCtx.stroke();
    tlCtx.fillStyle = muted;
    tlCtx.fillText(fmtUs(t), x + 3, 16);
  }
  // Lanes
  lanes.forEach((l, idx) => {
    const y = padTop + idx * laneH;
    tlCtx.strokeStyle = border; tlCtx.beginPath(); tlCtx.moveTo(0, y); tlCtx.lineTo(W, y); tlCtx.stroke();
    tlCtx.fillStyle = text; tlCtx.fillText(l.label, 8, y + 17);
  });

  tlHitRects = [];
  for (let i = 0; i < tlEvents.length; i++){
    const ev = tlEvents[i];
    if (cat && ev.cat !== cat) continue;
    if (q && !(ev.name.toLowerCase().includes(q) || (ev.detail && ev.detail.toLowerCase().includes(q)) || ev.cat.includes(q))) continue;
    if (ev.ts_us + ev.dur_us < tlStart || ev.ts_us > tlEnd) continue;
    const li = laneMap.get('B' + ev.boot + ':S' + ev.slot) || 0;
    const x1 = padLeft + ((Math.max(ev.ts_us, tlStart) - tlStart) / span) * plotW;
    const x2 = padLeft + ((Math.min(ev.ts_us + ev.dur_us, tlEnd) - tlStart) / span) * plotW;
    const rw = Math.max(2.5, x2 - x1);
    const y = padTop + li * laneH + 4;
    const rh = laneH - 8;
    tlCtx.fillStyle = CAT_COLORS[ev.cat] || '#94a3b8';
    tlCtx.fillRect(x1, y, rw, rh);
    if (rw > 42){
      tlCtx.fillStyle = '#041018';
      tlCtx.fillText(ev.name.slice(0, Math.floor(rw / 7)), x1 + 3, y + 12);
    }
    tlHitRects.push({x: x1, y, w: rw, h: rh, ev});
  }
}

let dragging = false, dragX = 0, dragStart = 0, dragEnd = 0;
tlCanvas.addEventListener('mousedown', e => {
  dragging = true; dragX = e.clientX; dragStart = tlStart; dragEnd = tlEnd;
});
window.addEventListener('mouseup', ()=> dragging = false);
window.addEventListener('mousemove', e => {
  if (!dragging) return;
  const plotW = Math.max(40, tlCanvas.parentElement.clientWidth - 130);
  const dx = e.clientX - dragX;
  const shift = -(dx / plotW) * (dragEnd - dragStart);
  let ns = dragStart + shift, ne = dragEnd + shift;
  if (ns < 0){ ne -= ns; ns = 0; }
  if (ne > tlMaxT){ ns -= (ne - tlMaxT); ne = tlMaxT; ns = Math.max(0, ns); }
  tlStart = ns; tlEnd = ne;
  redrawTimeline();
});
tlCanvas.addEventListener('wheel', e => {
  e.preventDefault();
  const r = tlCanvas.getBoundingClientRect();
  const frac = Math.max(0, Math.min(1, (e.clientX - r.left - 116) / Math.max(40, r.width - 130)));
  zoomTimeline(e.deltaY > 0 ? 1.25 : 0.78, frac);
}, {passive: false});
tlCanvas.addEventListener('mousemove', e => {
  if (dragging) return;
  const r = tlCanvas.getBoundingClientRect();
  const mx = e.clientX - r.left, my = e.clientY - r.top;
  for (let i = tlHitRects.length - 1; i >= 0; i--){
    const b = tlHitRects[i];
    if (mx >= b.x && mx <= b.x + b.w && my >= b.y && my <= b.y + b.h){
      const ev = b.ev;
      showTip(e, `${ev.name} [${ev.cat}]\nboot-${ev.boot} slot-${ev.slot} seq=${ev.seq}\nts=${fmtUs(ev.ts_us)}  dur=${fmtUs(ev.dur_us)}\nret=${ev.ret}` +
        (ev.bytes ? `  bytes=${fmtBytes(ev.bytes)}` : '') +
        (ev.detail ? `\n${ev.detail}` : ''));
      return;
    }
  }
  hideTip();
});
tlCanvas.addEventListener('mouseleave', hideTip);

// Interactive Deterministic CPU Flamegraph
const cpu = P.guest_compute.cpu_profile;
let flameRoot = null, flameFocus = null;
function buildFlameTree(stacks){
  const root = {name: 'all', value: 0, children: new Map(), depth: 0};
  for (const s of stacks){
    root.value += s.weight;
    let cur = root;
    const parts = s.stack.split(';');
    for (let i = 0; i < parts.length; i++){
      const name = parts[i];
      if (!cur.children.has(name)) cur.children.set(name, {name, value: 0, children: new Map(), depth: i + 1});
      cur = cur.children.get(name);
      cur.value += s.weight;
    }
  }
  return root;
}
function hashColor(str){
  let h = 2166136261;
  for (let i = 0; i < str.length; i++){ h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  const hue = 15 + ((h >>> 0) % 42);
  const sat = 72 + ((h >>> 8) % 18);
  const lit = 48 + ((h >>> 16) % 16);
  return `hsl(${hue},${sat}%,${lit}%)`;
}
function resetFlame(){ flameFocus = flameRoot; redrawFlame(); }
function redrawFlame(){
  const wrap = document.getElementById('fg-wrap');
  if (!cpu || !cpu.folded_stacks || cpu.folded_stacks.length === 0){
    wrap.innerHTML = `<div class="hint">No CPU flamegraph data in this run. Re-run with <code>--profile-cpu</code> (or retroactively with <code>patina replay ${esc(P.dir)} --profile-cpu</code>) for 100% deterministic compute-point CPU flamegraphs.</div>`;
    return;
  }
  document.getElementById('fg-controls').style.display = 'flex';
  document.getElementById('fg-stats').textContent =
    cpu.total_samples.toLocaleString() + ' samples | weight ' + cpu.total_weight.toLocaleString() +
    ' | interval ' + cpu.interval + ' | RT frames filtered: ' + cpu.rt_frames_filtered;
  if (!flameRoot){ flameRoot = buildFlameTree(cpu.folded_stacks); flameFocus = flameRoot; }

  const q = (document.getElementById('fg-search').value || '').toLowerCase();
  const rows = [];
  let maxDepth = 0, matchedW = 0;
  function layout(node, x0, totalW, depth){
    if (depth > maxDepth) maxDepth = depth;
    const w = node.value / Math.max(1, totalW);
    if (w < 0.0015) return;
    const match = q && node.name.toLowerCase().includes(q);
    if (match) matchedW += node.value;
    rows.push({node, x: x0, w, depth, match});
    let cx = x0;
    const kids = Array.from(node.children.values()).sort((a,b)=>a.name.localeCompare(b.name));
    for (const k of kids){
      layout(k, cx, totalW, depth + 1);
      cx += k.value / Math.max(1, totalW);
    }
  }
  layout(flameFocus, 0, flameFocus.value, 0);
  document.getElementById('fg-match').textContent = q
    ? ('Matched: ' + ((Math.min(matchedW, flameFocus.value) / Math.max(1, flameFocus.value))*100).toFixed(1) + '%')
    : 'Click any frame to zoom in';

  const rowH = 22;
  const H = (maxDepth + 1) * rowH + 8;
  const W = Math.max(600, wrap.clientWidth || 1000);
  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" style="display:block;font-family:var(--mono);font-size:11px">`;
  rows.forEach((r, idx) => {
    const x = r.x * W;
    const rw = Math.max(1, r.w * W - 1);
    const y = H - (r.depth + 1) * rowH - 2;
    const fill = r.match ? '#a855f7' : (r.depth === 0 ? '#38bdf8' : hashColor(r.node.name));
    const label = rw > 34 ? esc(r.node.name.slice(0, Math.floor((rw - 6) / 6.8))) : '';
    svg += `<g data-idx="${idx}" style="cursor:pointer"><rect x="${x.toFixed(1)}" y="${y}" width="${rw.toFixed(1)}" height="${rowH - 2}" rx="2" fill="${fill}" opacity="${q && !r.match ? '0.45' : '0.95'}"/>`;
    if (label) svg += `<text x="${(x + 4).toFixed(1)}" y="${y + 14}" fill="#081018" pointer-events="none">${label}</text>`;
    svg += `</g>`;
  });
  svg += `</svg>`;
  wrap.innerHTML = svg;
  wrap.querySelectorAll('g[data-idx]').forEach(g => {
    const r = rows[Number(g.getAttribute('data-idx'))];
    g.addEventListener('click', ()=>{ flameFocus = r.node; redrawFlame(); });
    g.addEventListener('mousemove', e => {
      const pctAll = (r.node.value / Math.max(1, flameRoot.value) * 100).toFixed(2);
      const pctFocus = (r.node.value / Math.max(1, flameFocus.value) * 100).toFixed(2);
      showTip(e, `${r.node.name}\nweight: ${r.node.value.toLocaleString()} compute events\n${pctAll}% of total  (${pctFocus}% of zoomed)`);
    });
    g.addEventListener('mouseleave', hideTip);
  });
}

// Memory Timeline SVG
function renderMemory(){
  const m = P.memory;
  document.getElementById('mem-stats').textContent =
    'peak ' + fmtBytes(m.peak_mapped_bytes) + ' | final ' + fmtBytes(m.final_mapped_bytes) +
    ' | ops: mmap ' + m.mmap_count + ', munmap ' + m.munmap_count + ', brk ' + m.brk_count;
  const pts = m.timeline || [];
  const box = document.getElementById('mem-chart');
  if (pts.length === 0){
    box.innerHTML = '<div class="hint">No mmap/brk memory deltas recorded.</div>';
  } else {
    const W = 560, H = 170, padL = 62, padR = 12, padT = 12, padB = 24;
    const maxT = Math.max(1, ...pts.map(p=>p.t_us));
    const maxB = Math.max(1, m.peak_mapped_bytes);
    const px = t => padL + (t / maxT) * (W - padL - padR);
    const py = b => padT + (1 - b / maxB) * (H - padT - padB);
    const poly = pts.map(p => `${px(p.t_us).toFixed(1)},${py(p.mapped_bytes).toFixed(1)}`).join(' ');
    const area = `${px(pts[0].t_us).toFixed(1)},${(H-padB)} ${poly} ${px(pts[pts.length-1].t_us).toFixed(1)},${(H-padB)}`;
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" style="font-family:var(--mono);font-size:10.5px">
      <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${H-padB}" stroke="var(--border)"/>
      <line x1="${padL}" y1="${H-padB}" x2="${W-padR}" y2="${H-padB}" stroke="var(--border)"/>
      <text x="4" y="${padT+8}" fill="var(--muted)">${esc(fmtBytes(maxB))}</text>
      <text x="4" y="${H-padB}" fill="var(--muted)">0 B</text>
      <text x="${W-padR-55}" y="${H-6}" fill="var(--muted)">${esc(fmtUs(maxT))}</text>
      <polygon points="${area}" fill="rgba(244,114,182,0.18)"/>
      <polyline points="${poly}" fill="none" stroke="#f472b6" stroke-width="2"/>
    </svg>`;
  }
  const allocs = m.top_allocations || [];
  if (allocs.length > 0){
    document.getElementById('mem-table-wrap').innerHTML =
      `<table><thead><tr><th>Op</th><th>Addr</th><th class="num">Size</th><th class="num">At (vTime)</th></tr></thead><tbody>` +
      allocs.slice(0, 8).map(a =>
        `<tr><td>${esc(a.op)}</td><td>${esc(a.addr)}</td><td class="num">${esc(fmtBytes(a.bytes))}</td><td class="num">${esc(fmtUs(a.t_us))}</td></tr>`
      ).join('') + `</tbody></table>`;
  }
}

// Virtual Tail Latency Chart & Table
function renderLatency(){
  const dists = Object.entries(P.virtual_latency.distributions || {});
  const box = document.getElementById('lat-chart');
  const tbl = document.getElementById('lat-table-wrap');
  if (dists.length === 0){
    box.innerHTML = '<div class="hint">No categorized syscall latency samples recorded.</div>';
    return;
  }
  const maxP99 = Math.max(1, ...dists.map(([,d]) => d.p99_ns));
  box.innerHTML = dists.map(([k, d]) => {
    const w50 = (d.p50_ns / maxP99 * 100).toFixed(1);
    const w95 = (d.p95_ns / maxP99 * 100).toFixed(1);
    const w99 = (d.p99_ns / maxP99 * 100).toFixed(1);
    return `<div style="margin-bottom:8px">
      <div style="display:flex;justify-content:space-between;font-family:var(--mono);font-size:12px">
        <span><b>${esc(k)}</b> (n=${d.count})</span>
        <span style="color:var(--muted)">p50 ${esc(fmtNs(d.p50_ns))} &middot; p95 ${esc(fmtNs(d.p95_ns))} &middot; p99 ${esc(fmtNs(d.p99_ns))}</span>
      </div>
      <div style="position:relative;height:10px;background:var(--surface2);border-radius:5px;overflow:hidden;margin-top:3px">
        <div style="position:absolute;left:0;top:0;height:100%;width:${w99}%;background:rgba(239,68,68,.55)"></div>
        <div style="position:absolute;left:0;top:0;height:100%;width:${w95}%;background:rgba(245,158,11,.75)"></div>
        <div style="position:absolute;left:0;top:0;height:100%;width:${w50}%;background:#38bdf8"></div>
      </div>
    </div>`;
  }).join('');

  tbl.innerHTML = `<table><thead><tr><th>Category</th><th class="num">Count</th><th class="num">p50</th><th class="num">p95</th><th class="num">p99</th><th class="num">max</th></tr></thead><tbody>` +
    dists.map(([k, d]) =>
      `<tr><td>${esc(k)}</td><td class="num">${d.count}</td><td class="num">${esc(fmtNs(d.p50_ns))}</td><td class="num">${esc(fmtNs(d.p95_ns))}</td><td class="num">${esc(fmtNs(d.p99_ns))}</td><td class="num">${esc(fmtNs(d.max_ns))}</td></tr>`
    ).join('') + `</tbody></table>`;
}

// Edge Coverage
if (P.coverage){
  const c = P.coverage;
  document.getElementById('cov-card').style.display = 'block';
  document.getElementById('cov-stats').textContent =
    c.edges_hit.toLocaleString() + ' / ' + c.map_size.toLocaleString() + ' edges (' + c.density_pct.toFixed(2) + '%) | ' + c.total_hits.toLocaleString() + ' total hits';
  document.getElementById('cov-body').innerHTML =
    `<div class="stack-bar"><div style="width:${Math.min(100, c.density_pct).toFixed(2)}%;background:var(--teal)"></div></div>` +
    `<div class="sub">Sample distinct edge hashes (showing ${c.sample_hashes.length} of ${c.unique_hashes}):</div>` +
    `<div class="pill-list">` + c.sample_hashes.map(h => `<span class="pill">0x${esc(h)}</span>`).join('') + `</div>`;
}

// Top Syscalls Table
document.getElementById('sc-tbody').innerHTML = (P.logical_io.top_syscalls || []).slice(0, 30).map(s =>
  `<tr><td>${esc(s.name)}</td><td><span class="swatch" style="background:${CAT_COLORS[s.category]||'#94a3b8'};margin-right:6px"></span>${esc(s.category)}</td>` +
  `<td class="num">${s.count.toLocaleString()}</td><td class="num">${s.errors}</td><td class="num">${esc(fmtBytes(s.bytes))}</td>` +
  `<td class="num">${esc(fmtNs(s.total_vtime_ns))}</td><td class="num">${esc(fmtNs(s.p50_ns))}</td><td class="num">${esc(fmtNs(s.p95_ns))}</td>` +
  `<td class="num">${esc(fmtNs(s.p99_ns))}</td><td class="num">${esc(fmtNs(s.max_ns))}</td></tr>`
).join('');

window._patinaRedraw = function(){ redrawTimeline(); redrawFlame(); };
window.addEventListener('resize', window._patinaRedraw);
renderMemory();
renderLatency();
window._patinaRedraw();
</script>
</body>
</html>
"###
    .replace("__SHARED_CSS__", SHARED_CSS)
    .replace("__THEME_JS__", THEME_JS)
    .replace("__SAFE_PROFILE__", &safe_profile)
    .replace("__SAFE_TRACE__", &safe_trace)
}

/// Render the self-contained sweep / campaign interactive HTML dashboard.
pub fn render_sweep_html(sweep_json: &str) -> String {
    let safe_sweep = safe_json_embed(sweep_json);

    r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Patina Sweep / Campaign Dashboard</title>
<style>__SHARED_CSS__</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <div class="title-row">
        <h1>Patina Sweep / Campaign Dashboard</h1>
        <span id="sw-badge" class="badge info">sweep</span>
      </div>
      <div id="sw-meta" class="meta"></div>
    </div>
    <div class="actions">
      <button class="primary" onclick="downloadSweep()">Download Profile JSON</button>
      <button onclick="toggleTheme()">Toggle Theme</button>
    </div>
  </header>

  <div class="grid-4" id="sw-cards"></div>

  <div class="card">
    <h2>Outcome Breakdown</h2>
    <div id="out-bar" class="stack-bar"></div>
    <div id="out-legend" class="legend"></div>
  </div>

  <div class="card">
    <h2>Grouped Findings <span id="grp-count" class="sub"></span></h2>
    <div id="groups-wrap"></div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Per-Seed Virtual Duration (ms)</h2>
      <div id="dist-vtime"></div>
    </div>
    <div class="card">
      <h2>Per-Seed Syscalls (Traps) &amp; Faults Injected</h2>
      <div id="dist-traps"></div>
    </div>
  </div>

  <div class="card">
    <h2>Runs &amp; Seeds Table <span id="tbl-count" class="sub"></span></h2>
    <div class="toolbar">
      <input type="text" id="run-search" placeholder="Filter seed / case / signature..." oninput="renderTable()">
      <select id="run-outcome" onchange="renderTable()"><option value="">All outcomes</option></select>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th onclick="sortBy('seed')">Seed</th>
            <th onclick="sortBy('outcome')">Outcome</th>
            <th onclick="sortBy('signature')">Signature</th>
            <th class="num" onclick="sortBy('virtual_ms')">vTime (ms)</th>
            <th class="num" onclick="sortBy('wall_ms')">Wall (ms)</th>
            <th class="num" onclick="sortBy('traps')">Traps</th>
            <th class="num" onclick="sortBy('faults_injected')">Faults</th>
            <th class="num" onclick="sortBy('edges_hit')">Edges</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="runs-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<script id="patina-sweep-data" type="application/json">__SAFE_SWEEP__</script>
<script>__THEME_JS__</script>
<script>
const S = JSON.parse(document.getElementById('patina-sweep-data').textContent);
function downloadSweep(){ downloadBlob('patina-sweep-profile.json', JSON.stringify(S, null, 2)); }
function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
const OUT_COLORS = {
  ok: '#22c55e', failure: '#ef4444', crash: '#dc2626', violation: '#f97316',
  liveness: '#f59e0b', nondeterministic: '#ec4899', error: '#eab308', timeout: '#64748b', internal: '#a855f7'
};

const swBadge = document.getElementById('sw-badge');
if (S.findings > 0){ swBadge.textContent = S.findings + ' findings'; swBadge.className = 'badge bad'; }
else if (S.vacuous){ swBadge.textContent = 'vacuous'; swBadge.className = 'badge warn'; }
else { swBadge.textContent = 'clean'; swBadge.className = 'badge ok'; }
document.getElementById('sw-meta').textContent = S.dir + '  |  ' + S.total_runs + ' runs  |  ' + S.unique_seeds + ' seeds';

const okCount = S.outcomes.ok || 0;
document.getElementById('sw-cards').innerHTML = [
  {k: 'Total Runs', m: S.total_runs.toLocaleString(), s: 'unique seeds: ' + S.unique_seeds + ' | ok: ' + okCount},
  {k: 'Findings / Groups', m: S.findings + ' / ' + S.groups.length, s: 'vacuous: ' + (S.vacuous ? 'yes' : 'no')},
  {k: 'Wall Time (p50 / p95)', m: S.summary_stats.p50_wall_ms + ' / ' + S.summary_stats.p95_wall_ms + ' ms', s: 'mean: ' + S.summary_stats.mean_wall_ms.toFixed(1) + ' ms | max: ' + S.summary_stats.max_wall_ms + ' ms'},
  {k: 'Syscalls & Faults', m: S.summary_stats.total_traps.toLocaleString() + ' traps', s: 'faults injected: ' + S.summary_stats.total_faults_injected.toLocaleString() + (S.summary_stats.max_edges_hit ? ' | max edges: ' + S.summary_stats.max_edges_hit : '')}
].map(c => `<div class="card"><div class="card-kicker">${esc(c.k)}</div><div class="metric">${esc(c.m)}</div><div class="sub">${esc(c.s)}</div></div>`).join('');

// Outcome Bar
const outs = Object.entries(S.outcomes || {});
const totOut = Math.max(1, outs.reduce((a,b)=>a+b[1], 0));
document.getElementById('out-bar').innerHTML = outs.map(([k,v]) =>
  `<div style="width:${(v/totOut*100).toFixed(2)}%;background:${OUT_COLORS[k]||'#38bdf8'}" title="${k}: ${v}"></div>`
).join('');
document.getElementById('out-legend').innerHTML = outs.map(([k,v]) =>
  `<span class="legend-item"><span class="swatch" style="background:${OUT_COLORS[k]||'#38bdf8'}"></span>${esc(k)}: <b>${v}</b> (${(v/totOut*100).toFixed(1)}%)</span>`
).join('');

// Outcome filter dropdown
const sel = document.getElementById('run-outcome');
outs.forEach(([k]) => {
  const o = document.createElement('option');
  o.value = k; o.textContent = k;
  sel.appendChild(o);
});

// Grouped Findings
document.getElementById('grp-count').textContent = S.groups.length + ' groups';
const gw = document.getElementById('groups-wrap');
if (S.groups.length === 0){
  gw.innerHTML = '<div class="hint">No non-ok finding groups in this sweep.</div>';
} else {
  gw.innerHTML = S.groups.map(g => {
    const cls = g.outcome === 'ok' ? 'ok' : (g.outcome === 'error' ? 'warn' : 'bad');
    return `<div style="border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin-bottom:10px;background:var(--surface2)">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
        <div><span class="badge ${cls}">#${g.index} ${esc(g.outcome)}</span> <b style="font-family:var(--mono);margin-left:6px">${esc(g.signature)}</b></div>
        <span class="sub">${g.count} runs &middot; seeds: ${g.seeds.slice(0,8).join(', ')}${g.seeds.length > 8 ? ' ...' : ''}</span>
      </div>
      ${g.example ? `<div class="sub" style="margin-top:6px;color:var(--text)">${esc(g.example)}</div>` : ''}
      ${g.faults_every.length ? `<div class="sub" style="margin-top:4px">faults in every run: ${esc(g.faults_every.join(', '))}</div>` : ''}
      ${g.replay_command ? `<div class="cmd-box"><code>${esc(g.replay_command)}</code><button onclick="copyText(this, ${JSON.stringify(g.replay_command)})">Copy replay</button></div>` : ''}
      ${g.rerun ? `<div class="cmd-box"><code>${esc(g.rerun)}</code><button onclick="copyText(this, ${JSON.stringify(g.rerun)})">Copy run</button></div>` : ''}
    </div>`;
  }).join('');
}

// Per-seed bar charts
function renderBarChart(elId, rows, getter, colorFn, unit){
  const el = document.getElementById(elId);
  if (!rows.length){ el.innerHTML = '<div class="hint">No runs found.</div>'; return; }
  const slice = rows.slice(0, 80);
  const maxV = Math.max(1e-6, ...slice.map(getter));
  const W = 560, H = 150, padL = 44, padR = 8, padT = 10, padB = 22;
  const bw = Math.max(2, (W - padL - padR) / slice.length - 1);
  let bars = '';
  slice.forEach((r, i) => {
    const v = getter(r);
    const h = (v / maxV) * (H - padT - padB);
    const x = padL + i * ((W - padL - padR) / slice.length);
    const y = H - padB - h;
    bars += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(1, h).toFixed(1)}" fill="${colorFn(r)}"><title>seed ${r.seed}: ${v.toFixed ? v.toFixed(1) : v} ${unit} (${r.outcome})</title></rect>`;
  });
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" style="font-family:var(--mono);font-size:10.5px">
    <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${H-padB}" stroke="var(--border)"/>
    <line x1="${padL}" y1="${H-padB}" x2="${W-padR}" y2="${H-padB}" stroke="var(--border)"/>
    <text x="4" y="${padT+8}" fill="var(--muted)">${maxV >= 100 ? Math.round(maxV) : maxV.toFixed(1)}</text>
    <text x="4" y="${H-padB}" fill="var(--muted)">0</text>
    ${bars}
  </svg>`;
}
renderBarChart('dist-vtime', S.runs, r => r.virtual_ms, r => OUT_COLORS[r.outcome] || '#38bdf8', 'ms');
renderBarChart('dist-traps', S.runs, r => r.traps, r => r.faults_injected > 0 ? '#f59e0b' : '#38bdf8', 'traps');

// Sortable & filterable seed table
let sortKey = 'seed', sortDir = 1;
function sortBy(k){
  if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = 1; }
  renderTable();
}
function renderTable(){
  const q = (document.getElementById('run-search').value || '').toLowerCase();
  const out = document.getElementById('run-outcome').value;
  let rows = S.runs.filter(r => {
    if (out && r.outcome !== out) return false;
    if (q && !(String(r.seed).includes(q) || (r.case||'').toLowerCase().includes(q) || r.signature.toLowerCase().includes(q))) return false;
    return true;
  });
  rows.sort((a,b) => {
    const va = a[sortKey] ?? -1, vb = b[sortKey] ?? -1;
    if (typeof va === 'string') return va.localeCompare(vb) * sortDir;
    return (va - vb) * sortDir;
  });
  document.getElementById('tbl-count').textContent = rows.length + ' of ' + S.runs.length + ' runs';
  document.getElementById('runs-tbody').innerHTML = rows.slice(0, 500).map(r => {
    const cls = r.outcome === 'ok' ? 'ok' : (r.outcome === 'error' ? 'warn' : 'bad');
    return `<tr>
      <td>${r.seed}${r.case ? ' <span class="sub">['+esc(r.case)+']</span>' : ''}</td>
      <td><span class="badge ${cls}">${esc(r.outcome)}</span></td>
      <td>${esc(r.signature)}</td>
      <td class="num">${r.virtual_ms.toFixed(2)}</td>
      <td class="num">${r.wall_ms}</td>
      <td class="num">${r.traps.toLocaleString()}</td>
      <td class="num">${r.faults_injected}</td>
      <td class="num">${r.edges_hit != null ? r.edges_hit : '-'}</td>
      <td><button onclick="copyText(this, ${JSON.stringify(r.replay_command)})">Copy replay</button></td>
    </tr>`;
  }).join('');
}
renderTable();
</script>
</body>
</html>
"###
    .replace("__SHARED_CSS__", SHARED_CSS)
    .replace("__THEME_JS__", THEME_JS)
    .replace("__SAFE_SWEEP__", &safe_sweep)
}
