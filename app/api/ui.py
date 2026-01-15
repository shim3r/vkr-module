from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["ui"])

HTML = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>VKR SIEM • Live</title>
  <style>
    :root{
      --bg: #0b1020;
      --panel: rgba(255,255,255,0.06);
      --panel2: rgba(255,255,255,0.04);
      --border: rgba(255,255,255,0.10);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.65);
      --good: #23c483;
      --warn: #ffcc00;
      --bad: #ff4d6d;
      --accent: #6aa6ff;
      --accent2: #b06cff;
      --shadow: 0 10px 30px rgba(0,0,0,0.35);
    }
    *{ box-sizing: border-box; }
    body{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:
        radial-gradient(1200px 900px at 15% 10%, rgba(106,166,255,0.20), transparent 55%),
        radial-gradient(900px 700px at 85% 0%, rgba(176,108,255,0.16), transparent 55%),
        radial-gradient(900px 700px at 80% 95%, rgba(35,196,131,0.10), transparent 60%),
        var(--bg);
      color: var(--text);
      min-height: 100vh;
    }
    header{
      padding: 22px 22px 10px;
      display:flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .brand{ display:flex; align-items:center; gap:12px; }
    .logo{
      width: 42px; height: 42px;
      border-radius: 14px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      box-shadow: var(--shadow);
    }
    .title{ line-height: 1.1; }
    .title h1{ margin:0; font-size: 18px; letter-spacing: 0.4px; }
    .title .sub{ margin-top: 4px; font-size: 12px; color: var(--muted); }

    .status-pill{
      display:flex; align-items:center; gap:10px;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: rgba(255,255,255,0.04);
      box-shadow: var(--shadow);
      max-width: 100%;
    }
    .dot{ width: 10px; height: 10px; border-radius: 50%; background: var(--muted); box-shadow: 0 0 0 4px rgba(255,255,255,0.06); }
    .dot.ok{ background: var(--good); box-shadow: 0 0 0 4px rgba(35,196,131,0.18); }
    .dot.warn{ background: var(--warn); box-shadow: 0 0 0 4px rgba(255,204,0,0.16); }
    .dot.bad{ background: var(--bad); box-shadow: 0 0 0 4px rgba(255,77,109,0.16); }
    .status-text{ font-size: 13px; color: var(--muted); overflow-wrap:anywhere; }

    .wrap{ padding: 0 22px 22px; display: grid; grid-template-columns: 1fr; gap: 14px; }
    .panel{ border: 1px solid var(--border); background: var(--panel); border-radius: 16px; box-shadow: var(--shadow); overflow: hidden; }
    .panel .hdr{ padding: 14px; display:flex; align-items: center; justify-content: space-between; gap: 10px; background: rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.08); }
    .panel .hdr .h{ display:flex; flex-direction: column; gap: 2px; }
    .panel .hdr .h b{ font-size: 13px; letter-spacing: 0.2px; }
    .panel .hdr .h span{ font-size: 12px; color: var(--muted); }

    .controls{ padding: 14px; display:flex; flex-wrap: wrap; gap: 10px; align-items:center; justify-content: space-between; }
    .left-controls{ display:flex; flex-wrap: wrap; gap: 10px; align-items:center; }

    select{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(0,0,0,0.35);
      color: var(--text);
      outline: none;
      min-width: 270px;
    }

    .btn{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.06);
      color: var(--text);
      cursor: pointer;
      transition: transform 0.06s ease, background 0.2s ease, border-color 0.2s ease;
      user-select: none;
      font-weight: 600;
      font-size: 13px;
      letter-spacing: 0.2px;
    }
    .btn:hover{ background: rgba(255,255,255,0.10); border-color: rgba(255,255,255,0.22); }
    .btn:active{ transform: translateY(1px); }
    .btn.primary{ background: linear-gradient(135deg, rgba(106,166,255,0.85), rgba(176,108,255,0.75)); border-color: rgba(255,255,255,0.16); }
    .btn.danger{ background: rgba(255,77,109,0.14); border-color: rgba(255,77,109,0.35); }
    .btn.ghost{ background: transparent; }

    .grid{ display: grid; grid-template-columns: 1fr; gap: 14px; padding: 14px; }
    .card{ border: 1px solid rgba(255,255,255,0.10); background: var(--panel2); border-radius: 16px; overflow: hidden; }
    .card .card-h{ padding: 12px; display:flex; align-items:center; justify-content: space-between; gap: 10px; border-bottom: 1px solid rgba(255,255,255,0.08); background: rgba(255,255,255,0.03); }

    .badge{ padding: 4px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: 0.3px; border: 1px solid rgba(255,255,255,0.14); background: rgba(255,255,255,0.06); color: var(--muted); }
    .badge.ok{ color: rgba(35,196,131,0.95); border-color: rgba(35,196,131,0.35); background: rgba(35,196,131,0.10); }
    .badge.warn{ color: rgba(255,204,0,0.95); border-color: rgba(255,204,0,0.35); background: rgba(255,204,0,0.10); }
    .badge.bad{ color: rgba(255,77,109,0.95); border-color: rgba(255,77,109,0.40); background: rgba(255,77,109,0.12); }

    .card pre{ margin: 0; padding: 12px; color: rgba(255,255,255,0.90); font-size: 12px; line-height: 1.45; overflow:auto; max-height: 520px; }
    .kpi{ display:flex; gap: 10px; flex-wrap: wrap; padding: 0 14px 14px; }
    .kpi .pill{ display:flex; gap: 8px; align-items:center; padding: 8px 10px; border-radius: 999px; border: 1px solid rgba(255,255,255,0.12); background: rgba(255,255,255,0.05); color: var(--muted); font-size: 12px; }
    .kpi .pill b{ color: var(--text); }
    .footer{ padding: 10px 22px 18px; color: var(--muted); font-size: 12px; }

    @media (min-width: 980px){ .grid{ grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo"></div>
    <div class="title">
      <h1>VKR MODULE • Live Dashboard</h1>
      <div class="sub">Демо-панель: запуск атак, остановка, сброс, просмотр Alerts/Incidents</div>
    </div>
  </div>
  <div class="status-pill">
    <div id="dot" class="dot"></div>
    <div id="status" class="status-text">Ready</div>
  </div>
</header>

<div class="wrap">
  <div class="panel">
    <div class="hdr">
      <div class="h">
        <b>Controls</b>
        <span>Кнопки управляют демо-атаками (API: /api/sim/*)</span>
      </div>
      <div class="badge">UI: /</div>
    </div>

    <div class="controls">
      <div class="left-controls">
        <select id="attackSelect">
          <option value="vpn_bruteforce">VPN Bruteforce (T1110)</option>
          <option value="vpn_compromise">Bruteforce → Success (T1110 + T1078)</option>
          <option value="portscan">Port Scan (T1046)</option>
          <option value="lateral">Lateral Movement (T1021)</option>
          <option value="malware">Malware Detected (T1204)</option>
        </select>

        <button class="btn primary" onclick="runAttack()">Run selected</button>
        <button class="btn" onclick="runRandomAttack()">Run random</button>
        <button class="btn danger" onclick="stopAttack()">Stop attack</button>
        <button class="btn ghost" onclick="resetData()">Reset data</button>
      </div>

      <div class="kpi">
        <div class="pill"><span>Alerts:</span> <b id="kpiAlerts">0</b></div>
        <div class="pill"><span>Incidents:</span> <b id="kpiIncidents">0</b></div>
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-h">
        <div><b>Alerts</b> <span style="color:var(--muted); font-size:12px; margin-left:10px;">последние 20</span></div>
        <span id="alertsBadge" class="badge">—</span>
      </div>
      <pre id="alerts">loading...</pre>
    </div>

    <div class="card">
      <div class="card-h">
        <div><b>Incidents</b> <span style="color:var(--muted); font-size:12px; margin-left:10px;">последние 20</span></div>
        <span id="incidentsBadge" class="badge">—</span>
      </div>
      <pre id="incidents">loading...</pre>
    </div>
  </div>
</div>


<script>
function setStatus(text, level){
  const statusEl = document.getElementById('status');
  const dot = document.getElementById('dot');
  statusEl.textContent = text;
  dot.classList.remove('ok','warn','bad');
  if(level === 'ok') dot.classList.add('ok');
  else if(level === 'warn') dot.classList.add('warn');
  else if(level === 'bad') dot.classList.add('bad');
}

function badgeFromItems(items){
  let crit = false, high = false;
  for(const it of items){
    const p = (it.priority || it.severity || it.level || '').toString().toLowerCase();
    if(p.includes('critical')) crit = true;
    if(p.includes('high')) high = true;
  }
  if(crit) return {cls:'bad', text:'CRITICAL'};
  if(high) return {cls:'warn', text:'HIGH'};
  return {cls:'ok', text:'OK'};
}

async function refresh(){
  const a = await fetch('/api/alerts?limit=20').then(r=>r.json()).catch(()=>({items:[]}));
  const alerts = a.items || [];
  document.getElementById('alerts').textContent = JSON.stringify(a, null, 2);
  document.getElementById('kpiAlerts').textContent = alerts.length;

  const i = await fetch('/api/incidents?limit=20').then(r=>r.json()).catch(()=>({items:[]}));
  const incidents = i.items || [];
  document.getElementById('incidents').textContent = JSON.stringify(i, null, 2);
  document.getElementById('kpiIncidents').textContent = incidents.length;

  const ab = badgeFromItems(alerts);
  const ib = badgeFromItems(incidents);

  const alertsBadge = document.getElementById('alertsBadge');
  alertsBadge.className = 'badge ' + ab.cls;
  alertsBadge.textContent = ab.text;

  const incidentsBadge = document.getElementById('incidentsBadge');
  incidentsBadge.className = 'badge ' + ib.cls;
  incidentsBadge.textContent = ib.text;
}

async function runAttack(){
  const mode = document.getElementById('attackSelect').value;
  setStatus('Starting: ' + mode + ' ...', 'warn');
  const res = await fetch('/api/sim/attack?mode=' + encodeURIComponent(mode), {method:'POST'}).then(r=>r.json()).catch(()=>({status:'error'}));
  if(res.status === 'started') setStatus('Started: ' + mode, 'ok');
  else if(res.status === 'busy') setStatus('Busy: already running', 'warn');
  else setStatus('Error starting attack', 'bad');
}

async function runRandomAttack(){
  setStatus('Starting random attack ...', 'warn');
  const res = await fetch('/api/sim/attack-random', {method:'POST'}).then(r=>r.json()).catch(()=>({status:'error'}));
  if(res.status === 'started') setStatus('Started random: ' + (res.mode || 'unknown'), 'ok');
  else if(res.status === 'busy') setStatus('Busy: already running', 'warn');
  else setStatus('Error starting random attack', 'bad');
}

async function stopAttack(){
  setStatus('Stopping attack ...', 'warn');
  const res = await fetch('/api/sim/attack-stop', {method:'POST'}).then(r=>r.json()).catch(()=>({status:'error'}));
  if(res.status === 'stopping') setStatus('Stopping...', 'ok');
  else if(res.status === 'not_running') setStatus('Not running', 'warn');
  else setStatus('Error stopping attack', 'bad');
}

async function resetData(){
  setStatus('Resetting data ...', 'warn');
  const res = await fetch('/api/sim/reset', {method:'POST'}).then(r=>r.json()).catch(()=>({status:'error'}));
  if(res.status === 'ok') setStatus('Reset done', 'ok');
  else setStatus('Error resetting data', 'bad');
  await refresh();
}

setStatus('Ready', 'ok');
setInterval(refresh, 1200);
refresh();
</script>
</body>
</html>
"""

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui_index():
    return HTML