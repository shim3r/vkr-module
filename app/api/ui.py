from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["ui"])

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>VKR SIEM Live</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    button, select { padding: 8px 12px; margin-right: 8px; margin-bottom: 8px; }
    pre { background: #f6f6f6; padding: 12px; border-radius: 8px; overflow:auto; max-height: 520px;}
    .row { display: flex; gap: 16px; }
    .col { flex: 1; }
    .muted { color: #666; }
    .ok { color: #0a7; }
    .warn { color: #c60; }
  </style>
</head>
<body>
  <h2>VKR SIEM Live Dashboard</h2>
  <div class="muted">
    Демонстрационный стенд SIEM. Управление атаками и просмотр инцидентов.
  </div>

  <div style="margin-top:12px;">
    <select id="attackSelect">
      <option value="vpn_bruteforce">VPN Bruteforce (T1110)</option>
      <option value="vpn_compromise">Bruteforce → Success (T1110 + T1078)</option>
      <option value="portscan">Port Scan (T1046)</option>
      <option value="lateral">Lateral Movement (T1021)</option>
      <option value="malware">Malware Detected (T1204)</option>
    </select>

    <button onclick="runAttack()">Run attack</button>
    <button onclick="runRandomAttack()">Run random</button>
    <button onclick="stopAttack()">Stop attack</button>
    <button onclick="resetData()">Reset alerts/incidents</button>

    <span id="status" class="muted"></span>
  </div>

  <div class="row">
    <div class="col">
      <h3>Alerts</h3>
      <pre id="alerts">loading...</pre>
    </div>
    <div class="col">
      <h3>Incidents</h3>
      <pre id="incidents">loading...</pre>
    </div>
  </div>

<script>
async function refresh(){
  const a = await fetch('/api/alerts?limit=20').then(r=>r.json()).catch(()=>({items:[]}));
  document.getElementById('alerts').textContent = JSON.stringify(a, null, 2);

  const i = await fetch('/api/incidents?limit=20').then(r=>r.json()).catch(()=>({items:[]}));
  document.getElementById('incidents').textContent = JSON.stringify(i, null, 2);
}

function setStatus(text, cls){
  const el = document.getElementById('status');
  el.className = cls || 'muted';
  el.textContent = text;
}

async function runAttack(){
  const mode = document.getElementById('attackSelect').value;
  setStatus('Running ' + mode + '...', 'warn');
  const res = await fetch('/api/sim/attack?mode=' + mode, {method:'POST'}).then(r=>r.json());
  setStatus(JSON.stringify(res), 'ok');
}

async function runRandomAttack(){
  setStatus('Running random attack...', 'warn');
  const res = await fetch('/api/sim/attack-random', {method:'POST'}).then(r=>r.json());
  setStatus(JSON.stringify(res), 'ok');
}

async function stopAttack(){
  setStatus('Stopping attack...', 'warn');
  const res = await fetch('/api/sim/attack-stop', {method:'POST'}).then(r=>r.json());
  setStatus(JSON.stringify(res), 'ok');
}

async function resetData(){
  setStatus('Resetting data...', 'warn');
  const res = await fetch('/api/sim/reset', {method:'POST'}).then(r=>r.json());
  setStatus('Reset done', 'ok');
  refresh();
}

setInterval(refresh, 1500);
refresh();
</script>
</body>
</html>
"""

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui():
    return HTML