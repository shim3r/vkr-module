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
    button { padding: 8px 12px; margin-right: 8px; }
    pre { background: #f6f6f6; padding: 12px; border-radius: 8px; }
    .row { display: flex; gap: 16px; }
    .col { flex: 1; }
  </style>
</head>
<body>
  <h2>VKR SIEM Live Dashboard</h2>
  <div>
    <button onclick="startSim()">Start simulator</button>
    <button onclick="stopSim()">Stop simulator</button>
    <button onclick="refresh()">Refresh now</button>
    <span id="status"></span>
  </div>
  <div class="row">
    <div class="col">
      <h3>Alerts (latest)</h3>
      <pre id="alerts">loading...</pre>
    </div>
  </div>

<script>
async function startSim(){
  await fetch('/api/sim/start?eps=2', {method:'POST'});
  refresh();
}
async function stopSim(){
  await fetch('/api/sim/stop', {method:'POST'});
  refresh();
}
async function refresh(){
  const s = await fetch('/api/sim/status').then(r=>r.json()).catch(()=>({running:false}));
  document.getElementById('status').textContent = 'sim running: ' + s.running;

  const a = await fetch('/api/alerts?limit=20').then(r=>r.json());
  document.getElementById('alerts').textContent = JSON.stringify(a, null, 2);
}
setInterval(refresh, 1500);
refresh();
</script>
</body>
</html>
"""

@router.get("/", response_class=HTMLResponse)
def ui():
    return HTML
