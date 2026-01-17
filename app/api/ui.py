from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import HTMLResponse
from typing import Any, Callable, Dict, Optional

router = APIRouter(tags=["ui"])

# --- optional service imports (project may vary) ---

def _try_import(path: str, name: str) -> Optional[Any]:
    try:
        mod = __import__(path, fromlist=[name])
        return getattr(mod, name)
    except Exception:
        return None


# Events store (raw + aggregates)
list_events = _try_import("app.services.events_store", "list_events")
list_aggregates = _try_import("app.services.events_store", "list_aggregates")
count_events = _try_import("app.services.events_store", "count_events")
count_aggregates = _try_import("app.services.events_store", "count_aggregates")

# Alerts store
list_alerts = (
    _try_import("app.services.alerts_store", "list_alerts")
    or _try_import("app.services.alerts_store", "get_alerts")
)
count_alerts = _try_import("app.services.alerts_store", "count_alerts")

# Incidents store
list_incidents = (
    _try_import("app.services.incidents_store", "list_incidents")
    or _try_import("app.services.incidents_store", "get_incidents")
)
count_incidents = _try_import("app.services.incidents_store", "count_incidents")

# Additional safe imports for incident patching
get_incident = _try_import("app.services.incidents_store", "get_incident")
update_incident = _try_import("app.services.incidents_store", "update_incident")

# Asset DB (demo in-memory)
ASSET_DB = _try_import("app.pipeline.collector", "ASSET_DB")


def _safe_count(fn: Optional[Callable[[], int]], fallback_list_fn: Optional[Callable[[int], Any]] = None) -> int:
    if callable(fn):
        try:
            return int(fn())
        except Exception:
            return 0
    if callable(fallback_list_fn):
        try:
            data = fallback_list_fn(10_000)
            return len(data) if isinstance(data, list) else len(list(data))
        except Exception:
            return 0
    return 0


def _safe_list(fn: Optional[Callable[[int], Any]], limit: int) -> list:
    if not callable(fn):
        return []
    try:
        data = fn(limit)
        return data if isinstance(data, list) else list(data)
    except Exception:
        return []


# --- API endpoints for new UI ---

@router.get("/api/metrics", include_in_schema=False)
def api_metrics() -> Dict[str, Any]:
    # totals
    events_raw = _safe_count(count_events, list_events)
    events_aggregated = _safe_count(count_aggregates, None)
    alerts = _safe_count(count_alerts, list_alerts)
    incidents = _safe_count(count_incidents, list_incidents)

    # per-source counters (best-effort, based on raw events)
    by_source: Dict[str, int] = {"firewall": 0, "av": 0, "edr": 0, "iam": 0, "endpoints": 0}
    if callable(list_events):
        try:
            data = list_events(10_000)
            items = data if isinstance(data, list) else list(data)
            for e in items:
                if not isinstance(e, dict):
                    continue
                st = str(e.get("source_type") or e.get("source") or "").lower()
                # normalize common variants
                if st in ("iam/ad", "iam", "ad", "active_directory"):
                    st = "iam"
                if st in ("antivirus", "av"):
                    st = "av"
                if st in ("edr", "edr_system"):
                    st = "edr"
                if st in ("endpoint", "endpoints", "os", "os_logs"):
                    st = "endpoints"
                if st in by_source:
                    by_source[st] += 1
        except Exception:
            pass

    return {
        "events_raw": events_raw,
        "events_aggregated": events_aggregated,
        "alerts": alerts,
        "incidents": incidents,
        "by_source": by_source,
        "note": "metrics generated in ui.py"
    }


@router.get("/api/events", include_in_schema=False)
def api_events(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_events, limit)
    return {"items": items, "limit": limit}


@router.get("/api/events-aggregated", include_in_schema=False)
def api_events_aggregated(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_aggregates, limit)
    return {"items": items, "limit": limit}


@router.get("/api/alerts", include_in_schema=False)
def api_alerts(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_alerts, limit)
    return {"items": items, "limit": limit}


@router.get("/api/incidents", include_in_schema=False)
def api_incidents(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_incidents, limit)
    return {"items": items, "limit": limit}


# PATCH endpoint for updating an incident (UI module, in-memory store)
@router.patch("/api/incidents/{incident_id}", include_in_schema=False)
def api_patch_incident(incident_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not callable(update_incident) or not callable(get_incident):
        raise HTTPException(status_code=501, detail="incident update is not available")

    updated = update_incident(
        incident_id,
        status=payload.get("status"),
        assignee=payload.get("assignee"),
        comment=payload.get("comment"),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="incident not found")
    return updated


@router.get("/api/assets", include_in_schema=False)
def api_assets() -> Dict[str, Any]:
    # ASSET_DB can be dict or None
    if isinstance(ASSET_DB, dict):
        return {"items": ASSET_DB, "note": "in-memory demo asset db"}
    return {"items": {}, "note": "ASSET_DB not found in app.pipeline.collector"}

HTML = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>VKR SIEM • Monitoring</title>
  <style>
    :root{
      --bg: #f6f7fb;
      --panel: #ffffff;
      --panel2: #fbfcff;
      --border: rgba(15, 23, 42, 0.10);
      --text: #0f172a;
      --muted: rgba(15, 23, 42, 0.65);
      --muted2: rgba(15, 23, 42, 0.45);
      --sidebar: #0b1220;
      --sidebar2: #0f172a;
      --accent: #2f6fed;
      --good: #16a34a;
      --warn: #f59e0b;
      --bad: #ef4444;
      --shadow: 0 10px 30px rgba(2,6,23,0.10);
      --radius: 14px;
    }
    *{ box-sizing: border-box; }
    html, body{ height: 100%; }
    body{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      overflow: hidden;
    }

    /* Layout */
    .app{ height: 100%; display: grid; grid-template-columns: 270px 1fr; }
    .sidebar{
      background: linear-gradient(180deg, var(--sidebar), var(--sidebar2));
      color: rgba(255,255,255,0.92);
      border-right: 1px solid rgba(255,255,255,0.06);
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .brand{
      display:flex; align-items:center; gap: 12px;
      padding: 10px 10px;
      border-radius: 14px;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.08);
    }
    .logo{
      width: 42px; height: 42px;
      border-radius: 14px;
      background: radial-gradient(circle at 30% 30%, rgba(47,111,237,0.95), rgba(47,111,237,0.15)),
                  radial-gradient(circle at 70% 70%, rgba(255,255,255,0.20), rgba(255,255,255,0.02));
      box-shadow: 0 10px 25px rgba(0,0,0,0.35);
      border: 1px solid rgba(255,255,255,0.12);
    }
    .brand .t{ line-height: 1.15; }
    .brand .t b{ display:block; font-size: 14px; letter-spacing: 0.2px; }
    .brand .t span{ display:block; font-size: 12px; color: rgba(255,255,255,0.65); margin-top: 2px; }

    .nav{ display:flex; flex-direction: column; gap: 6px; }
    .nav a{
      text-decoration: none;
      color: rgba(255,255,255,0.88);
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.06);
      background: rgba(255,255,255,0.03);
      display:flex; align-items:center; justify-content: space-between;
      gap: 10px;
      font-size: 13px;
    }
    .nav a:hover{ background: rgba(255,255,255,0.07); border-color: rgba(255,255,255,0.10); }
    .nav a.active{ background: rgba(47,111,237,0.22); border-color: rgba(47,111,237,0.35); }
    .nav small{ color: rgba(255,255,255,0.55); font-weight: 600; }

    .sidebar .footer{
      margin-top: auto;
      padding: 10px 10px;
      border-radius: 14px;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.04);
      color: rgba(255,255,255,0.70);
      font-size: 12px;
      display:flex; align-items:center; justify-content: space-between;
    }

    .main{ overflow: auto; padding: 18px 18px 24px; }

    /* Topbar */
    .topbar{
      display:flex;
      align-items:flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }
    .topbar h1{ margin: 0; font-size: 20px; letter-spacing: 0.2px; }
    .sub{ margin-top: 6px; color: var(--muted); font-size: 12px; }

    .rightbar{ display:flex; flex-wrap: wrap; gap: 10px; align-items:center; justify-content: flex-end; }

    .pill{
      display:flex; align-items:center; gap: 10px;
      padding: 10px 12px;
      border-radius: 14px;
      background: var(--panel);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      min-height: 42px;
    }
    .dot{ width: 10px; height: 10px; border-radius: 999px; background: #94a3b8; }
    .dot.ok{ background: var(--good); }
    .dot.warn{ background: var(--warn); }
    .dot.bad{ background: var(--bad); }

    select{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      outline: none;
      min-width: 280px;
      box-shadow: var(--shadow);
    }

    .btn{
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      cursor: pointer;
      font-weight: 700;
      font-size: 13px;
      box-shadow: var(--shadow);
      transition: transform 0.06s ease;
    }
    .btn:active{ transform: translateY(1px); }
    .btn.primary{ background: linear-gradient(135deg, rgba(47,111,237,0.95), rgba(47,111,237,0.70)); color: #fff; border-color: rgba(47,111,237,0.55); }
    .btn.danger{ background: rgba(239,68,68,0.12); border-color: rgba(239,68,68,0.30); }

    .tbl-input{
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid rgba(15,23,42,0.12);
      background: #fff;
      font-size: 12px;
      outline: none;
      width: 100%;
    }
    .tbl-input.wide{ min-width: 260px; }
    .tbl-input.mid{ min-width: 160px; }
    .tbl-select{
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid rgba(15,23,42,0.12);
      background: #fff;
      font-size: 12px;
      outline: none;
      min-width: 140px;
    }
    .tbl-btn{
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid rgba(15,23,42,0.12);
      background: rgba(47,111,237,0.10);
      cursor: pointer;
      font-weight: 800;
      font-size: 12px;
    }
    .tbl-btn:hover{ background: rgba(47,111,237,0.16); }

    /* Cards / grids */
    .grid{ display: grid; gap: 14px; }
    .grid.cols-2{ grid-template-columns: 1fr; }
    .grid.cols-3{ grid-template-columns: 1fr; }
    .grid.cols-4{ grid-template-columns: 1fr; }

    @media (min-width: 980px){
      .grid.cols-2{ grid-template-columns: 1fr 1fr; }
      .grid.cols-3{ grid-template-columns: 1fr 1fr 1fr; }
      .grid.cols-4{ grid-template-columns: 1fr 1fr 1fr 1fr; }
    }

    .card{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .card .hdr{
      padding: 12px 14px;
      display:flex; align-items:center; justify-content: space-between;
      gap: 10px;
      border-bottom: 1px solid rgba(15,23,42,0.08);
      background: var(--panel2);
    }
    .card .hdr b{ font-size: 13px; }
    .card .hdr span{ color: var(--muted); font-size: 12px; }
    .card .body{ padding: 14px; }

    .kpis{ display:grid; gap: 12px; grid-template-columns: 1fr 1fr; }
    @media (min-width: 980px){ .kpis{ grid-template-columns: repeat(5, 1fr);} }

    .kpi{
      padding: 12px 12px;
      border-radius: 14px;
      border: 1px solid rgba(15,23,42,0.10);
      background: linear-gradient(180deg, #ffffff, #fbfcff);
      box-shadow: var(--shadow);
      min-height: 74px;
    }
    .kpi .t{ color: var(--muted); font-size: 12px; }
    .kpi .v{ margin-top: 6px; font-size: 22px; font-weight: 900; letter-spacing: 0.2px; }
    .kpi .s{ margin-top: 6px; font-size: 12px; color: var(--muted2); }

    .badge{
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      border: 1px solid rgba(15,23,42,0.12);
      background: rgba(15,23,42,0.04);
      color: var(--muted);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      white-space: nowrap;
      line-height: 1;
    }
    .badge.ok{ color: var(--good); border-color: rgba(22,163,74,0.35); background: rgba(22,163,74,0.08); }
    .badge.warn{ color: var(--warn); border-color: rgba(245,158,11,0.35); background: rgba(245,158,11,0.10); }
    .badge.bad{ color: var(--bad); border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.10); }

    /* Tables */
    table{ width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td{ padding: 10px 10px; border-bottom: 1px solid rgba(15,23,42,0.08); font-size: 12px; vertical-align: top; }

    /* Fixed column widths for Incidents table (SIEM-style) */
    .incidents-table th:nth-child(1), .incidents-table td:nth-child(1){ width: 150px; }   /* id */
    .incidents-table th:nth-child(2), .incidents-table td:nth-child(2){ width: 110px; }   /* severity */
    .incidents-table th:nth-child(3), .incidents-table td:nth-child(3){ width: 140px; }   /* status */
    .incidents-table th:nth-child(4), .incidents-table td:nth-child(4){ width: 70px; }    /* sla */
    .incidents-table th:nth-child(5), .incidents-table td:nth-child(5){ width: 140px; }   /* assignee */
    .incidents-table th:nth-child(6), .incidents-table td:nth-child(6){ width: 170px; }   /* type */
    .incidents-table th:nth-child(7), .incidents-table td:nth-child(7){ width: 150px; }   /* first_seen */
    .incidents-table th:nth-child(8), .incidents-table td:nth-child(8){ width: 120px; }   /* asset */
    .incidents-table th:nth-child(9), .incidents-table td:nth-child(9){ width: 260px; }   /* title */

    /* Prevent layout shift from long text (incidents table only) */
    .incidents-table td:not(.col-comment):not(.col-actions){
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* Grid lines (SIEM-style) for incidents table: uniform separators */
    .incidents-table th,
    .incidents-table td{
      border-right: 1px solid rgba(15,23,42,0.06);
    }
    .incidents-table th:last-child,
    .incidents-table td:last-child{
      border-right: none;
    }

    th{ text-align: left; color: var(--muted); font-weight: 800; background: rgba(15,23,42,0.02); }

    /* Center column headers for Incidents table only */
    .incidents-table thead th{
      text-align: center;
      vertical-align: middle;
    }
    tr:hover td{ background: rgba(47,111,237,0.04); }

    .table-scroll{ overflow: auto; }
    /* Default: tables can still have a reasonable minimum */
    .table-scroll table{ min-width: 1200px; }

    /* SIEM-grade fixed grid: keep designed column widths and scroll horizontally instead of squeezing */
    .table-scroll table.tbl-fixed{
      width: max-content;
      min-width: 1400px;
    }

    /* Incidents full table total designed width (sum of fixed columns) */
    .table-scroll table.incidents-table{
      min-width: 1920px;
    }

    /* Slightly tighter spacing on smaller viewports */
    @media (max-width: 1100px){
      th, td{ padding: 8px 8px; }
      .tbl-input{ padding: 6px 8px; }
      .tbl-select{ padding: 6px 8px; }
      .tbl-textarea{ padding: 8px 9px; }
    }

    /* Sticky actions column (flush with table, no separate "window" look) */
    th.col-actions, td.col-actions{
      position: static;
      right: -1px;
      z-index: 6;
      background: inherit;          /* follow row/header background */
      box-shadow: none;            /* remove floating shadow */
      border-left: none;
    }
    thead th.col-actions{
      z-index: 7;
      background: rgba(15,23,42,0.02);
    }

    /* Column sizing: comment fixed, actions flexible */
    th.col-comment, td.col-comment{ width: 320px; min-width: 320px; max-width: 320px; }
    th.col-actions, td.col-actions{ min-width: 150px; }

    /* Small gap only: textarea should extend up to actions column */
    td.col-comment{ padding-right: 14px; }

    /* Actions cell: SIEM-style alignment */
    td.col-actions{
      vertical-align: top;
      padding: 12px 10px;        /* space above and below the button */
      display: flex;
      align-items: flex-start;   /* do not stretch the Save button to textarea height */
    }

    /* Save button: SIEM-style, visually part of row */
    td.col-actions .tbl-btn{
      width: 100%;
      height: 36px;              /* real fixed button height */
      min-height: 36px;
      max-height: 36px;
      margin: 0;                 /* spacing handled by td padding */
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0 18px;           /* horizontal padding only */
      border-radius: 12px;
      background: linear-gradient(135deg, rgba(47,111,237,0.95), rgba(47,111,237,0.70));
      border: 1px solid rgba(47,111,237,0.55);
      color: #ffffff;
      font-weight: 800;
      font-size: 20px;           /* normal readable size */
      letter-spacing: 0.4px;
      box-sizing: border-box;
      line-height: 1;            /* text fully centered vertically */
    }
    td.col-actions .tbl-btn:hover{
      filter: brightness(1.04);
    }
    td.col-actions .tbl-btn:active{
      transform: translateY(1px);
    }

    .tbl-textarea{
      padding: 9px 10px;
      border-radius: 12px;
      border: 1px solid rgba(15,23,42,0.12);
      background: rgba(15,23,42,0.02);
      font-size: 12px;
      outline: none;
      width: 100%;
      box-sizing: border-box;
      min-width: 0;
      height: 76px;                 /* fixed height aligned with Save button */
      min-height: 76px;
      max-height: 76px;
      overflow-y: auto;             /* scroll inside if text exceeds */
      line-height: 1.35;
      resize: none;                 /* fixed height for table alignment */
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      max-width: 100%;
      min-width: 100%;
    }
    .tbl-textarea:focus{
      background: #fff;
      border-color: rgba(47,111,237,0.35);
      box-shadow: 0 0 0 4px rgba(47,111,237,0.10);
    }
    .subcell{ margin-top: 4px; font-size: 11px; color: rgba(15,23,42,0.55); }

    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .muted{ color: var(--muted); }

    /* Pipeline */
    .pipeline{ display:flex; flex-wrap: wrap; gap: 10px; align-items:center; }
    .step{
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(15,23,42,0.10);
      background: #fff;
      display:flex; align-items:center; gap: 10px;
      box-shadow: var(--shadow);
      font-size: 12px;
    }
    .arrow{ color: var(--muted2); font-weight: 900; }

    /* Charts */
    .chart-wrap{ display:flex; gap: 14px; flex-wrap: wrap; align-items: stretch; }
    .chart{
      flex: 1 1 300px;
      min-height: 240px;
    }
    canvas{ width: 100%; height: 220px; }

    /* Sections */
    .section{ display:none; }
    .section.active{ display:block; }

    /* Small helpers */
    .row{ display:flex; gap: 12px; flex-wrap: wrap; }
    .right{ margin-left:auto; }

    .note{ font-size: 12px; color: var(--muted); }

  </style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="logo"></div>
      <div class="t">
        <b>VKR SIEM</b>
        <span>Unified Monitoring</span>
      </div>
    </div>

    <nav class="nav" id="nav">
      <a href="#/dashboard" data-route="dashboard">Панель мониторинга <small id="navKpi">—</small></a>
      <a href="#/alerts" data-route="alerts">Алерты <small id="navAlerts">0</small></a>
      <a href="#/events" data-route="events">События (Raw) <small id="navEvents">0</small></a>
      <a href="#/aggregated" data-route="aggregated">Агрегированные <small id="navAgg">0</small></a>
      <a href="#/incidents" data-route="incidents">Инциденты <small id="navIncidents">0</small></a>
      <a href="#/assets" data-route="assets">Активы (Asset DB) <small>demo</small></a>
      <a href="#/integrations" data-route="integrations">Интеграции <small>REST/Webhooks</small></a>
      <a href="#/reports" data-route="reports">Отчёты <small>dashboards</small></a>
      <a href="#/metrics" data-route="metrics">Метрики <small>API</small></a>
      <a href="#/simulation" data-route="simulation">Симулятор атак <small>demo</small></a>
    </nav>

    
  </aside>

  <main class="main">
    <div class="topbar">
      <div>
        <h1 id="pageTitle">Панель мониторинга</h1>
        <div class="sub">Интерфейс соответствует блок-схеме: сбор → нормализация → обогащение → агрегация → риск → корреляция → инциденты → отчётность</div>
      </div>

      <div class="rightbar">
        <div class="pill">
          <div id="dot" class="dot"></div>
          <div class="mono muted" id="status">Ready</div>
        </div>
        <div class="pill">
          <span class="muted">Обновлено:</span>
          <span class="mono" id="updated">—</span>
        </div>
      </div>
    </div>

    <!-- DASHBOARD -->
    <section id="sec-dashboard" class="section">

      <div class="card" style="margin-bottom: 14px;">
        <div class="hdr"><b>Источники</b><span>Firewall / AV / EDR / IAM/AD / Endpoints</span></div>
        <div class="body">
          <div class="grid cols-4" id="sourcesCards"></div>
          
        </div>
      </div>

      <div class="card" style="margin-bottom: 14px;">
        <div class="hdr"><b>Pipeline Overview</b><span>по блок-схеме</span></div>
        <div class="body">
          <div class="pipeline">
            <div class="step"><b>Collectors</b><span class="muted">/api/ingest</span></div><span class="arrow">→</span>
            <div class="step"><b>Raw store</b><span class="muted">data/raw</span></div><span class="arrow">→</span>
            <div class="step"><b>Normalization</b><span class="muted">Unified schema</span></div><span class="arrow">→</span>
            <div class="step"><b>Enrichment</b><span class="muted">Asset DB</span></div><span class="arrow">→</span>
            <div class="step"><b>Aggregation</b><span class="muted">T=5m</span></div><span class="arrow">→</span>
            <div class="step"><b>Risk scoring</b><span class="muted">priority/risk</span></div><span class="arrow">→</span>
            <div class="step"><b>Correlation</b><span class="muted">rules</span></div><span class="arrow">→</span>
            <div class="step"><b>Incidents</b><span class="muted">statuses/SLA</span></div><span class="arrow">→</span>
            <div class="step"><b>Reporting</b><span class="muted">dashboards</span></div>
          </div>

          <div style="height:12px"></div>
          <div class="kpis">
            <div class="kpi"><div class="t">Raw events</div><div class="v" id="kpiRaw">0</div><div class="s" id="kpiRawS">/api/events (если есть)</div></div>
            <div class="kpi"><div class="t">Aggregated events</div><div class="v" id="kpiAgg">0</div><div class="s">/api/events-aggregated</div></div>
            <div class="kpi"><div class="t">Alerts</div><div class="v" id="kpiAlerts">0</div><div class="s">/api/alerts</div></div>
            <div class="kpi"><div class="t">Incidents</div><div class="v" id="kpiIncidents">0</div><div class="s">/api/incidents</div></div>
            <div class="kpi"><div class="t">System</div><div class="v" id="kpiSys">OK</div><div class="s" id="kpiSysS">health</div></div>
          </div>
        </div>
      </div>

      <div class="grid cols-2" style="margin-bottom: 14px;">
        <div class="card">
          <div class="hdr"><b>Последние алерты</b><span>последние 10</span></div>
          <div class="body" style="padding:0">
            <table>
              <thead>
                <tr>
                  <th>Уровень</th>
                  <th>Тип</th>
                  <th>Источник</th>
                  <th>Время</th>
                  <th>Описание</th>
                </tr>
              </thead>
              <tbody id="tblAlerts"><tr><td colspan="5" class="muted" style="padding:14px">loading...</td></tr></tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="hdr"><b>Последние инциденты</b><span>последние 10</span></div>
          <div class="body" style="padding:0">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Тип</th>
                  <th>First seen</th>
                  <th>Title</th>
                </tr>
              </thead>
              <tbody id="tblIncidents"><tr><td colspan="5" class="muted" style="padding:14px">loading...</td></tr></tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="grid cols-2">
        <div class="card">
          <div class="hdr"><b>Alerts over time</b><span>bar (демо)</span></div>
          <div class="body"><canvas id="chartAlerts" width="800" height="260"></canvas><div class="note">Строится по timestamps алертов (последние 80 точек).</div></div>
        </div>
        <div class="card">
          <div class="hdr"><b>Incidents by Type / Severity</b><span>donut (демо)</span></div>
          <div class="body" class="chart-wrap">
            <div class="chart"><canvas id="chartIncType" width="800" height="260"></canvas></div>
            <div class="chart"><canvas id="chartIncSev" width="800" height="260"></canvas></div>
            <div class="note">Тип/важность берутся из объектов инцидентов (type/severity).</div>
          </div>
        </div>
      </div>
    </section>

    <!-- ALERTS -->
    <section id="sec-alerts" class="section">
      <div class="card">
        <div class="hdr"><b>Алерты</b><span>живой поток (последние 50)</span></div>
        <div class="body table-scroll" style="padding:0">
          <table>
            <thead>
              <tr>
                <th>Priority</th>
                <th>Risk</th>
                <th>Type</th>
                <th>src_ip</th>
                <th>dst_ip</th>
                <th>user</th>
                <th>time</th>
                <th>snippet</th>
              </tr>
            </thead>
            <tbody id="tblAlertsFull"></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- EVENTS RAW -->
    <section id="sec-events" class="section">
      <div class="card">
        <div class="hdr"><b>События (Raw)</b><span>если API /api/events отсутствует — покажет N/A</span></div>
        <div class="body">
          <div class="note">Этот раздел соответствует блоку «Хранилище сырых событий». Для UI нужен endpoint <span class="mono">GET /api/events?limit=...</span></div>
          <pre class="mono" id="rawJson" style="margin-top:10px; background:#0b1220; color:#e5e7eb; padding:12px; border-radius:14px; overflow:auto; max-height:520px;">loading...</pre>
        </div>
      </div>
    </section>

    <!-- AGGREGATED -->
    <section id="sec-aggregated" class="section">
      <div class="card">
        <div class="hdr"><b>Агрегированные события</b><span>T=5 минут, dedup</span></div>
        <div class="body" style="padding:0">
          <table>
            <thead>
              <tr>
                <th>count</th>
                <th>first_seen</th>
                <th>last_seen</th>
                <th>event_type</th>
                <th>src_ip</th>
                <th>dst_ip</th>
                <th>host</th>
                <th>user</th>
              </tr>
            </thead>
            <tbody id="tblAgg"></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- INCIDENTS -->
    <section id="sec-incidents" class="section">
      <div class="card">
        <div class="hdr"><b>Инциденты</b></div>
        <div class="body table-scroll" style="padding:0">
          <table class="tbl-fixed incidents-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>SEVERITY</th>
                <th>STATUS</th>
                <th>SLA</th>
                <th>ASSIGNEE</th>
                <th>TYPE</th>
                <th>FIRST_SEEN</th>
                <th>ASSET</th>
                <th>TITLE</th>
                <th class="col-comment">DESCRIPTIONS</th>
                <th class="col-actions">ACTIONS</th>
              </tr>
            </thead>
            <tbody id="tblIncidentsFull"></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ASSETS -->
    <section id="sec-assets" class="section">
      <div class="card">
        <div class="hdr"><b>Активы (Asset DB)</b><span>демо CMDB</span></div>
        <div class="body">
          <div class="note">Это демо-витрина «Базы активов» из блок-схемы. Сейчас Asset DB живёт в collector.py (in-memory). Позже можно вынести в отдельный сервис и сделать CRUD.</div>
          <pre class="mono" id="assetJson" style="margin-top:10px; background:#0b1220; color:#e5e7eb; padding:12px; border-radius:14px; overflow:auto; max-height:520px;">loading...</pre>
        </div>
      </div>
    </section>

    <!-- INTEGRATIONS -->
    <section id="sec-integrations" class="section">
      <div class="card">
        <div class="hdr"><b>Интеграции</b><span>REST API / Webhooks</span></div>
        <div class="body">
          <div class="note">Под этот блок обычно делают webhook на создание инцидента (например, отправка в Telegram/Email/ServiceDesk). Для демо достаточно показывать, что endpoint существует и конфиг читается из env.</div>
          <ul class="note">
            <li><span class="mono">WEBHOOK_URL</span> (env) — куда отправлять уведомления</li>
            <li>Событие: создание инцидента корреляцией</li>
          </ul>
          <div class="note">(Если хочешь — следующим шагом добавим реальную отправку webhook.)</div>
        </div>
      </div>
    </section>

    <!-- REPORTS -->
    <section id="sec-reports" class="section">
      <div class="card">
        <div class="hdr"><b>Отчёты</b><span>дашборды / метрики</span></div>
        <div class="body">
          <div class="note">Этот раздел соответствует «Отчётность / Дашборды / Метрики». Сейчас дашборд реализован на главной странице. Можно добавить экспорт JSON/CSV позже.</div>
        </div>
      </div>
    </section>

    <!-- METRICS -->
    <section id="sec-metrics" class="section">
      <div class="card">
        <div class="hdr"><b>Метрики</b><span>GET /api/metrics</span></div>
        <div class="body">
          <div class="note">UI читает метрики отсюда. Если endpoint отсутствует — показывается N/A.</div>
          <pre class="mono" id="metricsJson" style="margin-top:10px; background:#0b1220; color:#e5e7eb; padding:12px; border-radius:14px; overflow:auto; max-height:520px;">loading...</pre>
        </div>
      </div>
    </section>

    <!-- SIMULATION -->
    <section id="sec-simulation" class="section">
      <div class="card">
        <div class="hdr"><b>Симулятор атак</b><span>API: /api/sim/*</span></div>
        <div class="body">
          <div class="row">
            <select id="attackSelect">
              <option value="vpn_bruteforce">VPN Bruteforce (T1110)</option>
              <option value="vpn_compromise">Bruteforce → Success (T1110 + T1078)</option>
              <option value="portscan">Port Scan (T1046)</option>
              <option value="lateral">Lateral Movement (T1021)</option>
              <option value="malware">Malware Detected (T1204)</option>
              <option value="av_quarantine">AV Quarantine (T1567)</option>
              <option value="av_clean_fail">AV Clean Failed (T1204)</option>
              <option value="av_disabled">AV Disabled / Tamper (T1562.001)</option>
              <option value="edr_suspicious_process">EDR Suspicious Process (T1059)</option>
              <option value="edr_credential_dump">EDR Credential Dump (T1003)</option>
              <option value="edr_lateral_tool">EDR Lateral Tool (T1021)</option>
              <option value="edr_ransomware">EDR Ransomware Behavior (T1486)</option>
              <option value="iam_password_spray">IAM Password Spray (T1110.003)</option>
              <option value="iam_auth_success">IAM Auth Success (T1078)</option>
              <option value="iam_admin_group_change">IAM Admin Group Change (T1098)</option>
              <option value="endpoint_login_fail">Endpoint Login Fail Burst (T1110)</option>
              <option value="endpoint_powershell">Endpoint PowerShell Encoded (T1059.001)</option>
              <option value="endpoint_service_create">Endpoint Service Create (T1543.003)</option>
            </select>

            <button class="btn primary" onclick="runAttack()">Start attack</button>
            <button class="btn" onclick="runRandomAttack()">Start random</button>
            <button class="btn danger" onclick="stopAttack()">Stop</button>
            <button class="btn" onclick="resetData()">Reset data</button>
          </div>
          <div class="note" style="margin-top:10px">Симулятор помогает на защите: показывает поток событий → алерты → инциденты.</div>
        </div>
      </div>
    </section>

  </main>
</div>

<script>
// ---------------------------
// Small helpers
// ---------------------------
function setStatus(text, level){
  const statusEl = document.getElementById('status');
  const dot = document.getElementById('dot');
  statusEl.textContent = text;
  dot.classList.remove('ok','warn','bad');
  if(level === 'ok') dot.classList.add('ok');
  else if(level === 'warn') dot.classList.add('warn');
  else if(level === 'bad') dot.classList.add('bad');
}

function fmtTime(s){
  if(!s) return '—';
  try{
    const d = new Date(s);
    if(!isNaN(d.getTime())) return d.toLocaleString();
  }catch(e){}
  return String(s);
}

function sevBadge(val){
  const s = (val || '').toString().toLowerCase();
  if(s.includes('crit')) return '<span class="badge bad">CRITICAL</span>';
  if(s.includes('high')) return '<span class="badge warn">HIGH</span>';
  if(s.includes('med')) return '<span class="badge warn">MEDIUM</span>';
  return '<span class="badge ok">OK</span>';
}

function priorityBadge(val){
  const s = (val || '').toString().toLowerCase();
  if(s.includes('crit')) return '<span class="badge bad">CRITICAL</span>';
  if(s.includes('high')) return '<span class="badge warn">HIGH</span>';
  return '<span class="badge ok">LOW</span>';
}

function esc(s){
  return String(s ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
}

function statusBadge(val){
  const s = (val || '').toString().toLowerCase();
  if(s.includes('new')) return '<span class="badge warn">NEW</span>';
  if(s.includes('progress')) return '<span class="badge warn">IN&nbsp;PROGRESS</span>';
  if(s.includes('resolved')) return '<span class="badge ok">RESOLVED</span>';
  if(s.includes('closed')) return '<span class="badge ok">CLOSED</span>';
  return '<span class="badge">' + esc(val || '—') + '</span>';
}

async function patchIncident(incidentId, payload){
  try{
    const r = await fetch('/api/incidents/' + encodeURIComponent(incidentId), {
      method: 'PATCH',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload || {})
    });
    if(!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  }catch(e){
    return null;
  }
}

function statusSelectHtml(incidentId, current){
  const cur = (current || 'New');
  const opts = ['New','In Progress','Resolved','Closed'];
  const o = opts.map(x => `<option value="${esc(x)}" ${x===cur?'selected':''}>${esc(x)}</option>`).join('');
  return `<select class="tbl-select" data-incident-id="${esc(incidentId)}" data-role="status">${o}</select>`;
}

async function safeJson(url){
  try{
    const r = await fetch(url);
    if(!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  }catch(e){
    return null;
  }
}

function sumBy(arr, keyFn){
  const m = new Map();
  for(const x of arr){
    const k = keyFn(x);
    m.set(k, (m.get(k) || 0) + 1);
  }
  return Array.from(m.entries()).sort((a,b)=>b[1]-a[1]);
}

// ---------------------------
// Charts (canvas, no libs)
// ---------------------------
function drawBars(canvas, values){
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0,0,w,h);

  const pad = 26;
  const max = Math.max(1, ...values.map(v=>v.v));

  // axis
  ctx.fillStyle = 'rgba(15,23,42,0.25)';
  ctx.fillRect(pad, h-pad, w-2*pad, 1);

  const n = values.length;
  if(n === 0) return;
  const barW = (w - 2*pad) / n;

  for(let i=0;i<n;i++){
    const v = values[i].v;
    const bh = Math.round((h-2*pad) * (v / max));
    const x = pad + i*barW + 2;
    const y = (h - pad) - bh;

    // bar
    ctx.fillStyle = 'rgba(47,111,237,0.55)';
    ctx.fillRect(x, y, Math.max(2, barW-4), bh);
  }

  // labels (few)
  ctx.fillStyle = 'rgba(15,23,42,0.55)';
  ctx.font = '12px ui-sans-serif, system-ui';
  const step = Math.max(1, Math.floor(n/6));
  for(let i=0;i<n;i+=step){
    const label = values[i].k;
    ctx.fillText(label, pad + i*barW + 2, h-8);
  }
}

function drawDonut(canvas, entries, title){
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0,0,w,h);

  const cx = Math.round(w*0.32);
  const cy = Math.round(h*0.50);
  const r1 = Math.min(w,h)*0.30;
  const r0 = r1*0.62;

  const total = entries.reduce((a,e)=>a+e[1],0) || 1;
  let a0 = -Math.PI/2;

  // palette
  const pal = [
    'rgba(47,111,237,0.75)',
    'rgba(22,163,74,0.70)',
    'rgba(245,158,11,0.75)',
    'rgba(239,68,68,0.70)',
    'rgba(99,102,241,0.70)',
    'rgba(14,165,233,0.65)'
  ];

  entries.forEach((e, idx)=>{
    const frac = e[1]/total;
    const a1 = a0 + frac*2*Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.fillStyle = pal[idx % pal.length];
    ctx.arc(cx,cy,r1,a0,a1);
    ctx.closePath();
    ctx.fill();
    a0 = a1;
  });

  // hole
  ctx.beginPath();
  ctx.fillStyle = '#ffffff';
  ctx.arc(cx,cy,r0,0,2*Math.PI);
  ctx.fill();

  // title
  ctx.fillStyle = 'rgba(15,23,42,0.85)';
  ctx.font = '700 14px ui-sans-serif, system-ui';
  ctx.fillText(title, 14, 22);

  // legend
  ctx.font = '12px ui-sans-serif, system-ui';
  ctx.fillStyle = 'rgba(15,23,42,0.70)';
  let ly = 44;
  const lx = Math.round(w*0.62);
  entries.slice(0,6).forEach((e, idx)=>{
    ctx.fillStyle = pal[idx % pal.length];
    ctx.fillRect(lx, ly-10, 10, 10);
    ctx.fillStyle = 'rgba(15,23,42,0.75)';
    ctx.fillText(`${e[0]}  (${e[1]})`, lx+14, ly);
    ly += 18;
  });
}

// ---------------------------
// Routing
// ---------------------------
const ROUTES = [
  {id:'dashboard', title:'Панель мониторинга'},
  {id:'alerts', title:'Алерты'},
  {id:'events', title:'События (Raw)'},
  {id:'aggregated', title:'Агрегированные'},
  {id:'incidents', title:'Инциденты'},
  {id:'assets', title:'Активы (Asset DB)'},
  {id:'integrations', title:'Интеграции'},
  {id:'reports', title:'Отчёты'},
  {id:'metrics', title:'Метрики'},
  {id:'simulation', title:'Симулятор атак'},
];

function setRoute(routeId){
  for(const r of ROUTES){
    const sec = document.getElementById('sec-' + r.id);
    if(sec) sec.classList.toggle('active', r.id === routeId);
  }
  const t = ROUTES.find(x=>x.id===routeId)?.title || 'Панель мониторинга';
  document.getElementById('pageTitle').textContent = t;

  for(const a of document.querySelectorAll('#nav a')){
    a.classList.toggle('active', a.dataset.route === routeId);
  }
}

function currentRoute(){
  const h = (location.hash || '#/dashboard').replace('#/','');
  const exists = ROUTES.some(r=>r.id===h);
  return exists ? h : 'dashboard';
}

window.addEventListener('hashchange', ()=> setRoute(currentRoute()));

// ---------------------------
// Data rendering
// ---------------------------
function renderSources(){
  const sources = [
    {name:'Firewall', sub:'Syslog/CEF', k:'firewall', sev:'critical'},
    {name:'Antivirus', sub:'CEF', k:'av', sev:'critical'},
    {name:'EDR System', sub:'API/JSON', k:'edr', sev:'high'},
    {name:'IAM/AD', sub:'IAM/AD', k:'iam', sev:'medium'},
    {name:'Endpoints', sub:'OS logs', k:'endpoints', sev:'medium'},
  ];
  const host = document.getElementById('sourcesCards');
  host.innerHTML = '';
  for(const s of sources){
    const sev = s.sev;
    const badge = sev.includes('crit') ? 'bad' : (sev.includes('high') || sev.includes('med') ? 'warn' : 'ok');
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = `
      <div class="hdr"><b>${s.name}</b><span>${s.sub}</span></div>
      <div class="body">
        <div class="row">
          <div class="badge ${badge}">${sev.toUpperCase()}</div>
          <div class="right mono muted" id="src-${s.k}">—</div>
        </div>
        <div class="note" style="margin-top:10px">Счётчик событий</div>
      </div>
    `;
    host.appendChild(div);
  }
}

function renderAlertsTables(items){
  const top = items.slice(0,10);
  const tb = document.getElementById('tblAlerts');
  tb.innerHTML = '';
  if(top.length === 0){
    tb.innerHTML = '<tr><td colspan="5" class="muted" style="padding:14px">Нет алертов</td></tr>';
  }else{
    for(const a of top){
      const pri = a.priority || '';
      const t = a.event_type || a.type || '';
      const src = a.source_type || a.source || '';
      const ts = a.received_at || a.time || a.ts || '';
      const sn = a.snippet || a.message || '';
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${priorityBadge(pri)}</td>
        <td class="mono">${t}</td>
        <td class="mono muted">${src}</td>
        <td class="mono">${fmtTime(ts)}</td>
        <td>${sn}</td>
      `;
      tb.appendChild(row);
    }
  }

  const full = document.getElementById('tblAlertsFull');
  full.innerHTML = '';
  for(const a of items.slice(0,50)){
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${priorityBadge(a.priority)}</td>
      <td class="mono">${(a.risk ?? '')}</td>
      <td class="mono">${a.event_type || ''}</td>
      <td class="mono">${a.src_ip || ''}</td>
      <td class="mono">${a.dst_ip || ''}</td>
      <td class="mono">${a.user || ''}</td>
      <td class="mono">${fmtTime(a.received_at)}</td>
      <td>${a.snippet || ''}</td>
    `;
    full.appendChild(row);
  }
}

function renderIncidentsTables(items){
  // Dashboard table (top 10)
  const top = items.slice(0,10);
  const tb = document.getElementById('tblIncidents');
  tb.innerHTML = '';
  if(top.length === 0){
    tb.innerHTML = '<tr><td colspan="5" class="muted" style="padding:14px">Нет инцидентов</td></tr>';
  }else{
    for(const it of top){
      const sev = it.severity || '';
      const st = it.status || 'New';
      const type = it.type || '';
      const fs = it.first_seen || it.created_at || '';
      const title = it.title || '';
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${sevBadge(sev)}</td>
        <td>${statusBadge(st)}</td>
        <td class="mono">${esc(type)}</td>
        <td class="mono">${fmtTime(fs)}</td>
        <td>
          <div>${esc(title)}</div>
          ${it.comment ? `<div class="subcell">${esc(String(it.comment).slice(0,90))}${String(it.comment).length>90?'…':''}</div>` : ''}
        </td>
      `;
      tb.appendChild(row);
    }
  }

  // Full incidents table with controls
  const full = document.getElementById('tblIncidentsFull');
  full.innerHTML = '';
  for(const it of items.slice(0,50)){
    const id = it.incident_id || it.id || '';
    const sev = it.severity || '';
    const st = it.status || 'New';
    const sla = it.sla_minutes ?? '';
    const assignee = it.assignee || '';
    const type = it.type || '';
    const fs = it.first_seen || it.created_at || '';
    const asset = it.asset_id ? `${it.asset_id}${it.asset_criticality ? ' (crit '+it.asset_criticality+')' : ''}` : '';
    const title = it.title || '';
    const comment = it.comment || '';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono">${esc(id)}</td>
      <td>${sevBadge(sev)}</td>
      <td>${statusSelectHtml(id, st)}</td>
      <td class="mono muted">${esc(sla)}</td>
      <td><input class="tbl-input mid" data-incident-id="${esc(id)}" data-role="assignee" value="${esc(assignee)}" placeholder="SOC-1"/></td>
      <td class="mono">${esc(type)}</td>
      <td class="mono">${fmtTime(fs)}</td>
      <td class="mono muted">${esc(asset)}</td>
      <td>${esc(title)}</td>
      <td class="col-comment"><textarea class="tbl-textarea" rows="2" style="width:100%" data-incident-id="${esc(id)}" data-role="comment" placeholder="Комментарий (сохраняется кнопкой Save)">${esc(comment)}</textarea></td>
      <td class="col-actions"><button class="tbl-btn" data-incident-id="${esc(id)}" data-action="save">Save</button></td>
    `;
    full.appendChild(row);
  }

  // Wire handlers (delegation)
  full.querySelectorAll('select[data-role="status"]').forEach(sel => {
    sel.addEventListener('change', async (e)=>{
      const incidentId = sel.getAttribute('data-incident-id');
      const v = sel.value;
      const ok = await patchIncident(incidentId, {status: v});
      if(!ok) {
        setStatus('Failed to update status', 'bad');
      } else {
        setStatus('Incident updated', 'ok');
        setEditing(false);
        await refresh();
      }
    });
  });

  full.querySelectorAll('button[data-action="save"]').forEach(btn => {
    btn.addEventListener('click', async ()=>{
      const incidentId = btn.getAttribute('data-incident-id');
      const ass = full.querySelector(`input[data-role="assignee"][data-incident-id="${CSS.escape(incidentId)}"]`);
      const com = full.querySelector(`textarea[data-role="comment"][data-incident-id="${CSS.escape(incidentId)}"]`);
      const payload = {assignee: ass ? ass.value : '', comment: com ? com.value : ''};
      const ok = await patchIncident(incidentId, payload);
      if(!ok) {
        setStatus('Failed to save incident fields', 'bad');
      } else {
        setStatus('Incident updated', 'ok');
        setEditing(false);
        await refresh();
      }
    });
  });

  // prevent refresh from overwriting user input while editing
  attachEditingGuards(full);
  // auto-grow comments so rows expand downward (no overlap with Save)
  attachAutoGrow(full);
}

function renderCharts(alerts, incidents){
  // Alerts over time: bucket by minute label
  const pts = alerts
    .map(a=>a.received_at)
    .filter(Boolean)
    .map(s=>{
      const d = new Date(s);
      if(isNaN(d.getTime())) return null;
      const hh = String(d.getHours()).padStart(2,'0');
      const mm = String(d.getMinutes()).padStart(2,'0');
      return `${hh}:${mm}`;
    })
    .filter(Boolean);

  const buckets = new Map();
  for(const k of pts){ buckets.set(k, (buckets.get(k)||0)+1); }
  const arr = Array.from(buckets.entries()).sort((a,b)=>a[0].localeCompare(b[0])).slice(-80).map(([k,v])=>({k,v}));

  const c1 = document.getElementById('chartAlerts');
  if(c1) drawBars(c1, arr);

  const byType = sumBy(incidents, (x)=> (x.type || 'unknown'));
  const bySev = sumBy(incidents, (x)=> (x.severity || 'unknown'));

  const c2 = document.getElementById('chartIncType');
  const c3 = document.getElementById('chartIncSev');
  if(c2) drawDonut(c2, byType.slice(0,6), 'Incidents by Type');
  if(c3) drawDonut(c3, bySev.slice(0,6), 'Incidents by Severity');
}

// ---------------------------
// Editing guard for incidents table (prevents refresh during edit)
// ---------------------------
let isEditing = false;

function setEditing(v){
  isEditing = !!v;
}

function attachEditingGuards(root){
  if(!root) return;
  root.querySelectorAll('input.tbl-input, textarea.tbl-textarea, select.tbl-select').forEach(el => {
    el.addEventListener('focus', ()=> setEditing(true));
    el.addEventListener('blur', ()=> setEditing(false));
  });
}
// ---------------------------
// Auto-grow for incident comment textarea (SIEM-like UX)
// ---------------------------
function attachAutoGrow(root){
  // disabled: fixed-height comment field (76px)
}
// ---------------------------
// Refresh loop
// ---------------------------
async function refresh(){
  if(isEditing) return;
  // Metrics (optional)
  const m = await safeJson('/api/metrics');
  if(m){
    document.getElementById('kpiRaw').textContent = (m.events_raw ?? 0);
    document.getElementById('kpiAgg').textContent = (m.events_aggregated ?? 0);
    document.getElementById('kpiAlerts').textContent = (m.alerts ?? 0);
    document.getElementById('kpiIncidents').textContent = (m.incidents ?? 0);

    document.getElementById('navEvents').textContent = (m.events_raw ?? 0);
    document.getElementById('navAgg').textContent = (m.events_aggregated ?? 0);
    document.getElementById('navAlerts').textContent = (m.alerts ?? 0);
    document.getElementById('navIncidents').textContent = (m.incidents ?? 0);
    document.getElementById('navKpi').textContent = `${m.alerts ?? 0}/${m.incidents ?? 0}`;

    document.getElementById('metricsJson').textContent = JSON.stringify(m, null, 2);

    // Per-source counters (Источники)
    const bs = (m.by_source || {});
    const map = {
      firewall: 'src-firewall',
      av: 'src-av',
      edr: 'src-edr',
      iam: 'src-iam',
      endpoints: 'src-endpoints'
    };
    for(const k of Object.keys(map)){
      const el = document.getElementById(map[k]);
      if(el) el.textContent = (bs[k] ?? 0);
    }
  }else{
    document.getElementById('kpiRaw').textContent = 'N/A';
    document.getElementById('kpiAgg').textContent = 'N/A';
    document.getElementById('kpiSys').textContent = 'N/A';
    document.getElementById('metricsJson').textContent = 'N/A (endpoint /api/metrics не найден)';
  }

  // Alerts
  const a = await safeJson('/api/alerts?limit=50');
  const alerts = (a && (a.items || a.alerts)) ? (a.items || a.alerts) : [];
  renderAlertsTables(alerts);

  // Incidents
  const i = await safeJson('/api/incidents?limit=50');
  const incidents = (i && (i.items || i.incidents)) ? (i.items || i.incidents) : [];
  renderIncidentsTables(incidents);

  // Aggregated events
  const ag = await safeJson('/api/events-aggregated?limit=50');
  const aggItems = (ag && (ag.items || ag.events)) ? (ag.items || ag.events) : [];
  const tb = document.getElementById('tblAgg');
  tb.innerHTML = '';
  if(aggItems.length === 0){
    tb.innerHTML = '<tr><td colspan="8" class="muted" style="padding:14px">Нет агрегированных событий (или endpoint не найден)</td></tr>';
  }else{
    for(const e of aggItems){
      const row = document.createElement('tr');
      row.innerHTML = `
        <td class="mono">${e.count ?? ''}</td>
        <td class="mono">${fmtTime(e.first_seen)}</td>
        <td class="mono">${fmtTime(e.last_seen)}</td>
        <td class="mono">${e.event_type ?? ''}</td>
        <td class="mono">${e.src_ip ?? ''}</td>
        <td class="mono">${e.dst_ip ?? ''}</td>
        <td class="mono">${e.host ?? ''}</td>
        <td class="mono">${e.user ?? ''}</td>
      `;
      tb.appendChild(row);
    }
  }

  // Raw events (optional)
  const ev = await safeJson('/api/events?limit=50');
  document.getElementById('rawJson').textContent = ev ? JSON.stringify(ev, null, 2) : 'N/A (endpoint /api/events не найден)';

  // Asset DB (demo only): try to read from /api/assets if you add it later
  const asset = await safeJson('/api/assets');
  document.getElementById('assetJson').textContent = asset ? JSON.stringify(asset, null, 2) : 'demo: Asset DB находится в app/pipeline/collector.py (ASSET_DB)';

  // Charts
  renderCharts(alerts, incidents);

  // Status
  const now = new Date();
  document.getElementById('updated').textContent = now.toLocaleString();
  if(incidents.some(x => String(x.severity || '').toLowerCase().includes('crit'))){
    setStatus('Critical incidents detected', 'bad');
    document.getElementById('kpiSys').textContent = 'ALERT';
    document.getElementById('kpiSysS').textContent = 'critical';
  }else if(alerts.some(x => String(x.priority || '').toLowerCase().includes('high') || String(x.priority || '').toLowerCase().includes('crit'))){
    setStatus('High alerts present', 'warn');
    document.getElementById('kpiSys').textContent = 'WARN';
    document.getElementById('kpiSysS').textContent = 'high';
  }else{
    setStatus('Operational', 'ok');
    document.getElementById('kpiSys').textContent = 'OK';
    document.getElementById('kpiSysS').textContent = 'normal';
  }
}

// ---------------------------
// Simulator actions (kept)
// ---------------------------
async function runAttack(){
  const mode = document.getElementById('attackSelect').value;
  setStatus('Starting: ' + mode + ' ...', 'warn');
  // safeJson uses GET by default; simulator expects POST, so do POST:
  try{
    const r = await fetch('/api/sim/attack?mode=' + encodeURIComponent(mode), {method:'POST'});
    const j = await r.json();
    if(j.status === 'started') setStatus('Started: ' + mode, 'ok');
    else if(j.status === 'busy') setStatus('Busy: already running', 'warn');
    else setStatus('Error starting attack', 'bad');
  }catch(e){
    setStatus('Error starting attack', 'bad');
  }
}

async function runRandomAttack(){
  setStatus('Starting random attack ...', 'warn');
  try{
    const r = await fetch('/api/sim/attack-random', {method:'POST'});
    const j = await r.json();
    if(j.status === 'started') setStatus('Started random: ' + (j.mode || 'unknown'), 'ok');
    else if(j.status === 'busy') setStatus('Busy: already running', 'warn');
    else setStatus('Error starting random attack', 'bad');
  }catch(e){
    setStatus('Error starting random attack', 'bad');
  }
}

async function stopAttack(){
  setStatus('Stopping attack ...', 'warn');
  try{
    const r = await fetch('/api/sim/attack-stop', {method:'POST'});
    const j = await r.json();
    if(j.status === 'stopping') setStatus('Stopping...', 'ok');
    else if(j.status === 'not_running') setStatus('Not running', 'warn');
    else setStatus('Error stopping attack', 'bad');
  }catch(e){
    setStatus('Error stopping attack', 'bad');
  }
}

async function resetData(){
  setStatus('Resetting data ...', 'warn');
  try{
    const r = await fetch('/api/sim/reset', {method:'POST'});
    const j = await r.json();
    if(j.status === 'ok') setStatus('Reset done', 'ok');
    else setStatus('Error resetting data', 'bad');
  }catch(e){
    setStatus('Error resetting data', 'bad');
  }
  await refresh();
}

// Init
renderSources();
setRoute(currentRoute());
setStatus('Operational', 'ok');
refresh();
setInterval(refresh, 2500);
</script>
</body>
</html>"""

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui_index():
    return HTML
