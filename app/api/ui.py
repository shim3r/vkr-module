from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import HTMLResponse
from typing import Any, Dict, List

router = APIRouter(tags=["ui"])

# --- Service imports (business logic delegated to services) ---
from app.services.metrics_service import compute_metrics, get_assets, search_assets
from app.services.events_store import list_events
from app.services.alerts_store import list_alerts
from app.services.incidents_store import list_incidents, get_incident, update_incident

try:
    from app.services.aggregates_store import list_aggregates
except ImportError:
    list_aggregates = None


def _safe_list(fn, limit: int) -> list:
    if not callable(fn):
        return []
    try:
        data = fn(limit)
        return data if isinstance(data, list) else list(data)
    except Exception:
        return []


# --- API endpoints (no business logic — delegated to metrics_service) ---

@router.get("/api/metrics", include_in_schema=False)
def api_metrics() -> Dict[str, Any]:
    return compute_metrics()


@router.get("/api/events", include_in_schema=False)
def api_events(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_events, limit)
    return {"items": items, "limit": limit}


@router.get("/api/events-aggregated", include_in_schema=False)
def api_events_aggregated(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_aggregates, limit)
    return {"items": items, "count": len(items), "limit": limit}


@router.get("/api/alerts", include_in_schema=False)
def api_alerts(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_alerts, limit)
    return {"items": items, "limit": limit}


@router.get("/api/incidents", include_in_schema=False)
def api_incidents(limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    items = _safe_list(list_incidents, limit)
    return {"items": items, "limit": limit}


@router.patch("/api/incidents/{incident_id}", include_in_schema=False)
def api_patch_incident(incident_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
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
    assets = get_assets()
    return {"items": assets, "count": len(assets)}


@router.get("/api/assets/search", include_in_schema=False)
def api_assets_search(q: str = Query("", min_length=0, max_length=100)) -> Dict[str, Any]:
    filtered = search_assets(q)
    return {"items": filtered, "count": len(filtered), "q": q}

HTML = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>VKR SIEM • Monitoring</title>
  <style>
    :root{
      --bg: #0d1117;
      --bg2: #161b22;
      --panel: #1c2128;
      --panel2: #21262d;
      --border: rgba(240,246,252,0.1);
      --border2: rgba(240,246,252,0.06);
      --text: #e6edf3;
      --text2: #c9d1d9;
      --muted: rgba(230,237,243,0.55);
      --muted2: rgba(230,237,243,0.35);
      --sidebar: #010409;
      --sidebar2: #0d1117;
      --accent: #388bfd;
      --accent2: rgba(56,139,253,0.15);
      --good: #1FB141; /* Aceframe green */
      --warn: #d29922;
      --bad: #f85149;
      --shadow: 0 8px 32px rgba(0,0,0,0.3);
      --radius: 24px; /* Aceframe extreme rounding */
      --radius-sm: 12px;
      --mono: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;
      --row-odd: rgba(255,255,255,0.02);
      --row-hover: rgba(56,139,253,0.08);
      --row-selected: rgba(56,139,253,0.18);
      --glass: rgba(255, 255, 255, 0.03);
      --glass-border: rgba(255, 255, 255, 0.08);
    }

    body.light-theme {
      --bg: #F5F5F7;
      --bg2: #FFFFFF;
      --panel: #FFFFFF;
      --panel2: #F9FAFB;
      --border: rgba(0,0,0,0.06);
      --border2: rgba(0,0,0,0.04);
      --text: #1d1d1f;
      --text2: #424245;
      --muted: rgba(0,0,0,0.5);
      --muted2: rgba(0,0,0,0.3);
      --sidebar: #FFFFFF;
      --sidebar2: #F5F5F7;
      --accent: #0071e3;
      --shadow: 0 8px 32px rgba(0,0,0,0.08);
      --glass: rgba(255, 255, 255, 0.7);
      --glass-border: rgba(0, 0, 0, 0.05);
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

    @media (max-width: 900px) {
      .app { grid-template-columns: 1fr; grid-template-rows: auto 1fr; overflow: auto; }
      body { overflow: auto; height: auto; }
      .sidebar { border-right: none; border-bottom: 1px solid rgba(255,255,255,0.06); height: auto; }
      .main { height: auto; overflow: visible; }
    }

    .sidebar{
      background: linear-gradient(180deg, var(--sidebar), var(--sidebar2));
      color: var(--text);
      border-right: 1px solid var(--border);
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      gap: 20px;
      overflow-y: auto;
      scrollbar-width: thin;
      scrollbar-color: var(--border) transparent;
      z-index: 100;
    }
    .brand{
      display:flex; align-items:center; gap: 14px;
      padding: 12px;
      border-radius: var(--radius-sm);
      background: var(--glass);
      backdrop-filter: blur(10px);
      border: 1px solid var(--glass-border);
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

    .nav{ display:flex; flex-direction: column; gap: 8px; }
    .nav a{
      text-decoration: none;
      color: var(--text2);
      padding: 12px 16px;
      border-radius: var(--radius-sm);
      border: 1px solid transparent;
      background: transparent;
      display:flex; align-items:center; justify-content: space-between;
      gap: 10px;
      font-size: 14px;
      transition: all 0.2s ease;
    }
    .nav a:hover{ background: var(--bg2); border-color: var(--border); }
    .nav a.active{ background: var(--accent2); border-color: var(--accent); color: var(--accent); font-weight: 600; }
    .nav small{ color: var(--muted); font-weight: 600; font-size: 11px; }

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
      padding: 8px 16px;
      border-radius: 999px;
      background: var(--glass);
      backdrop-filter: blur(8px);
      border: 1px solid var(--glass-border);
      box-shadow: var(--shadow);
      min-height: 40px;
    }
    .dot{ width: 10px; height: 10px; border-radius: 999px; background: #94a3b8; }
    .dot.ok{ background: var(--good); box-shadow: 0 0 12px var(--good); }
    .dot.warn{ background: var(--warn); box-shadow: 0 0 12px var(--warn); }
    .dot.bad{ background: var(--bad); box-shadow: 0 0 12px var(--bad); }

    select{
      padding: 10px 16px;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      outline: none;
      min-width: 280px;
      box-shadow: var(--shadow);
      appearance: none;
    }

    .btn{
      padding: 10px 20px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--panel);
      color: var(--text);
      cursor: pointer;
      font-weight: 600;
      font-size: 14px;
      box-shadow: var(--shadow);
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .btn:hover{ transform: translateY(-2px); box-shadow: 0 12px 40px rgba(0,0,0,0.15); }
    .btn:active{ transform: translateY(0); }
    .btn.primary{ background: var(--text); color: var(--bg); border: none; }
    .btn.danger{ background: rgba(239,68,68,0.1); border-color: rgba(239,68,68,0.2); color: var(--bad); }
    
    .theme-toggle {
      width: 40px;
      height: 40px;
      padding: 0;
      border-radius: 50%;
    }

    .tbl-input{
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--bg2);
      color: var(--text);
      font-size: 12px;
      outline: none;
      width: 100%;
    }
    .tbl-input:focus{ border-color: var(--accent); background: var(--bg); }
    .tbl-input.wide{ min-width: 260px; }
    .tbl-input.mid{ min-width: 160px; }
    .tbl-select{
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--bg2);
      color: var(--text);
      font-size: 12px;
      outline: none;
      min-width: 140px;
    }
    .tbl-select:focus{ border-color: var(--accent); }
    .tbl-btn{
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid rgba(47,111,237,0.30);
      background: rgba(47,111,237,0.15);
      color: var(--text);
      cursor: pointer;
      font-weight: 800;
      font-size: 12px;
    }
    .tbl-btn:hover{ background: rgba(47,111,237,0.25); }

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
      transition: all 0.3s ease;
    }
    .card:hover{ border-color: var(--accent); }
    .card .hdr{
      padding: 20px 24px;
      display:flex; align-items:center; justify-content: space-between;
      gap: 10px;
      border-bottom: 1px solid var(--border);
      background: var(--panel2);
    }
    .card .hdr b{ font-size: 15px; color: var(--text); letter-spacing: -0.01em; }
    .card .hdr span{ color: var(--muted); font-size: 13px; }
    .card .body{ padding: 24px; }

    .kpis{ display:grid; gap: 12px; grid-template-columns: 1fr 1fr; }
    @media (min-width: 980px){ .kpis{ grid-template-columns: repeat(5, 1fr);} }

    .kpi{
      padding: 12px 12px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: var(--panel2);
      box-shadow: var(--shadow);
      min-height: 74px;
    }
    .kpi .t{ color: var(--muted); font-size: 12px; }
    .kpi .v{ margin-top: 6px; font-size: 22px; font-weight: 900; letter-spacing: 0.2px; color: var(--text); }
    .kpi .s{ margin-top: 6px; font-size: 12px; color: var(--muted2); }

    .badge{
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      border: 1px solid rgba(255,255,255,0.12);
      background: rgba(255,255,255,0.06);
      color: var(--text2);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      white-space: nowrap;
      line-height: 1;
    }
    .badge.ok{ color: var(--good); border-color: rgba(22,163,74,0.35); background: rgba(22,163,74,0.12); }
    .badge.warn{ color: var(--warn); border-color: rgba(245,158,11,0.35); background: rgba(245,158,11,0.14); }
    .badge.bad{ color: var(--bad); border-color: rgba(239,68,68,0.35); background: rgba(239,68,68,0.14); }

    /* Tables */
    table{ width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td{ padding: 10px 10px; border-bottom: 1px solid var(--border); font-size: 12px; vertical-align: top; color: var(--text2); }

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
      border-right: 1px solid var(--border2);
    }
    .incidents-table th:last-child,
    .incidents-table td:last-child{
      border-right: none;
    }

    th{ text-align: left; color: var(--muted); font-weight: 800; background: rgba(255,255,255,0.03); }

    /* Center column headers for Incidents table only */
    .incidents-table thead th{
      text-align: center;
      vertical-align: middle;
    }
    tr:hover td{ background: rgba(47,111,237,0.08); }

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
      background: var(--panel2);
    }

    /* Column sizing: comment fixed, actions flexible */
    th.col-comment, td.col-comment{ width: 320px; min-width: 320px; max-width: 320px; }
    th.col-actions, td.col-actions{ min-width: 150px; }

    /* Refactored premium layout for comment and actions */
    td.col-comment, td.col-actions {
      padding: 14px 12px;
      vertical-align: top;
    }
    td.col-comment { padding-right: 8px; } /* Closer to the button */
    td.col-actions { padding-left: 8px; }

    .tbl-comment-box {
      display: block;
      width: 100%;
      height: 84px;
      resize: none;
      margin: 0;
      padding: 12px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--bg2);
      color: var(--text);
      font-size: 13px;
      line-height: 1.4;
      outline: none;
      box-sizing: border-box;
      transition: all 0.2s ease;
    }
    .tbl-comment-box:focus {
      border-color: var(--accent);
      background: var(--bg);
    }
    
    .tbl-save-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      height: 84px;
      margin: 0;
      border-radius: 10px;
      border: 1px solid rgba(47,111,237,0.30);
      background: rgba(47,111,237,0.15);
      color: var(--text);
      font-weight: 800;
      font-size: 14px;
      box-sizing: border-box;
      cursor: pointer;
      transition: all 0.1s ease;
    }
    .tbl-save-btn:hover {
      background: rgba(47,111,237,0.25);
    }
    .tbl-save-btn:active {
      transform: translateY(1px);
    }
    .subcell{ margin-top: 4px; font-size: 11px; color: var(--muted); }

    .mono{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .muted{ color: var(--muted); }

    /* Pipeline */
    .pipeline{ display:flex; flex-wrap: wrap; gap: 10px; align-items:center; }
    .step{
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: var(--panel2);
      display:flex; align-items:center; gap: 10px;
      box-shadow: var(--shadow);
      font-size: 12px;
      color: var(--text);
    }
    .step b{ color: var(--text); }
    .step .muted{ color: var(--muted) !important; }
    .arrow{ color: var(--accent); font-weight: 900; }

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
    .note li{ margin-bottom: 4px; }

    /* ===== SOAR Playbooks Styles ===== */
    .soar-kpis{ display:grid; gap:12px; grid-template-columns: repeat(4, 1fr); margin-bottom:14px; }
    @media (max-width:980px){ .soar-kpis{ grid-template-columns: 1fr 1fr; } }

    .soar-toolbar{
      display:flex; align-items:center; justify-content:space-between;
      flex-wrap:wrap; gap:10px; margin-bottom:14px;
    }
    .soar-toolbar .search-box{
      flex:1; min-width:200px; max-width:400px;
      padding:10px 16px; border-radius:var(--radius-sm);
      border:1px solid var(--border); background:var(--panel);
      color:var(--text); font-size:13px; outline:none;
    }
    .soar-toolbar .search-box:focus{ border-color:var(--accent); }

    .btn-create{
      padding:10px 24px; border-radius:999px;
      background:linear-gradient(135deg, #2563eb, #3b82f6);
      color:#fff; border:none; font-weight:700; font-size:14px;
      cursor:pointer; box-shadow:0 4px 20px rgba(37,99,235,0.3);
      transition:all 0.2s ease; display:inline-flex; align-items:center; gap:8px;
    }
    .btn-create:hover{ transform:translateY(-2px); box-shadow:0 8px 30px rgba(37,99,235,0.4); }
    .btn-create:active{ transform:translateY(0); }

    .pb-grid{ display:grid; gap:14px; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); }

    .pb-card{
      background:var(--panel); border:1px solid var(--border);
      border-radius:var(--radius); box-shadow:var(--shadow);
      overflow:hidden; transition:all 0.3s ease;
      position:relative;
    }
    .pb-card:hover{ border-color:var(--accent); transform:translateY(-2px); }
    .pb-card.disabled{ opacity:0.55; }
    .pb-card .pb-header{
      padding:18px 20px; display:flex; align-items:center;
      justify-content:space-between; gap:10px;
      border-bottom:1px solid var(--border); background:var(--panel2);
    }
    .pb-card .pb-header .pb-title{
      font-weight:700; font-size:15px; color:var(--text);
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
    }
    .pb-card .pb-header .pb-id{
      font-family:var(--mono); font-size:11px; color:var(--muted); margin-top:2px;
    }
    .pb-card .pb-body{ padding:18px 20px; }
    .pb-card .pb-desc{
      color:var(--muted); font-size:12px; line-height:1.5; margin-bottom:14px;
      display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden;
    }

    .pb-flow{
      display:flex; align-items:center; gap:8px;
      padding:12px; background:rgba(0,0,0,0.15);
      border-radius:var(--radius-sm); margin-bottom:14px;
    }
    .pb-flow-col{ flex:1; min-width:0; }
    .pb-flow-label{ font-size:10px; font-weight:800; color:var(--muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
    .pb-flow-arrow{
      color:var(--accent); font-size:18px; font-weight:900;
      flex-shrink:0; padding:0 4px;
    }
    .pb-flow .pb-chip{
      display:inline-block; padding:3px 8px; border-radius:6px;
      font-size:10px; font-weight:700; font-family:var(--mono);
      margin:2px; white-space:nowrap;
    }
    .pb-chip.cond-type{ background:rgba(99,102,241,0.15); color:rgb(129,140,248); border:1px solid rgba(99,102,241,0.25); }
    .pb-chip.cond-sev{ background:rgba(245,158,11,0.12); color:var(--warn); border:1px solid rgba(245,158,11,0.25); }
    .pb-chip.act-block{ background:rgba(239,68,68,0.12); color:var(--bad); border:1px solid rgba(239,68,68,0.25); }
    .pb-chip.act-isolate{ background:rgba(245,158,11,0.12); color:var(--warn); border:1px solid rgba(245,158,11,0.25); }
    .pb-chip.act-disable{ background:rgba(56,139,253,0.12); color:var(--accent); border:1px solid rgba(56,139,253,0.25); }

    .pb-footer{
      display:flex; align-items:center; justify-content:space-between;
      padding:0 20px 16px; gap:8px;
    }
    .pb-actions{ display:flex; gap:6px; }
    .pb-actions button{
      padding:6px 14px; border-radius:8px; font-size:12px; font-weight:600;
      cursor:pointer; border:1px solid var(--border); background:var(--panel2);
      color:var(--text2); transition:all 0.15s ease;
    }
    .pb-actions button:hover{ background:var(--accent2); border-color:var(--accent); color:var(--accent); }
    .pb-actions button.del:hover{ background:rgba(239,68,68,0.12); border-color:rgba(239,68,68,0.4); color:var(--bad); }

    /* Toggle switch */
    .toggle-switch{
      position:relative; width:44px; height:24px; flex-shrink:0;
    }
    .toggle-switch input{ opacity:0; width:0; height:0; }
    .toggle-slider{
      position:absolute; cursor:pointer; inset:0;
      background:rgba(255,255,255,0.1); border-radius:999px;
      border:1px solid var(--border); transition:all 0.25s ease;
    }
    .toggle-slider::before{
      content:''; position:absolute; height:18px; width:18px;
      left:2px; bottom:2px; background:#fff; border-radius:50%;
      transition:all 0.25s ease; box-shadow:0 2px 6px rgba(0,0,0,0.3);
    }
    .toggle-switch input:checked + .toggle-slider{
      background:var(--good); border-color:var(--good);
    }
    .toggle-switch input:checked + .toggle-slider::before{
      transform:translateX(20px);
    }

    /* Modal */
    .soar-modal-overlay{
      position:fixed; inset:0; z-index:9999;
      background:rgba(0,0,0,0.65); backdrop-filter:blur(6px);
      display:none; align-items:center; justify-content:center;
      padding:20px;
    }
    .soar-modal-overlay.open{ display:flex; }
    .soar-modal{
      background:var(--panel); border:1px solid var(--border);
      border-radius:var(--radius); box-shadow:0 24px 80px rgba(0,0,0,0.5);
      width:100%; max-width:640px; max-height:90vh; overflow-y:auto;
      animation:modalSlideIn 0.25s ease;
    }
    @keyframes modalSlideIn{
      from{ opacity:0; transform:translateY(20px) scale(0.97); }
      to{ opacity:1; transform:translateY(0) scale(1); }
    }
    .soar-modal .modal-hdr{
      padding:20px 24px; border-bottom:1px solid var(--border);
      display:flex; align-items:center; justify-content:space-between;
    }
    .soar-modal .modal-hdr h2{ margin:0; font-size:18px; }
    .soar-modal .modal-hdr .close-btn{
      width:32px; height:32px; border-radius:8px; border:none;
      background:var(--panel2); color:var(--text); cursor:pointer;
      font-size:18px; display:flex; align-items:center; justify-content:center;
    }
    .soar-modal .modal-body{ padding:24px; }
    .soar-modal .form-group{ margin-bottom:16px; }
    .soar-modal .form-group label{
      display:block; font-size:12px; font-weight:700;
      color:var(--muted); text-transform:uppercase;
      letter-spacing:0.5px; margin-bottom:6px;
    }
    .soar-modal .form-input{
      width:100%; padding:10px 14px; border-radius:var(--radius-sm);
      border:1px solid var(--border); background:var(--bg2);
      color:var(--text); font-size:14px; outline:none;
      transition:border-color 0.2s;
    }
    .soar-modal .form-input:focus{ border-color:var(--accent); }
    .soar-modal textarea.form-input{ resize:vertical; min-height:60px; font-family:inherit; }

    .multi-select-box{
      display:flex; flex-wrap:wrap; gap:6px; padding:8px;
      border:1px solid var(--border); border-radius:var(--radius-sm);
      background:var(--bg2); min-height:40px;
    }
    .multi-select-box .ms-chip{
      padding:4px 10px; border-radius:6px; font-size:11px; font-weight:700;
      cursor:pointer; transition:all 0.15s ease; border:1px solid var(--border);
      background:var(--panel2); color:var(--text2); user-select:none;
    }
    .multi-select-box .ms-chip.selected{
      background:var(--accent2); border-color:var(--accent); color:var(--accent);
    }
    .multi-select-box .ms-chip:hover{ border-color:var(--accent); }

    .action-rows{ display:flex; flex-direction:column; gap:8px; }
    .action-row{
      display:flex; gap:8px; align-items:center;
      padding:8px 10px; background:var(--bg2);
      border:1px solid var(--border); border-radius:var(--radius-sm);
    }
    .action-row select{
      flex:1; padding:8px 10px; border-radius:8px;
      border:1px solid var(--border); background:var(--panel);
      color:var(--text); font-size:13px; outline:none; min-width:0;
    }
    .action-row .remove-action{
      width:28px; height:28px; border-radius:6px; border:none;
      background:rgba(239,68,68,0.1); color:var(--bad); cursor:pointer;
      font-size:14px; display:flex; align-items:center; justify-content:center;
      flex-shrink:0;
    }
    .add-action-btn{
      padding:8px 14px; border-radius:8px;
      border:1px dashed var(--border); background:transparent;
      color:var(--muted); cursor:pointer; font-size:12px; font-weight:600;
      transition:all 0.15s ease; width:100%;
    }
    .add-action-btn:hover{ border-color:var(--accent); color:var(--accent); background:var(--accent2); }

    .modal-footer{
      padding:16px 24px; border-top:1px solid var(--border);
      display:flex; gap:10px; justify-content:flex-end;
    }
    .modal-footer .btn-save{
      padding:10px 28px; border-radius:999px;
      background:linear-gradient(135deg, #2563eb, #3b82f6);
      color:#fff; border:none; font-weight:700; font-size:14px;
      cursor:pointer; box-shadow:0 4px 16px rgba(37,99,235,0.3);
    }
    .modal-footer .btn-cancel{
      padding:10px 20px; border-radius:999px;
      background:var(--panel2); color:var(--text2);
      border:1px solid var(--border); font-weight:600; font-size:14px;
      cursor:pointer;
    }

    .pb-empty{
      text-align:center; padding:60px 20px;
      color:var(--muted); font-size:14px;
    }
    .pb-empty .pb-empty-icon{ font-size:48px; margin-bottom:12px; opacity:0.4; }

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
      <a href="#/assets" data-route="assets">Активы (CMDB) <small>Asset DB</small></a>
      <a href="#/reports" data-route="reports">Отчёты <small>SOC</small></a>
      <a href="#/simulation" data-route="simulation">Симулятор атак <small>MITRE</small></a>
      <a href="#/response" data-route="response">Реагирование <small id="navResponse">0</small></a>
      <a href="#/playbooks" data-route="playbooks">Автоматизация <small>SOAR</small></a>
    </nav>

    
  </aside>

  <main class="main">
    <div class="topbar">
      <div>
        <h1 id="pageTitle">Панель мониторинга</h1>
        </div>

      <div class="rightbar">
        <button class="btn theme-toggle" id="themeToggle" title="Toggle Light/Dark Theme">🌓</button>
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

      <div class="card" style="margin-bottom: 14px; border:none; background:transparent; box-shadow:none;">
        <div class="body" style="padding: 0; background: transparent;">
          <div class="kpis">
            <div class="kpi"><div class="t">Raw events</div><div class="v" id="kpiRaw">0</div><div class="s" id="kpiRawS">/api/events</div></div>
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
          <div class="body table-scroll" style="padding:0">
            <table class="tbl-fixed" style="min-width: 800px;">
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
          <div class="body table-scroll" style="padding:0">
            <table class="tbl-fixed" style="min-width: 800px;">
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
          <div class="hdr"><b>Alerts over time</b><span>bar chart</span></div>
          <div class="body"><canvas id="chartAlerts" width="800" height="260"></canvas></div>
        </div>
        <div class="card">
          <div class="hdr"><b>Incidents by Type / Severity</b><span>donut chart</span></div>
          <div class="body" class="chart-wrap">
            <div class="chart"><canvas id="chartIncType" width="800" height="260"></canvas></div>
            <div class="chart"><canvas id="chartIncSev" width="800" height="260"></canvas></div>
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
        <div class="hdr">
          <b>События (Raw)</b>
          <span>Сырой поток входящих данных (последние 100)</span>
        </div>
        <div class="body table-scroll" style="padding:0">
          <table class="tbl-fixed" style="min-width: 1400px;">
            <thead>
              <tr>
                <th style="width:160px;">Time</th>
                <th style="width:150px;">Source</th>
                <th style="width:200px;">Event Type</th>
                <th style="width:160px;">IP (Src/Dst)</th>
                <th style="width:140px;">User</th>
                <th>Raw Payload</th>
              </tr>
            </thead>
            <tbody id="tblEventsRaw"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section id="sec-aggregated" class="section">
      <div class="card">
        <div class="hdr"><b>Агрегированные события</b><span>T=5 минут, dedup</span></div>
        <div class="body table-scroll" style="padding:0">
          <table class="tbl-fixed">
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

      <!-- KPI Row -->
      <div class="kpis" id="assetKpis" style="margin-bottom:14px;">
        <div class="kpi"><div class="t">Всего активов</div><div class="v" id="assetKpiTotal">—</div><div class="s">CMDB records</div></div>
        <div class="kpi"><div class="t">Online</div><div class="v" id="assetKpiOnline" style="color:var(--good)">—</div><div class="s">status=online</div></div>
        <div class="kpi"><div class="t">Критичные (5)</div><div class="v" id="assetKpiCrit" style="color:var(--bad)">—</div><div class="s">criticality=5</div></div>
        <div class="kpi"><div class="t">Зона DMZ</div><div class="v" id="assetKpiDmz" style="color:var(--warn)">—</div><div class="s">network_zone=dmz</div></div>
        <div class="kpi"><div class="t">ICS / OT</div><div class="v" id="assetKpiIcs" style="color:var(--accent)">—</div><div class="s">zone=ics</div></div>
      </div>

      <!-- Type breadcrumbs -->
      <div style="margin-bottom:14px;display:flex;flex-wrap:wrap;gap:8px;" id="assetTypeChips"></div>

      <!-- Filters -->
      <div class="card" style="margin-bottom:14px;">
        <div class="body" style="padding:14px;">
          <div class="row" style="gap:10px;align-items:center;flex-wrap:wrap;">
            <input class="tbl-input wide" id="assetSearch" placeholder="&#128269;&#xFE0E;  Поиск: hostname, IP, asset_id, OS..." oninput="renderAssets()" />
            <select class="tbl-select" id="assetTypeFilter" onchange="renderAssets()">
              <option value="">Все типы</option>
              <option value="network_device">Network Device</option>
              <option value="iam_system">IAM / AD</option>
              <option value="server">Server</option>
              <option value="workstation">Workstation</option>
              <option value="ics_system">ICS / SCADA</option>
              <option value="security_tool">Security Tool</option>
            </select>
            <select class="tbl-select" id="assetZoneFilter" onchange="renderAssets()">
              <option value="">Все зоны</option>
              <option value="dmz">DMZ</option>
              <option value="internal">Internal</option>
              <option value="ics">ICS / OT</option>
            </select>
            <select class="tbl-select" id="assetStatusFilter" onchange="renderAssets()">
              <option value="">Любой статус</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="maintenance">Maintenance</option>
            </select>
            <button class="tbl-btn" onclick="document.getElementById('assetSearch').value='';document.getElementById('assetTypeFilter').value='';document.getElementById('assetZoneFilter').value='';document.getElementById('assetStatusFilter').value='';renderAssets()">Сброс</button>
            <span class="muted" id="assetCount" style="margin-left:auto;font-size:12px;"></span>
          </div>
        </div>
      </div>

      <!-- CMDB Table -->
      <div class="card">
        <div class="hdr"><b>CMDB — База активов</b><span id="assetTableSubtitle">loading...</span></div>
        <div class="body table-scroll" style="padding:0">
          <table class="tbl-fixed" id="assetTable" style="min-width:1600px;">
            <thead>
              <tr>
                <th style="width:120px;">Asset ID</th>
                <th style="width:130px;">Тип</th>
                <th style="width:150px;">Hostname</th>
                <th style="width:140px;">IP-адреса</th>
                <th style="width:170px;">ОС / Версия</th>
                <th style="width:90px;">Зона</th>
                <th style="width:60px;">Crit</th>
                <th style="width:100px;">Статус</th>
                <th style="width:200px;">Сервисы</th>
                <th style="width:100px;">Отдел</th>
                <th style="width:160px;">Расположение</th>
                <th style="width:170px;">Владелец</th>
              </tr>
            </thead>
            <tbody id="assetTableBody"><tr><td colspan="12" class="muted" style="padding:14px;">loading...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- INTEGRATIONS -->
    <section id="sec-integrations" class="section">
      <div class="card" style="margin-bottom:14px;">
        <div class="hdr"><b>Интеграции</b><span>REST API / Webhooks</span></div>
        <div class="body">
          <div class="note" style="margin-bottom:12px;">Интеграционный слой — webhook-уведомления при создании инцидентов (Telegram/Email/ServiceDesk).</div>
          <div class="grid cols-2">
            <div class="card">
              <div class="hdr"><b>Webhook</b><span>POST при создании инцидента</span></div>
              <div class="body">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                  <div id="webhookDot" class="dot"></div>
                  <span class="mono" id="webhookStatus">Проверка...</span>
                </div>
                <div class="note"><span class="mono">WEBHOOK_URL</span> — переменная окружения для целевого URL.</div>
                <div class="note" style="margin-top:6px;">При каждом создании инцидента корреляцией выполняется <span class="mono">POST</span>-запрос с JSON-телом инцидента.</div>
              </div>
            </div>
            <div class="card">
              <div class="hdr"><b>REST API</b><span>Endpoints</span></div>
              <div class="body">
                <table>
                  <thead><tr><th>Method</th><th>Endpoint</th><th>Описание</th></tr></thead>
                  <tbody>
                    <tr><td class="mono">POST</td><td class="mono">/api/ingest</td><td>Приём событий</td></tr>
                    <tr><td class="mono">GET</td><td class="mono">/api/alerts</td><td>Лента алертов</td></tr>
                    <tr><td class="mono">GET</td><td class="mono">/api/incidents</td><td>Список инцидентов</td></tr>
                    <tr><td class="mono">PATCH</td><td class="mono">/api/incidents/{id}</td><td>Обновление инцидента</td></tr>
                    <tr><td class="mono">GET</td><td class="mono">/api/reports</td><td>SOC-отчёт (FP-rate, MTTR)</td></tr>
                    <tr><td class="mono">GET</td><td class="mono">/api/metrics</td><td>Метрики дашборда</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- REPORTS -->
    <section id="sec-reports" class="section">
      <div class="kpis" style="margin-bottom:14px;">
        <div class="kpi"><div class="t">Incidents (24h)</div><div class="v" id="rptIncCount">—</div></div>
        <div class="kpi"><div class="t">FP Rate</div><div class="v" id="rptFpRate">—</div></div>
        <div class="kpi"><div class="t">Resolved (FP)</div><div class="v" id="rptFpCount">—</div></div>
        <div class="kpi"><div class="t">MTTR (min)</div><div class="v" id="rptMttr">—</div></div>
        <div class="kpi"><div class="t">Total Resolved</div><div class="v" id="rptResolved">—</div></div>
      </div>
      <div class="grid cols-2">
        <div class="card">
          <div class="hdr"><b>Инциденты по Severity</b><span>за 24h</span></div>
          <div class="body">
            <table>
              <thead><tr><th>Severity</th><th>Count</th></tr></thead>
              <tbody id="rptBySev"><tr><td colspan="2" class="muted">loading...</td></tr></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="hdr"><b>Инциденты по типу</b><span>за 24h</span></div>
          <div class="body">
            <table>
              <thead><tr><th>Type</th><th>Count</th></tr></thead>
              <tbody id="rptByType"><tr><td colspan="2" class="muted">loading...</td></tr></tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="card" style="margin-top:14px;">
        <div class="hdr"><b>Полный отчёт (JSON)</b><span>GET /api/reports</span></div>
        <div class="body">
          <pre class="mono" id="reportJson" style="background:#0b1220; color:#e5e7eb; padding:12px; border-radius:14px; overflow:auto; max-height:400px;">loading...</pre>
        </div>
      </div>
    </section>

    <!-- METRICS -->
    <section id="sec-metrics" class="section">
      <div class="kpis" style="margin-bottom:14px;">
        <div class="kpi"><div class="t">Всего активов</div><div class="v" id="metAssets">—</div><div class="s">CMDB</div></div>
        <div class="kpi"><div class="t">Событий (Raw)</div><div class="v" id="metRaw">—</div><div class="s">Total logs</div></div>
        <div class="kpi"><div class="t">Агрегированных</div><div class="v" id="metAgg">—</div><div class="s">Deduplicated</div></div>
        <div class="kpi"><div class="t">Алертов</div><div class="v" id="metAlerts" style="color:var(--warn)">—</div><div class="s">Total alerts</div></div>
        <div class="kpi"><div class="t">Инцидентов</div><div class="v" id="metInc" style="color:var(--bad)">—</div><div class="s">Total incidents</div></div>
      </div>

      <div class="grid cols-3" style="margin-bottom:14px;">
        <div class="card">
          <div class="hdr"><b>Топ типов событий</b></div>
          <div class="body"><canvas id="metChartEvTypes" width="400" height="240"></canvas></div>
        </div>
        <div class="card">
          <div class="hdr"><b>Топ IP источников</b></div>
          <div class="body"><canvas id="metChartSrcIp" width="400" height="240"></canvas></div>
        </div>
        <div class="card">
          <div class="hdr"><b>Источники (Sources)</b></div>
          <div class="body"><canvas id="metChartSources" width="400" height="240"></canvas></div>
        </div>
      </div>
      
      <div class="grid cols-3">
        <div class="card">
          <div class="hdr"><b>Топы пользователей</b><span>Топ активных UserID</span></div>
          <div class="body table-scroll" style="padding:0">
            <table class="tbl-fixed">
              <thead><tr><th>User / Account</th><th style="width:100px;">Событий</th></tr></thead>
              <tbody id="tblMetUsers"></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="hdr"><b>Активы по типам</b></div>
          <div class="body"><canvas id="metChartAssetTypes" width="400" height="240"></canvas></div>
        </div>
        <div class="card">
          <div class="hdr"><b>Активы по зонам</b></div>
          <div class="body"><canvas id="metChartAssetZones" width="400" height="240"></canvas></div>
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

    <!-- RESPONSE -->
    <section id="sec-response" class="section">
      <!-- KPI strip -->
      <div class="grid cols-3" style="margin-bottom:14px;">
        <div class="card">
          <div class="hdr"><b>🚫 Заблокированные IP</b><span id="respBlockedIpsCount">0</span></div>
          <div class="body" id="respBlockedIps" style="font-family:var(--mono);font-size:12px;color:var(--bad);line-height:1.8;">—</div>
        </div>
        <div class="card">
          <div class="hdr"><b>🔒 Изолированные хосты</b><span id="respIsolatedHostsCount">0</span></div>
          <div class="body" id="respIsolatedHosts" style="font-family:var(--mono);font-size:12px;color:var(--warn);line-height:1.8;">—</div>
        </div>
        <div class="card">
          <div class="hdr"><b>👤 Деактивированные пользователи</b><span id="respBlockedUsersCount">0</span></div>
          <div class="body" id="respBlockedUsers" style="font-family:var(--mono);font-size:12px;color:var(--muted);line-height:1.8;">—</div>
        </div>
      </div>

      <!-- Manual action forms -->
      <div class="grid cols-3" style="margin-bottom:14px;">
        <div class="card">
          <div class="hdr"><b>Блокировка IP вручную</b></div>
          <div class="body" style="display:flex;flex-direction:column;gap:8px;">
            <input class="tbl-input" id="manBlockIp" placeholder="IP-адрес (напр. 10.10.10.1)" />
            <input class="tbl-input" id="manBlockIpReason" placeholder="Причина" />
            <button class="btn danger" onclick="manualBlockIp()">🚫 Заблокировать IP</button>
          </div>
        </div>
        <div class="card">
          <div class="hdr"><b>Изоляция хоста вручную</b></div>
          <div class="body" style="display:flex;flex-direction:column;gap:8px;">
            <input class="tbl-input" id="manIsolateHost" placeholder="Имя хоста (напр. win-srv01)" />
            <input class="tbl-input" id="manIsolateHostReason" placeholder="Причина" />
            <button class="btn" style="border-color:rgba(245,158,11,0.4);background:rgba(245,158,11,0.15);color:var(--warn);" onclick="manualIsolateHost()">🔒 Изолировать хост</button>
          </div>
        </div>
        <div class="card">
          <div class="hdr"><b>Деактивация пользователя</b></div>
          <div class="body" style="display:flex;flex-direction:column;gap:8px;">
            <input class="tbl-input" id="manDisableUser" placeholder="Имя пользователя (напр. john.doe)" />
            <input class="tbl-input" id="manDisableUserReason" placeholder="Причина" />
            <button class="btn" style="border-color:rgba(134,239,172,0.3);background:rgba(134,239,172,0.1);color:#86efac;" onclick="manualDisableUser()">👤 Деактивировать</button>
          </div>
        </div>
      </div>

      <!-- Actions journal -->
      <div class="card">
        <div class="hdr">
          <b>Журнал действий реагирования</b>
          <span id="respActionsCount" style="color:var(--muted);">0 записей</span>
          <button class="btn" style="margin-left:auto;" onclick="loadResponseData()">↻ Обновить</button>
        </div>
        <div class="body table-scroll" style="padding:0;">
          <table class="tbl-fixed" style="min-width:1100px;">
            <thead>
              <tr>
                <th style="width:160px;">ID действия</th>
                <th style="width:160px;">Инцидент</th>
                <th style="width:130px;">Тип действия</th>
                <th style="width:200px;">Цель</th>
                <th style="width:90px;">Статус</th>
                <th style="width:170px;">Время</th>
                <th style="width:200px;">Примечание</th>
                <th style="width:130px;">Управление</th>
              </tr>
            </thead>
            <tbody id="tblResponseActions"><tr><td colspan="8" class="muted" style="padding:14px;">Загрузка...</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- PLAYBOOKS (SOAR) -->
    <section id="sec-playbooks" class="section">

      <!-- KPI strip -->
      <div class="soar-kpis">
        <div class="kpi"><div class="t">Всего плейбуков</div><div class="v" id="pbKpiTotal">0</div><div class="s">SOAR rules</div></div>
        <div class="kpi"><div class="t">Активные</div><div class="v" id="pbKpiActive" style="color:var(--good)">0</div><div class="s">enabled</div></div>
        <div class="kpi"><div class="t">Отключённые</div><div class="v" id="pbKpiDisabled" style="color:var(--muted)">0</div><div class="s">disabled</div></div>
        <div class="kpi"><div class="t">Действий</div><div class="v" id="pbKpiActions" style="color:var(--accent)">0</div><div class="s">total actions</div></div>
      </div>

      <!-- Toolbar -->
      <div class="soar-toolbar">
        <input class="search-box" id="pbSearch" placeholder="&#128269;&#xFE0E;  Поиск плейбуков по названию..." oninput="renderPlaybookCards()" />
        <div style="display:flex;gap:10px;align-items:center;">
          <button class="btn" onclick="loadPlaybooks()" title="Обновить">↻</button>
          <button class="btn-create" onclick="openPlaybookModal()">＋ Создать плейбук</button>
        </div>
      </div>

      <!-- Playbook cards -->
      <div class="pb-grid" id="pbCardsGrid">
        <div class="pb-empty">
          <div class="pb-empty-icon">⚙️</div>
          <div>Загрузка плейбуков...</div>
        </div>
      </div>
    </section>

    <!-- Playbook Modal -->
    <div class="soar-modal-overlay" id="pbModalOverlay" onclick="if(event.target===this)closePlaybookModal()">
      <div class="soar-modal">
        <div class="modal-hdr">
          <h2 id="pbModalTitle">Новый плейбук</h2>
          <button class="close-btn" onclick="closePlaybookModal()">✕</button>
        </div>
        <div class="modal-body">
          <input type="hidden" id="pbModalId" value="" />

          <div class="form-group">
            <label>Название</label>
            <input class="form-input" id="pbModalName" placeholder="Например: Изоляция при обнаружении ВПО" />
          </div>
          <div class="form-group">
            <label>Описание</label>
            <textarea class="form-input" id="pbModalDesc" placeholder="Описание логики плейбука..."></textarea>
          </div>

          <div class="form-group">
            <label>Типы инцидентов (Condition: type_in)</label>
            <div class="multi-select-box" id="pbModalTypes"></div>
          </div>
          <div class="form-group">
            <label>Severity (Condition: severity_in)</label>
            <div class="multi-select-box" id="pbModalSevs"></div>
          </div>

          <div class="form-group">
            <label>Действия (Actions)</label>
            <div class="action-rows" id="pbModalActions"></div>
            <button class="add-action-btn" onclick="addActionRow()" style="margin-top:8px;">＋ Добавить действие</button>
          </div>

          <div class="form-group" style="display:flex;align-items:center;gap:12px;">
            <label style="margin-bottom:0;">Включён</label>
            <label class="toggle-switch">
              <input type="checkbox" id="pbModalEnabled" checked />
              <span class="toggle-slider"></span>
            </label>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn-cancel" onclick="closePlaybookModal()">Отмена</button>
          <button class="btn-save" onclick="savePlaybook()">Сохранить</button>
        </div>
      </div>
    </div>

  </main>

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

function assetStatusBadge(val){
  const s = (val || '').toString().toLowerCase();
  if(s === 'online') return '<span class="badge ok">✅ ONLINE</span>';
  if(s === 'offline') return '<span class="badge bad">❌ OFFLINE</span>';
  if(s === 'maintenance') return '<span class="badge warn">🔧 MAINT</span>';
  return '<span class="badge">' + esc(val || '—') + '</span>';
}

function assetTypeIcon(val){
  const s = (val || '').toString().toLowerCase();
  if(s === 'network_device') return '🌐 ' + esc(val);
  if(s === 'iam_system') return '🔑 ' + esc(val);
  if(s === 'server') return '🖥 ' + esc(val);
  if(s === 'workstation') return '💻 ' + esc(val);
  if(s === 'ics_system') return '⚙️ ' + esc(val);
  if(s === 'security_tool') return '🛡 ' + esc(val);
  return '📦 ' + esc(val || 'unknown');
}

function renderAssets(){
  const data = window._assetData || [];
  
  // Update KPIs
  const total = data.length;
  const online = data.filter(a => a.status === 'online').length;
  const crit = data.filter(a => String(a.criticality) === '5').length;
  const dmz = data.filter(a => a.network_zone === 'dmz' || a.zone === 'dmz').length;
  const ics = data.filter(a => a.network_zone === 'ics' || a.zone === 'ics').length;
  
  document.getElementById('assetKpiTotal').textContent = total;
  document.getElementById('assetKpiOnline').textContent = online;
  document.getElementById('assetKpiCrit').textContent = crit;
  document.getElementById('assetKpiDmz').textContent = dmz;
  document.getElementById('assetKpiIcs').textContent = ics;

  // Filter values
  const searchEl = document.getElementById('assetSearch');
  const typeFilt = document.getElementById('assetTypeFilter');
  const zoneFilt = document.getElementById('assetZoneFilter');
  const statusFilt = document.getElementById('assetStatusFilter');
  
  if (!searchEl || !typeFilt || !zoneFilt || !statusFilt) return;

  const q = (searchEl.value || '').toLowerCase();
  const tFilt = typeFilt.value;
  const zFilt = zoneFilt.value;
  const sFilt = statusFilt.value;

  // Type Breadcrumbs Calculation
  const typesCount = {};
  data.forEach(a => {
    const t = a.asset_type || 'unknown';
    typesCount[t] = (typesCount[t] || 0) + 1;
  });
  const chipsEl = document.getElementById('assetTypeChips');
  if(chipsEl){
    chipsEl.innerHTML = Object.entries(typesCount)
      .sort((a,b)=>b[1]-a[1])
      .map(([k,v]) => `<span class="badge" style="cursor:pointer;" onclick="document.getElementById('assetTypeFilter').value='${k}';renderAssets()">${assetTypeIcon(k)}: ${v}</span>`)
      .join('');
  }

  // Filtering
  let filtered = data.filter(a => {
    if(tFilt && (a.asset_type || 'unknown') !== tFilt) return false;
    const zn = a.network_zone || a.zone || 'unknown';
    if(zFilt && zn !== zFilt) return false;
    if(sFilt && (a.status || 'unknown') !== sFilt) return false;
    if(q){
      const text = `${a.hostname||''} ${a.name||''} ${a.asset_id||''} ${(a.ips||[]).join(' ')} ${a.os||''}`.toLowerCase();
      if(!text.includes(q)) return false;
    }
    return true;
  });

  // Sort by criticality DESC 
  filtered.sort((a,b) => (parseInt(b.criticality)||0) - (parseInt(a.criticality)||0));

  document.getElementById('assetCount').textContent = `Показано: ${filtered.length} из ${total}`;

  const tb = document.getElementById('assetTableBody');
  if(!tb) return;
  tb.innerHTML = '';
  if(filtered.length === 0){
    tb.innerHTML = '<tr><td colspan="12" class="muted" style="padding:14px;text-align:center;">Активы не найдены</td></tr>';
    return;
  }

  for(const a of filtered){
    const tr = document.createElement('tr');
    
    // Determine severity for badge displaying
    let cBadge = 'low';
    if(a.criticality == 5) cBadge = 'critical';
    else if(a.criticality >= 3) cBadge = 'medium';
    
    tr.innerHTML = `
      <td class="mono"><b>${esc(a.asset_id)}</b></td>
      <td>${assetTypeIcon(a.asset_type)}</td>
      <td class="mono" style="font-weight:600;">${esc(a.hostname)}</td>
      <td class="mono"><div style="display:flex;flex-direction:column;gap:4px;">${(a.ips||[]).map(ip => `<span>${esc(ip)}</span>`).join('')}</div></td>
      <td>${esc(a.os)} <div class="subcell">${esc(a.os_version)}</div></td>
      <td class="mono muted">${esc(a.network_zone || a.zone)}</td>
      <td>${sevBadge(cBadge)}</td>
      <td>${assetStatusBadge(a.status)}</td>
      <td>
        <div style="display:flex;flex-wrap:wrap;gap:4px;">
          ${(a.services||[]).map(s => `<span class="badge" style="font-size:10px;padding:2px 6px;">${esc(s)}</span>`).join('')}
        </div>
      </td>
      <td class="muted">${esc(a.department)}</td>
      <td class="muted" style="font-size:11px;">${esc(a.location)}</td>
      <td class="mono muted" style="font-size:11px;">${esc(a.owner)}</td>
    `;
    tb.appendChild(tr);
  }
}


const openDetails = new Set();

function toggleDetails(incidentId){
  const el = document.getElementById('details-' + incidentId);
  if(el){
    if (el.style.display === 'none') {
      el.style.display = 'block';
      openDetails.add(incidentId);
    } else {
      el.style.display = 'none';
      openDetails.delete(incidentId);
    }
  }
}

function renderRelatedEvents(events, incident){
  if(!events || events.length === 0) return '<div class="muted">Связанные события не найдены для построения цепочки атак.</div>';
  
  // 1. Entity Extraction & Grouping
  const nodes = [];
  const edges = [];
  
  const sorted = [...events].sort((a,b) => new Date(a.received_at || 0) - new Date(b.received_at || 0));
  
  // Heuristic for Stages (MITRE-like)
  const getStage = (type) => {
    const t = String(type).toUpperCase();
    if(t.includes('SCAN') || t.includes('RECON')) return 1;
    if(t.includes('LOGIN_FAIL') || t.includes('AUTH_FAIL')) return 2;
    if(t.includes('LOGIN_SUCCESS') || t.includes('AUTH_SUCCESS')) return 3;
    if(t.includes('PROCESS') || t.includes('MALWARE') || t.includes('DETECT')) return 4;
    return 2.5; // Default intermediate
  };

  // 2. Build Nodes (Unique events as primary nodes)
  sorted.forEach((e, i) => {
    nodes.push({
      id: `evt_${i}`,
      label: e.event_type || 'Unknown',
      time: fmtTime(e.received_at).split(' ')[1],
      user: e.user || incident.user || '',
      host: e.host || incident.host || '',
      ip: e.src_ip || incident.src_ip || '',
      stage: getStage(e.event_type),
      severity: e.severity || e.priority || 'medium'
    });
  });

  // 3. Build Causal Edges (Automatic Chain Construction)
  for(let i=0; i<nodes.length; i++){
    for(let j=i+1; j<nodes.length; j++){
      const a = nodes[i];
      const b = nodes[j];
      
      // Causality: Shared User, IP, or Host + Temporal Sequence
      let reason = '';
      if(a.user && a.user === b.user) reason = 'Shared User';
      else if(a.ip && a.ip === b.ip) reason = 'Shared IP';
      else if(a.host && a.host === b.host) reason = 'Shared Host';
      
      if(reason){
        edges.push({ source: a.id, target: b.id, label: reason });
        break; // Only link to the immediate next causal event to avoid spiderwebs
      }
    }
  }

  // 4. SVG Rendering (DAG Layout)
  const width = 800;
  const height = 400;
  const stageWidth = width / 5;
  const rowGap = 70;
  
  // Assign grid positions
  const stageCounts = {};
  nodes.forEach(n => {
    n.x = (n.stage * stageWidth) - (stageWidth / 2);
    stageCounts[n.stage] = (stageCounts[n.stage] || 0) + 1;
    n.y = (stageCounts[n.stage] * rowGap) + 50;
  });

  let svg = `<svg viewBox="0 0 ${width} ${height}" style="width:100%; height:auto; overflow:visible;">
    <defs>
      <marker id="attackArrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
        <polygon points="0 0, 10 3.5, 0 7" fill="var(--accent)" opacity="0.6" />
      </marker>
      <filter id="nodeGlow" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="2" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
    </defs>
    
    <!-- Stage Background Labels -->
    <g opacity="0.1" font-size="10" font-weight="700" letter-spacing="2">
      <text x="${stageWidth*0.5}" y="30" text-anchor="middle">RECON</text>
      <text x="${stageWidth*1.5}" y="30" text-anchor="middle">ACCESS</text>
      <text x="${stageWidth*2.5}" y="30" text-anchor="middle">ESTABLISH</text>
      <text x="${stageWidth*3.5}" y="30" text-anchor="middle">LATERAL</text>
      <text x="${stageWidth*4.5}" y="30" text-anchor="middle">IMPACT</text>
      <line x1="${stageWidth}" y1="40" x2="${stageWidth}" y2="${height}" stroke="var(--border)" stroke-dasharray="4,4" />
      <line x1="${stageWidth*2}" y1="40" x2="${stageWidth*2}" y2="${height}" stroke="var(--border)" stroke-dasharray="4,4" />
      <line x1="${stageWidth*3}" y1="40" x2="${stageWidth*3}" y2="${height}" stroke="var(--border)" stroke-dasharray="4,4" />
      <line x1="${stageWidth*4}" y1="40" x2="${stageWidth*4}" y2="${height}" stroke="var(--border)" stroke-dasharray="4,4" />
    </g>
  `;

  // Draw Edges (Bézier Curves)
  edges.forEach(e => {
    const s = nodes.find(n => n.id === e.source);
    const t = nodes.find(n => n.id === e.target);
    const cp1x = s.x + (t.x - s.x) / 2;
    svg += `
      <path d="M ${s.x} ${s.y} C ${cp1x} ${s.y}, ${cp1x} ${t.y}, ${t.x} ${t.y}" 
            stroke="var(--accent)" stroke-width="1.5" fill="none" opacity="0.4"
            marker-end="url(#attackArrow)">
        <animate attributeName="stroke-dasharray" from="0,10" to="10,0" dur="2s" repeatCount="indefinite" />
        <text><title>${e.label}</title></text>
      </path>`;
  });

  // Draw Nodes
  nodes.forEach(n => {
    const col = n.severity === 'critical' ? 'var(--bad)' : (n.severity === 'high' ? 'var(--warn)' : 'var(--accent)');
    svg += `
      <g transform="translate(${n.x}, ${n.y})">
        <rect x="-65" y="-22" width="130" height="44" rx="10" fill="var(--panel2)" stroke="${col}" stroke-width="1.5" filter="${n.severity === 'critical' ? 'url(#nodeGlow)' : 'none'}" />
        <text y="-4" text-anchor="middle" font-size="11" font-weight="700" fill="var(--text)">${esc(n.label)}</text>
        <text y="12" text-anchor="middle" font-size="9" fill="var(--muted)" font-family="monospace">${n.time}</text>
        
        <!-- Entity Icons (Small dots) -->
        <circle cx="-50" cy="12" r="2.5" fill="${n.ip ? 'var(--bad)' : 'transparent'}" title="IP present" />
        <circle cx="-42" cy="12" r="2.5" fill="${n.user ? 'var(--warn)' : 'transparent'}" title="User present" />
        <circle cx="-34" cy="12" r="2.5" fill="${n.host ? 'var(--ok)' : 'transparent'}" title="Host present" />
        
        <title>User: ${esc(n.user)}\nHost: ${esc(n.host)}\nIP: ${esc(n.ip)}</title>
      </g>`;
  });

  svg += '</svg>';

  return `
    <div class="attack-chain-box">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; border-bottom:1px solid var(--border); padding-bottom:10px;">
        <div style="font-weight:700; color:var(--accent); font-size:13px;">АВТОМАТИЧЕСКАЯ ЦЕПОЧКА АТАК (GRAPH CORRELATION)</div>
        <div style="font-size:10px; display:flex; gap:10px;">
          <span><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--bad);"></span> IP Link</span>
          <span><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--warn);"></span> User Link</span>
          <span><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:var(--ok);"></span> Host Link</span>
        </div>
      </div>
      ${svg}
      <div style="margin-top:15px; padding:10px; background:rgba(0,0,0,0.2); border-radius:8px; border:1px solid var(--border); font-size:11px;">
        <b style="color:var(--warn);">Метод:</b> На основе графа связей типов событий. Реберная связь устанавливается при совпадении ключевых атрибутов (Сущности) в скользящем окне корреляции.
      </div>
    </div>
  `;
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

  const padBottom = 26;
  const padLeft = 30;
  const padTop = 15;
  const padRight = 10;
  const chartW = w - padLeft - padRight;
  const chartH = h - padTop - padBottom;
  
  const max = Math.max(1, ...values.map(v=>v.v));
  const n = values.length;
  if(n === 0) return;

  // Draw horizontal grid lines
  const gridLines = 4;
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  for(let i=0; i<=gridLines; i++){
    const y = padTop + (chartH / gridLines) * i;
    ctx.moveTo(padLeft, y);
    ctx.lineTo(padLeft + chartW, y);
  }
  ctx.stroke();

  // Draw Y axis labels
  ctx.fillStyle = 'rgba(230,237,243,0.5)';
  ctx.font = '10px ui-sans-serif, system-ui';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for(let i=0; i<=gridLines; i++){
    const val = Math.round(max - (max / gridLines) * i);
    const y = padTop + (chartH / gridLines) * i;
    ctx.fillText(val, padLeft - 6, y);
  }

  // Draw X axis line
  ctx.fillStyle = 'rgba(255,255,255,0.2)';
  ctx.fillRect(padLeft, h - padBottom, chartW, 1);

  const barSpace = chartW / n;
  const barW = Math.max(2, Math.min(barSpace * 0.7, 40));

  // Create gradient for bars
  const grad = ctx.createLinearGradient(0, padTop, 0, h - padBottom);
  grad.addColorStop(0, 'rgba(56, 189, 248, 0.9)'); // bright blue top
  grad.addColorStop(1, 'rgba(37, 99, 235, 0.1)');  // darker/transparent bottom

  ctx.textAlign = 'center';
  
  for(let i=0; i<n; i++){
    const v = values[i].v;
    const bh = Math.max(1, chartH * (v / max));
    const centerX = padLeft + i*barSpace + (barSpace/2);
    const x = centerX - barW/2;
    const y = (h - padBottom) - bh;

    // Draw rounded bar
    ctx.fillStyle = grad;
    ctx.beginPath();
    const r = Math.min(4, barW/2, bh);
    ctx.moveTo(x, y + bh);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.lineTo(x + barW - r, y);
    ctx.quadraticCurveTo(x + barW, y, x + barW, y + r);
    ctx.lineTo(x + barW, y + bh);
    ctx.fill();

    // Draw value on top if bar is wide enough
    if (barW > 12 && v > 0) {
      ctx.fillStyle = 'rgba(255,255,255,0.8)';
      ctx.font = '9px ui-sans-serif, system-ui';
      ctx.fillText(v, centerX, y - 6);
    }
  }

  // Draw X axis labels
  ctx.fillStyle = 'rgba(230,237,243,0.65)';
  ctx.font = '11px ui-sans-serif, system-ui';
  ctx.textBaseline = 'top';
  
  const maxLabels = Math.max(2, Math.floor(chartW / 60)); 
  const step = Math.max(1, Math.floor(n / maxLabels));
  
  for(let i=0; i<n; i+=step){
    const label = values[i].k;
    const centerX = padLeft + i*barSpace + (barSpace/2);
    ctx.fillText(label, centerX, h - padBottom + 6);
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
  ctx.fillStyle = '#1c2128';
  ctx.arc(cx,cy,r0,0,2*Math.PI);
  ctx.fill();

  // title
  ctx.fillStyle = 'rgba(230,237,243,0.9)';
  ctx.font = '700 14px ui-sans-serif, system-ui';
  ctx.fillText(title, 14, 22);

  // legend
  ctx.font = '12px ui-sans-serif, system-ui';
  ctx.fillStyle = 'rgba(230,237,243,0.7)';
  let ly = 44;
  const lx = Math.round(w*0.62);
  entries.slice(0,6).forEach((e, idx)=>{
    ctx.fillStyle = pal[idx % pal.length];
    ctx.fillRect(lx, ly-10, 10, 10);
    ctx.fillStyle = 'rgba(230,237,243,0.75)';
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
  {id:'response', title:'Активное реагирование'},
  {id:'playbooks', title:'Автоматизация (SOAR)'},
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
      <td>
        <div style="font-weight:600;margin-bottom:10px;margin-left:6px;">${esc(title)}</div>
        <div style="display:flex; gap:8px;">
          <button class="tbl-btn" style="flex:1; margin-top:8px;" onclick="toggleDetails('${esc(id)}')">Показать историю корреляции (Related Events)</button>
          <button class="tbl-btn" style="flex:0.5; margin-top:8px; background:rgba(16,185,129,0.1); border-color:rgba(16,185,129,0.3); color:var(--good);" onclick="exportGossopka('${esc(id)}')">ГосСОПКА ГОСТ</button>
        </div>
        <div id="details-${esc(id)}" class="related-events-box" style="display:${openDetails.has(id) ? 'block' : 'none'}; margin-top:10px; padding:15px; background:var(--bg); border:1px solid var(--border); border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,0.2);">
          ${renderRelatedEvents(it.related_events, it)}
        </div>
      </td>
      <td class="col-comment"><textarea class="tbl-comment-box" data-incident-id="${esc(id)}" data-role="comment" placeholder="Комментарий (сохраняется кнопкой Save)">${esc(comment)}</textarea></td>
      <td class="col-actions"><button class="tbl-save-btn" data-incident-id="${esc(id)}" data-action="save">Save</button></td>
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

window.exportGossopka = async function(id) {
  try {
    const r = await fetch('/api/gossopka/' + encodeURIComponent(id));
    if (!r.ok) {
        setStatus('Ошибка экспорта ГосСОПКА (' + r.status + ')', 'bad');
        return;
    }
    const data = await r.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: "application/json"});
    const link = document.createElement("a");
    link.href = window.URL.createObjectURL(blob);
    link.download = `gossopka_report_${id}.json`;
    link.click();
    setStatus('Отчет ГосСОПКА выгружен', 'ok');
  } catch(e) {
    setStatus('Ошибка скачивания отчета', 'bad');
  }
};


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

    // Update specialized metrics tab
    document.getElementById('metAssets').textContent = (m.cmdb?.assets_count ?? '—');
    document.getElementById('metRaw').textContent = (m.events_raw ?? '—');
    document.getElementById('metAgg').textContent = (m.events_aggregated ?? '—');
    document.getElementById('metAlerts').textContent = (m.alerts ?? '—');
    document.getElementById('metInc').textContent = (m.incidents ?? '—');
    
    if (m.tops?.event_types) {
      drawBars(document.getElementById('metChartEvTypes'), m.tops.event_types.map(x => ({k: String(x.key), v: x.count})));
    }
    if (m.tops?.src_ip) {
      drawBars(document.getElementById('metChartSrcIp'), m.tops.src_ip.map(x => ({k: String(x.key), v: x.count})));
    }
    if (m.by_source) {
      const entries = Object.entries(m.by_source).filter(x => x[1] > 0);
      if(entries.length) drawDonut(document.getElementById('metChartSources'), entries, 'Источники');
    }
    if (m.cmdb?.by_type) {
      const entries = Object.entries(m.cmdb.by_type).filter(x => x[1] > 0);
      if(entries.length) drawDonut(document.getElementById('metChartAssetTypes'), entries, 'Типы активов');
    }
    if (m.cmdb?.by_zone) {
      const entries = Object.entries(m.cmdb.by_zone).filter(x => x[1] > 0);
      if(entries.length) drawDonut(document.getElementById('metChartAssetZones'), entries, 'Зоны');
    }
    const tblUsers = document.getElementById('tblMetUsers');
    if (tblUsers) {
      if (m.tops?.users && m.tops.users.length > 0) {
        tblUsers.innerHTML = m.tops.users.map(u => `<tr><td class="mono" style="font-weight:600">${esc(u.key)}</td><td class="mono">${u.count}</td></tr>`).join('');
      } else {
        tblUsers.innerHTML = '<tr><td colspan="2" class="muted" style="padding:14px; text-align:center;">Нет активности</td></tr>';
      }
    }

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

  // Raw events
  const ev = await safeJson('/api/events?limit=100');
  const evItems = ev && ev.items ? ev.items : [];
  const tbEv = document.getElementById('tblEventsRaw');
  if (tbEv) {
    tbEv.innerHTML = '';
    if (evItems.length === 0) {
      tbEv.innerHTML = '<tr><td colspan="6" class="muted" style="padding:14px; text-align:center;">Сырые события не найдены</td></tr>';
    } else {
      for (const e of evItems) {
        let ips = [];
        if (e.src_ip) ips.push(e.src_ip);
        if (e.dst_ip) ips.push(e.dst_ip);
        const ipStr = ips.length ? ips.join(' ➔ ') : '—';
        
        const row = document.createElement('tr');
        row.innerHTML = `
          <td class="mono" style="font-size:11px;">${fmtTime(e.received_at)}</td>
          <td class="mono muted">${esc(e.source || e.source_type || '—')}</td>
          <td class="mono" style="font-weight:600;color:var(--accent);">${esc(e.event_type || '—')}</td>
          <td class="mono">${esc(ipStr)}</td>
          <td class="mono">${esc(e.user || '—')}</td>
          <td class="mono muted" style="font-size:11px; max-width:400px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${esc(JSON.stringify(e))}">${esc(JSON.stringify(e))}</td>
        `;
        tbEv.appendChild(row);
      }
    }
  }

  // Asset DB (CMDB) — loaded lazily, rendered by renderAssets()
  window._assetData = null;
  const assetResp = await safeJson('/api/assets');
  if(assetResp && Array.isArray(assetResp.items)){
    window._assetData = assetResp.items;
    renderAssets();
  } else {
    const tb = document.getElementById('assetTableBody');
    if(tb) tb.innerHTML = '<tr><td colspan="12" class="muted" style="padding:14px;">Asset DB недоступна</td></tr>';
  }

  // Charts
  renderCharts(alerts, incidents);

  // Reports (SOC-level)
  const rpt = await safeJson('/api/reports');
  if(rpt){
    document.getElementById('reportJson').textContent = JSON.stringify(rpt, null, 2);
    const inc24 = rpt.incidents || {};
    document.getElementById('rptIncCount').textContent = (inc24.total ?? '—');
    const fp = rpt.fp_rate || {};
    document.getElementById('rptFpRate').textContent = (fp.fp_rate_pct != null ? fp.fp_rate_pct + '%' : '—');
    document.getElementById('rptFpCount').textContent = (fp.false_positives ?? '—') + '/' + (fp.total_resolved ?? '—');
    const mttr = rpt.mttr || {};
    document.getElementById('rptMttr').textContent = (mttr.mttr_minutes ?? '—');
    document.getElementById('rptResolved').textContent = (mttr.resolved_count ?? '—');

    const bySev = inc24.by_severity || {};
    const sevTb = document.getElementById('rptBySev');
    sevTb.innerHTML = '';
    const sevKeys = Object.keys(bySev);
    if(sevKeys.length === 0){
      sevTb.innerHTML = '<tr><td colspan="2" class="muted">Нет данных</td></tr>';
    } else {
      for(const k of sevKeys){
        const row = document.createElement('tr');
        row.innerHTML = '<td>' + sevBadge(k) + '</td><td class="mono">' + bySev[k] + '</td>';
        sevTb.appendChild(row);
      }
    }
    const byType = inc24.by_type || {};
    const typeTb = document.getElementById('rptByType');
    typeTb.innerHTML = '';
    const typeKeys = Object.keys(byType);
    if(typeKeys.length === 0){
      typeTb.innerHTML = '<tr><td colspan="2" class="muted">Нет данных</td></tr>';
    } else {
      for(const k of typeKeys){
        const row = document.createElement('tr');
        row.innerHTML = '<td class="mono">' + esc(k) + '</td><td class="mono">' + byType[k] + '</td>';
        typeTb.appendChild(row);
      }
    }
  }

  // Integrations: webhook status
  const webhookDot = document.getElementById('webhookDot');
  const webhookStatus = document.getElementById('webhookStatus');
  if(webhookDot && webhookStatus){
    // Just show whether webhook URL is configured (we can't check from frontend, show as info)
    webhookDot.className = 'dot ok';
    webhookStatus.textContent = 'Webhook endpoint ready (env WEBHOOK_URL)';
  }

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

  // Auto-refresh Response tab if active
  const secResponse = document.getElementById('sec-response');
  if (secResponse && secResponse.classList.contains('active')) {
    loadResponseData();
  }
}

// ---------------------------
// SOAR Playbooks — Full CRUD UI
// ---------------------------

// Catalog of known incident types for the multi-select
const INCIDENT_TYPES = [
  'BRUTEFORCE_VPN','PORT_SCAN','IAM_PASSWORD_SPRAY','ENDPOINT_BRUTEFORCE',
  'MALWARE_DETECTED','AV_TAMPER','AV_CLEAN_FAILED','RANSOMWARE_BEHAVIOR',
  'CREDENTIAL_DUMP','LATERAL_MOVEMENT','EDR_LATERAL_ACTIVITY','SUSPICIOUS_PROCESS',
  'VPN_BRUTE_CHAIN','VPN_COMPROMISE','ENCODED_POWERSHELL','SERVICE_CREATION',
  'IAM_ADMIN_GROUP_CHANGE'
];
const SEVERITY_LEVELS = ['critical','high','medium','low'];

let _playbookData = [];

async function loadPlaybooks(){
  const resp = await safeJson('/api/playbooks/');
  _playbookData = resp ? (resp.items || resp.playbooks || []) : [];
  renderPlaybookCards();
}

function renderPlaybookCards(){
  const grid = document.getElementById('pbCardsGrid');
  if(!grid) return;

  const q = (document.getElementById('pbSearch')?.value || '').toLowerCase();
  let items = _playbookData;
  if(q) items = items.filter(pb => (pb.name||'').toLowerCase().includes(q) || (pb.description||'').toLowerCase().includes(q) || (pb.id||'').toLowerCase().includes(q));

  // KPI
  const total = _playbookData.length;
  const active = _playbookData.filter(p=>p.enabled).length;
  const disabled = total - active;
  const totalActions = _playbookData.reduce((s,p)=>(s+(p.actions||[]).length),0);
  const el = id => document.getElementById(id);
  if(el('pbKpiTotal')) el('pbKpiTotal').textContent = total;
  if(el('pbKpiActive')) el('pbKpiActive').textContent = active;
  if(el('pbKpiDisabled')) el('pbKpiDisabled').textContent = disabled;
  if(el('pbKpiActions')) el('pbKpiActions').textContent = totalActions;

  grid.innerHTML = '';

  if(items.length === 0){
    grid.innerHTML = `<div class="pb-empty"><div class="pb-empty-icon">⚙️</div><div>${total===0?'Нет плейбуков. Создайте первый!':'Ничего не найдено'}</div></div>`;
    return;
  }

  for(const pb of items){
    const cond = pb.condition || {};
    const types = cond.type_in || [];
    const sevs = cond.severity_in || [];
    const acts = pb.actions || [];

    const typesHtml = types.length
      ? types.map(t=>`<span class="pb-chip cond-type">${esc(t)}</span>`).join('')
      : '<span style="color:var(--muted);font-size:11px;">Любой тип</span>';
    const sevsHtml = sevs.length
      ? sevs.map(s=>`<span class="pb-chip cond-sev">${esc(s)}</span>`).join('')
      : '<span style="color:var(--muted);font-size:11px;">Любой</span>';

    const actionIcons = {block_ip:'🚫', isolate_host:'🔒', disable_user:'👤'};
    const actionClasses = {block_ip:'act-block', isolate_host:'act-isolate', disable_user:'act-disable'};
    const actsHtml = acts.length
      ? acts.map(a=>`<span class="pb-chip ${actionClasses[a.type]||''}">${actionIcons[a.type]||''} ${esc(a.type)} → ${esc(a.target_field)}</span>`).join('')
      : '<span style="color:var(--muted);font-size:11px;">Нет действий</span>';

    const card = document.createElement('div');
    card.className = 'pb-card' + (pb.enabled ? '' : ' disabled');
    card.innerHTML = `
      <div class="pb-header">
        <div>
          <div class="pb-title">${esc(pb.name)}</div>
          <div class="pb-id">${esc(pb.id)}</div>
        </div>
        <label class="toggle-switch" title="${pb.enabled?'Выключить':'Включить'}">
          <input type="checkbox" ${pb.enabled?'checked':''} onchange="togglePlaybook('${esc(pb.id)}',this.checked)" />
          <span class="toggle-slider"></span>
        </label>
      </div>
      <div class="pb-body">
        <div class="pb-desc">${esc(pb.description || 'Без описания')}</div>
        <div class="pb-flow">
          <div class="pb-flow-col">
            <div class="pb-flow-label">IF условие</div>
            <div>${typesHtml}</div>
            <div style="margin-top:4px;">${sevsHtml}</div>
          </div>
          <div class="pb-flow-arrow">→</div>
          <div class="pb-flow-col">
            <div class="pb-flow-label">THEN действия</div>
            <div>${actsHtml}</div>
          </div>
        </div>
      </div>
      <div class="pb-footer">
        <div style="font-size:11px;color:var(--muted);">${pb.enabled?'<span style="color:var(--good);font-weight:700;">● Active</span>':'<span>○ Disabled</span>'}</div>
        <div class="pb-actions">
          <button onclick="openPlaybookModal('${esc(pb.id)}')">✏️ Изменить</button>
          <button class="del" onclick="deletePlaybook('${esc(pb.id)}','${esc(pb.name)}')">🗑 Удалить</button>
        </div>
      </div>
    `;
    grid.appendChild(card);
  }
}

// --- Toggle ---
window.togglePlaybook = async function(id, state){
  try{
    const r = await fetch('/api/playbooks/' + encodeURIComponent(id), {
      method: 'PATCH',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled: state})
    });
    if(!r.ok) throw new Error('HTTP ' + r.status);
    setStatus('Плейбук обновлён', 'ok');
    await loadPlaybooks();
  }catch(e){
    setStatus('Ошибка обновления плейбука', 'bad');
    await loadPlaybooks();
  }
};

// --- Delete ---
window.deletePlaybook = async function(id, name){
  if(!confirm(`Удалить плейбук «${name}»?`)) return;
  try{
    const r = await fetch('/api/playbooks/' + encodeURIComponent(id), {method:'DELETE'});
    if(!r.ok) throw new Error('HTTP ' + r.status);
    setStatus('Плейбук удалён', 'ok');
    await loadPlaybooks();
  }catch(e){
    setStatus('Ошибка удаления', 'bad');
  }
};

// --- Modal ---
function _renderMultiSelect(containerId, options, selected){
  const box = document.getElementById(containerId);
  if(!box) return;
  box.innerHTML = '';
  for(const opt of options){
    const chip = document.createElement('span');
    chip.className = 'ms-chip' + (selected.includes(opt) ? ' selected' : '');
    chip.textContent = opt;
    chip.onclick = ()=>{ chip.classList.toggle('selected'); };
    box.appendChild(chip);
  }
}

function _getMultiSelectValues(containerId){
  const box = document.getElementById(containerId);
  if(!box) return [];
  return Array.from(box.querySelectorAll('.ms-chip.selected')).map(c=>c.textContent);
}

function addActionRow(type, target){
  const container = document.getElementById('pbModalActions');
  const row = document.createElement('div');
  row.className = 'action-row';
  row.innerHTML = `
    <select class="act-type">
      <option value="block_ip" ${type==='block_ip'?'selected':''}>🚫 block_ip</option>
      <option value="isolate_host" ${type==='isolate_host'?'selected':''}>🔒 isolate_host</option>
      <option value="disable_user" ${type==='disable_user'?'selected':''}>👤 disable_user</option>
    </select>
    <select class="act-target">
      <option value="src_ip" ${target==='src_ip'?'selected':''}>src_ip</option>
      <option value="host" ${target==='host'?'selected':''}>host</option>
      <option value="user" ${target==='user'?'selected':''}>user</option>
    </select>
    <button class="remove-action" onclick="this.parentElement.remove()">✕</button>`;
  container.appendChild(row);
}

function openPlaybookModal(editId){
  const pb = editId ? _playbookData.find(p=>p.id===editId) : null;
  document.getElementById('pbModalId').value = pb ? pb.id : '';
  document.getElementById('pbModalTitle').textContent = pb ? 'Редактировать плейбук' : 'Новый плейбук';
  document.getElementById('pbModalName').value = pb ? pb.name : '';
  document.getElementById('pbModalDesc').value = pb ? (pb.description||'') : '';
  document.getElementById('pbModalEnabled').checked = pb ? pb.enabled : true;

  const cond = pb ? (pb.condition||{}) : {};
  _renderMultiSelect('pbModalTypes', INCIDENT_TYPES, cond.type_in || []);
  _renderMultiSelect('pbModalSevs', SEVERITY_LEVELS, (cond.severity_in||[]).map(s=>s.toLowerCase()));

  const actContainer = document.getElementById('pbModalActions');
  actContainer.innerHTML = '';
  if(pb && pb.actions){
    for(const a of pb.actions) addActionRow(a.type, a.target_field);
  }

  document.getElementById('pbModalOverlay').classList.add('open');
}

function closePlaybookModal(){
  document.getElementById('pbModalOverlay').classList.remove('open');
}

async function savePlaybook(){
  const id = document.getElementById('pbModalId').value;
  const name = document.getElementById('pbModalName').value.trim();
  if(!name){ alert('Введите название плейбука'); return; }
  const description = document.getElementById('pbModalDesc').value.trim();
  const enabled = document.getElementById('pbModalEnabled').checked;
  const type_in = _getMultiSelectValues('pbModalTypes');
  const severity_in = _getMultiSelectValues('pbModalSevs');

  const actionRows = document.querySelectorAll('#pbModalActions .action-row');
  const actions = [];
  for(const row of actionRows){
    const t = row.querySelector('.act-type').value;
    const tf = row.querySelector('.act-target').value;
    actions.push({type:t, target_field:tf});
  }

  const payload = {
    name, description, enabled,
    condition: {type_in, severity_in},
    actions
  };

  try{
    let url, method;
    if(id){
      url = '/api/playbooks/' + encodeURIComponent(id);
      method = 'PUT';
    } else {
      url = '/api/playbooks/';
      method = 'POST';
    }
    const r = await fetch(url, {
      method,
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    if(!r.ok){
      const err = await r.json().catch(()=>({}));
      throw new Error(err.detail || 'HTTP ' + r.status);
    }
    setStatus(id ? 'Плейбук обновлён' : 'Плейбук создан', 'ok');
    closePlaybookModal();
    await loadPlaybooks();
  }catch(e){
    alert('Ошибка: ' + e.message);
    setStatus('Ошибка сохранения плейбука', 'bad');
  }
}

// ---------------------------
// Active Response functions
// ---------------------------
async function loadResponseData(){
  const status = await safeJson('/api/response/status');
  if(status){
    const ips = status.blocked_ips || [];
    const hosts = status.isolated_hosts || [];
    const users = status.blocked_users || [];
    document.getElementById('respBlockedIpsCount').textContent = ips.length;
    document.getElementById('respIsolatedHostsCount').textContent = hosts.length;
    document.getElementById('respBlockedUsersCount').textContent = users.length;
    document.getElementById('respBlockedIps').innerHTML = ips.length ? ips.map(ip=>`<div>${ip}</div>`).join('') : '<span class="muted">Нет блокировок</span>';
    document.getElementById('respIsolatedHosts').innerHTML = hosts.length ? hosts.map(h=>`<div>${h}</div>`).join('') : '<span class="muted">Нет изолированных хостов</span>';
    document.getElementById('respBlockedUsers').innerHTML = users.length ? users.map(u=>`<div>${u}</div>`).join('') : '<span class="muted">Нет деактивированных пользователей</span>';
    const navEl = document.getElementById('navResponse');
    if(navEl) navEl.textContent = status.total_blocked || 0;
  }

  const actData = await safeJson('/api/response/actions?limit=100');
  const actions = (actData && actData.actions) ? actData.actions : [];
  document.getElementById('respActionsCount').textContent = actions.length + ' записей';
  const tb = document.getElementById('tblResponseActions');
  tb.innerHTML = '';
  if(actions.length === 0){
    tb.innerHTML = '<tr><td colspan="8" class="muted" style="padding:14px;">Действий реагирования ещё нет. Запустите симуляцию атаки.</td></tr>';
    return;
  }
  for(const a of actions){
    const isRevoked = a.status === 'revoked';
    const isSkipped = a.status === 'skipped';
    const statusBadge = isRevoked ? '<span class="badge warn">revoked</span>'
      : isSkipped ? '<span class="badge">skipped</span>'
      : a.status === 'applied' ? '<span class="badge ok">applied</span>'
      : a.status === 'failed' ? '<span class="badge bad">failed</span>'
      : `<span class="badge">${a.status}</span>`;

    const actionLabel = {
      block_ip: '🚫 block_ip',
      isolate_host: '🔒 isolate_host',
      disable_user: '👤 disable_user',
      recommend: '💡 recommend',
    }[a.action_type] || a.action_type;

    const revokeBtn = (!isRevoked && a.status === 'applied')
      ? `<button class="tbl-btn" style="background:rgba(239,68,68,0.1);border-color:rgba(239,68,68,0.3);color:var(--bad);" onclick="revokeAction('${a.action_id}')">Снять</button>`
      : '—';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono" style="font-size:11px;">${a.action_id}</td>
      <td class="mono" style="font-size:11px;">${a.incident_id || '—'}</td>
      <td>${actionLabel}</td>
      <td class="mono" style="font-weight:700;">${a.target || '—'}</td>
      <td>${statusBadge}</td>
      <td class="mono" style="font-size:11px;">${fmtTime(a.created_at)}</td>
      <td class="muted" style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;" title="${(a.notes||'').replace(/"/g,'&quot;')}">${a.notes || ''}</td>
      <td>${revokeBtn}</td>
    `;
    tb.appendChild(row);
  }
}

async function revokeAction(actionId){
  try{
    const r = await fetch('/api/response/actions/' + actionId, {method:'DELETE'});
    if(r.ok){ await loadResponseData(); }
    else{ alert('Ошибка при отзыве действия: ' + r.status); }
  }catch(e){ alert('Ошибка: ' + e); }
}

async function manualBlockIp(){
  const ip = (document.getElementById('manBlockIp').value || '').trim();
  const reason = (document.getElementById('manBlockIpReason').value || '').trim() || 'manual';
  if(!ip){ alert('Введите IP-адрес'); return; }
  const r = await fetch('/api/response/block-ip', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,reason})});
  if(r.ok){ document.getElementById('manBlockIp').value=''; document.getElementById('manBlockIpReason').value=''; await loadResponseData(); }
  else{ alert('Ошибка блокировки: ' + r.status); }
}

async function manualIsolateHost(){
  const host = (document.getElementById('manIsolateHost').value || '').trim();
  const reason = (document.getElementById('manIsolateHostReason').value || '').trim() || 'manual';
  if(!host){ alert('Введите имя хоста'); return; }
  const r = await fetch('/api/response/isolate-host', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,reason})});
  if(r.ok){ document.getElementById('manIsolateHost').value=''; document.getElementById('manIsolateHostReason').value=''; await loadResponseData(); }
  else{ alert('Ошибка изоляции: ' + r.status); }
}

async function manualDisableUser(){
  const user = (document.getElementById('manDisableUser').value || '').trim();
  const reason = (document.getElementById('manDisableUserReason').value || '').trim() || 'manual';
  if(!user){ alert('Введите имя пользователя'); return; }
  const r = await fetch('/api/response/disable-user', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user,reason})});
  if(r.ok){ document.getElementById('manDisableUser').value=''; document.getElementById('manDisableUserReason').value=''; await loadResponseData(); }
  else{ alert('Ошибка деактивации: ' + r.status); }
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

// ---------------------------
// Correlation Graph (SVG) - Refined Node-based Design
// ---------------------------
function renderCorrelationGraph() {
  return;
  if (!container) return;
  
  const w = container.clientWidth;
  const h = container.clientHeight;
  if(w < 100) return; // Wait for layout

  const nodes = [
    // Column 1: Input
    { id: 'in_agent', label: 'Агент Endpoint', type: 'Точка входа', col: 0, row: 1 },
    { id: 'in_syslog', label: 'Logstash', type: 'Точка входа', col: 0, row: 3 },
    
    // Column 2: Transform
    { id: 'norm_endp', label: 'Нормализатор для Endp...', type: 'VRL-трансформация', col: 1, row: 1 },
    
    // Column 3: Filters
    { id: 'filt_linux', label: 'Linux Object access events', type: 'Фильтр', col: 2, row: 0 },
    { id: 'filt_exch', label: 'Exchange events', type: 'Фильтр', col: 2, row: 1 },
    { id: 'filt_dns', label: 'DNS events', type: 'Фильтр', col: 2, row: 2 },
    { id: 'filt_win', label: 'Windows Security events', type: 'Фильтр', col: 2, row: 3 },
    { id: 'filt_sys', label: 'Windows sysmon events', type: 'Фильтр', col: 2, row: 4 },
    
    // Column 4: Normalizers
    { id: 'norm_linux', label: 'Linux Object access enric...', type: 'Нормализатор', col: 3, row: 0 },
    { id: 'norm_exch', label: 'Exchange normalizer', type: 'Нормализатор', col: 3, row: 1 },
    { id: 'norm_dns', label: 'DNS Debug normalizer', type: 'Нормализатор', col: 3, row: 2 },
    { id: 'norm_win', label: 'Windows event security n...', type: 'Нормализатор', col: 3, row: 3 },
    { id: 'norm_sys', label: 'Windows sysmon normali...', type: 'Нормализатор', col: 3, row: 4 },
    
    // Column 5: Global Transform & Final
    { id: 'norm_global', label: 'Event_Normalizer', type: 'VRL-трансформация', col: 4, row: 1 },
    { id: 'storage', label: 'Event storage', type: 'Конечная точка', col: 5, row: 1 },
    
    { id: 'filt_logon', label: 'Logon activity', type: 'Фильтр', col: 4, row: 3 },
    { id: 'bus_events', label: 'Analytical events', type: 'Шина - Получение', col: 5, row: 3 }
  ];

  const links = [
    { source: 'in_agent', target: 'norm_endp' },
    { source: 'norm_endp', target: 'filt_linux' },
    { source: 'norm_endp', target: 'filt_exch' },
    { source: 'norm_endp', target: 'filt_dns' },
    
    { source: 'in_syslog', target: 'filt_win' },
    { source: 'in_syslog', target: 'filt_sys' },
    
    { source: 'filt_linux', target: 'norm_linux' },
    { source: 'filt_exch', target: 'norm_exch' },
    { source: 'filt_dns', target: 'norm_dns' },
    { source: 'filt_win', target: 'norm_win' },
    { source: 'filt_sys', target: 'norm_sys' },
    
    { source: 'norm_linux', target: 'norm_global' },
    { source: 'norm_exch', target: 'norm_global' },
    { source: 'norm_dns', target: 'norm_global' },
    
    { source: 'norm_win', target: 'filt_logon' },
    { source: 'norm_sys', target: 'filt_logon' },
    
    { source: 'norm_global', target: 'storage' },
    { source: 'filt_logon', target: 'storage' },
    { source: 'filt_logon', target: 'bus_events' }
  ];

  const colWidth = w / 6;
  const rowHeight = h / 5;
  const nodeW = 180;
  const nodeH = 46;
  const nodePadding = 15;

  let html = `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="overflow: visible;">`;
  
  // Define gradients and markers
  html += `
    <defs>
      <linearGradient id="linkGrad" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style="stop-color:var(--accent);stop-opacity:0.1" />
        <stop offset="50%" style="stop-color:var(--accent);stop-opacity:0.6" />
        <stop offset="100%" style="stop-color:var(--accent);stop-opacity:0.1" />
      </linearGradient>
      <filter id="nodeGlow" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="3" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
      <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
        <polygon points="0 0, 10 3.5, 0 7" fill="var(--accent)" opacity="0.6" />
      </marker>
    </defs>
  `;

  // Draw links first (under nodes)
  links.forEach(link => {
    const s = nodes.find(n => n.id === link.source);
    const t = nodes.find(n => n.id === link.target);
    if (!s || !t) return;

    const x1 = (s.col * colWidth) + nodePadding + nodeW;
    const y1 = (s.row * rowHeight) + (rowHeight / 2);
    const x2 = (t.col * colWidth) + nodePadding;
    const y2 = (t.row * rowHeight) + (rowHeight / 2);

    const cp1x = x1 + (x2 - x1) / 2;
    const cp2x = x1 + (x2 - x1) / 2;
    
    html += `<path d="M ${x1} ${y1} C ${cp1x} ${y1}, ${cp2x} ${y2}, ${x2} ${y2}" 
              stroke="url(#linkGrad)" stroke-width="1.5" fill="none" 
              marker-end="url(#arrowhead)" opacity="0.8">
              <animate attributeName="stroke-dasharray" from="0,10" to="10,0" dur="2s" repeatCount="indefinite" />
            </path>`;
  });

  // Draw nodes
  nodes.forEach(n => {
    const x = (n.col * colWidth) + nodePadding;
    const y = (n.row * rowHeight) + (rowHeight / 2) - (nodeH / 2);

    html += `
      <g class="graph-node" transform="translate(${x}, ${y})">
        <!-- Node Type Header -->
        <text y="-8" font-size="10" fill="var(--warn)" font-weight="600" opacity="0.8">${n.type}</text>
        
        <!-- Node Box -->
        <rect width="${nodeW}" height="${nodeH}" rx="8" ry="8" 
              fill="var(--panel2)" stroke="var(--border)" stroke-width="1" />
        
        <!-- Node Content -->
        <circle cx="12" cy="${nodeH/2}" r="3" fill="var(--accent)">
            <animate attributeName="opacity" values="0.3;1;0.3" dur="2s" repeatCount="indefinite" />
        </circle>
        
        <text x="24" y="${nodeH/2 + 5}" font-size="11" font-weight="500" fill="var(--text)">${n.label}</text>
        
        <!-- Port Dot -->
        <circle cx="${nodeW}" cy="${nodeH/2}" r="2.5" fill="var(--border)" stroke="var(--accent)" stroke-width="1" />
        <circle cx="0" cy="${nodeH/2}" r="2.5" fill="var(--border)" stroke="var(--accent)" stroke-width="1" />
      </g>
    `;
  });

  html += '</svg>';
  container.innerHTML = html;
}

// ---------------------------
// Theme Toggle Logic
// ---------------------------
function initTheme() {
  const toggle = document.getElementById('themeToggle');
  const stored = localStorage.getItem('vkr-theme');
  const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
  
  if (stored === 'light' || (!stored && prefersLight)) {
    document.body.classList.add('light-theme');
  }

  toggle.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const isLight = document.body.classList.contains('light-theme');
    localStorage.setItem('vkr-theme', isLight ? 'light' : 'dark');
    
    // Redraw charts and graph to match colors
    setTimeout(() => {
      refresh();
      renderCorrelationGraph();
    }, 50);
  });
}

// Init
initTheme();
renderSources();
setRoute(currentRoute());
setStatus('Operational', 'ok');
renderCorrelationGraph();
window.onresize = renderCorrelationGraph;
loadPlaybooks();
refresh();
setInterval(refresh, 2500);

// Reload playbooks when navigating to the tab
window.addEventListener('hashchange', ()=>{
  if(currentRoute() === 'playbooks') loadPlaybooks();
});
</script>
</body>
</html>"""

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def ui_index():
    return HTML
