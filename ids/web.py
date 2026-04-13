from __future__ import annotations

import csv
import io
import json
import secrets
import time
from html import escape
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from ids.config import IDSConfig
from ids.security import create_jwt, decode_and_verify_jwt, verify_password
from ids.storage import (
    AlertStore,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    VALID_ROLES,
)

ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60
ACCESS_TOKEN_COOKIE = "ids_access_token"
REFRESH_TOKEN_COOKIE = "ids_refresh_token"
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 5 * 60


def _build_query(params: dict[str, str | int | None], *, omit_page: bool = False) -> str:
    filtered = {}
    for key, value in params.items():
        if value in ("", None):
            continue
        if omit_page and key == "page":
            continue
        filtered[key] = str(value)
    return urlencode(filtered)


def _json_script_payload(payload: object) -> str:
    return json.dumps(payload).replace("</", "<\\/")


def _auth_shell(title: str, subtitle: str, form_html: str, *, error: str = "", warning: str = "", info: str = "") -> str:
    error_html = f'<p class="notice error">{escape(error)}</p>' if error else ""
    warning_html = f'<p class="notice warn">{escape(warning)}</p>' if warning else ""
    info_html = f'<p class="notice info">{escape(info)}</p>' if info else ""
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{ --ink:#10233f; --muted:#5b6f8f; --card:rgba(255,255,255,0.95); --bg1:#f6efe2; --bg2:#dce9ff; --danger:#8a1f1f; --warn:#8a5a00; --info:#1f4c8a; }}
    body {{ font-family: Georgia, serif; background:
      radial-gradient(circle at top left, rgba(182,77,43,0.18), transparent 28%),
      linear-gradient(135deg, var(--bg1), var(--bg2)); color: var(--ink); padding: 2rem; min-height:100vh; box-sizing:border-box; }}
    .card {{ max-width: 460px; margin: 8vh auto; background: var(--card); padding: 2rem; border-radius: 22px; box-shadow: 0 24px 60px rgba(16,35,63,0.16); }}
    h1 {{ margin-top:0; }}
    p.lead {{ color: var(--muted); }}
    label {{ display:block; margin-top: 0.9rem; font-weight: bold; }}
    input {{ width: 100%; padding: 0.8rem; margin-top: 0.35rem; border-radius: 12px; border: 1px solid #9db4d3; box-sizing: border-box; }}
    button {{ width: 100%; padding: 0.9rem; border: 0; border-radius: 12px; background: #10233f; color: white; font-weight: bold; margin-top: 1rem; }}
    a {{ color: #1d3f75; }}
    .links {{ margin-top: 0.9rem; display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }}
    .notice {{ border-radius: 12px; padding: 0.8rem 1rem; }}
    .error {{ background: rgba(138,31,31,0.08); color: var(--danger); }}
    .warn {{ background: rgba(138,90,0,0.08); color: var(--warn); }}
    .info {{ background: rgba(31,76,138,0.08); color: var(--info); }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{escape(title)}</h1>
    <p class="lead">{escape(subtitle)}</p>
    {warning_html}
    {info_html}
    {error_html}
    {form_html}
  </div>
</body>
</html>
"""


def _login_page(error: str = "", warning: str = "", info: str = "") -> str:
    return _auth_shell(
        "IDS Dashboard",
        "Sign in to review alerts, investigate details, and export findings.",
        """
        <form method="post" action="/login">
          <label>Username</label>
          <input name="username" autocomplete="username">
          <label>Password</label>
          <input name="password" type="password" autocomplete="current-password">
          <button type="submit">Sign In</button>
        </form>
        <div class="links">
          <a href="/register">Create account</a>
          <a href="/forgot-password">Forgot password?</a>
        </div>
        """,
        error=error,
        warning=warning,
        info=info,
    )


def _register_page(error: str = "", warning: str = "", info: str = "") -> str:
    return _auth_shell(
        "Create Account",
        "Register with your email to activate dashboard access.",
        """
        <form method="post" action="/register">
          <label>Username</label>
          <input name="username" autocomplete="username">
          <label>Email</label>
          <input name="email" type="email" autocomplete="email">
          <label>Password</label>
          <input name="password" type="password" autocomplete="new-password">
          <button type="submit">Create Account</button>
        </form>
        <div class="links">
          <a href="/login">Back to sign in</a>
        </div>
        """,
        error=error,
        warning=warning,
        info=info,
    )


def _forgot_password_page(error: str = "", warning: str = "", info: str = "") -> str:
    return _auth_shell(
        "Reset Password",
        "Enter your verified account email to receive a reset link.",
        """
        <form method="post" action="/forgot-password">
          <label>Email</label>
          <input name="email" type="email" autocomplete="email">
          <button type="submit">Send Reset Link</button>
        </form>
        <div class="links">
          <a href="/login">Back to sign in</a>
        </div>
        """,
        error=error,
        warning=warning,
        info=info,
    )


def _reset_password_page(token: str, error: str = "", warning: str = "", info: str = "") -> str:
    return _auth_shell(
        "Choose New Password",
        "Set a new password for your account.",
        f"""
        <form method="post" action="/reset-password">
          <input type="hidden" name="token" value="{escape(token)}">
          <label>New Password</label>
          <input name="password" type="password" autocomplete="new-password">
          <button type="submit">Update Password</button>
        </form>
        <div class="links">
          <a href="/login">Back to sign in</a>
        </div>
        """,
        error=error,
        warning=warning,
        info=info,
    )


def _dashboard_page(
    payload: dict[str, object],
) -> str:
    template = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel Ops Dashboard</title>
  <style>
    :root{--bg:#f3f8ff;--panel:#fff;--soft:#f6f9ff;--line:#d7e3f0;--text:#12253f;--muted:#5f7390;--blue:#2563eb;--blue2:#1e40af;--high:#c43e31;--med:#bc7b1c;--ok:#108a63;--r:16px;--sh:0 18px 36px rgba(15,35,55,.09)}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 110% -20%,rgba(37,99,235,.16),transparent 30%),var(--bg);color:var(--text);font:15px/1.45 "Segoe UI",Tahoma,sans-serif}
    .app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}.side{background:linear-gradient(180deg,#10233c,#182f4d);color:#eef4ff;padding:1rem;display:flex;flex-direction:column;gap:.8rem}
    .brand{display:flex;gap:.7rem;align-items:center;padding-bottom:.8rem;border-bottom:1px solid rgba(255,255,255,.12)}.mark{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#60a5fa,var(--blue));display:grid;place-items:center;font-weight:800}
    .label{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:rgba(224,231,255,.62)}.n{display:flex;gap:.55rem;align-items:center;padding:.66rem .75rem;border-radius:12px;color:#f7fbff;text-decoration:none;transition:.22s}.n:hover{background:rgba(255,255,255,.1);box-shadow:0 8px 18px rgba(37,99,235,.15)}.n.active{background:linear-gradient(135deg,rgba(96,165,250,.3),rgba(37,99,235,.36));box-shadow:inset 0 0 0 1px rgba(191,219,254,.32),0 10px 20px rgba(37,99,235,.22)}
    .ic{display:inline-flex;width:16px;height:16px;align-items:center;justify-content:center;color:inherit;flex:0 0 16px;transition:transform .2s,color .2s,filter .2s}.ic svg{width:16px;height:16px;fill:currentColor}
    .n:hover .ic{transform:translateY(-1px);color:#bfdbfe;filter:drop-shadow(0 2px 6px rgba(191,219,254,.35))}
    .n.active .ic{color:#dbeafe;filter:drop-shadow(0 2px 8px rgba(147,197,253,.45))}
    .note{margin-top:auto;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.1);padding:.8rem;border-radius:12px;font-size:.83rem;color:rgba(240,249,255,.85)}
    main{padding:1rem;display:grid;gap:1rem}.top,.card{background:var(--panel);border:1px solid var(--line);box-shadow:var(--sh)}.top{display:flex;justify-content:space-between;gap:.7rem;align-items:center;border-radius:18px;padding:.72rem .9rem}
    .search{flex:1;max-width:620px}.search input{width:100%;padding:.72rem .8rem;border:1px solid var(--line);border-radius:12px}
    .acts{display:flex;gap:.5rem;align-items:center}.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:12px;padding:.6rem .85rem;font-weight:600;text-decoration:none;cursor:pointer;transition:.22s}
    .btn.i{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;padding:0}
    .btn.i:hover{border-color:#bfd4f6;background:#f1f6ff;box-shadow:0 10px 20px rgba(37,99,235,.16)}
    .btn.i:hover .ic{transform:translateY(-1px) scale(1.03);color:#1e40af;filter:drop-shadow(0 2px 6px rgba(37,99,235,.25))}
    .btn.i:active{transform:translateY(0)}
    .btn:hover,.chip:hover{transform:translateY(-1px);box-shadow:0 9px 16px rgba(37,99,235,.12)}.btn.p{background:linear-gradient(135deg,var(--blue),var(--blue2));color:#fff;border:0}.btn.g{background:var(--soft);color:var(--blue2)}
    .avatar{width:36px;height:36px;border-radius:11px;background:linear-gradient(135deg,#dbeafe,#bfdbfe);display:grid;place-items:center;color:var(--blue2);font-weight:700}
    .muted{color:var(--muted)}.small{font-size:.85rem}.head{display:flex;justify-content:space-between;align-items:flex-end;gap:.7rem;flex-wrap:wrap}.head h2{margin:0}
    .banner{display:none;border-radius:12px;padding:.68rem .8rem}.err{background:#fff2f2;color:#991b1b;border:1px solid #fecaca}.load{background:#eff6ff;color:#1e3a8a;border:1px dashed #bfdbfe}
    .kpi{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1rem}.card{border-radius:var(--r);padding:.9rem}.num{font-size:1.9rem;font-weight:800;margin:.22rem 0}.meta{font-size:.83rem;color:var(--ok)}
    .status{display:grid;grid-template-columns:1.2fr .8fr;gap:1rem}.pill{display:inline-flex;gap:.4rem;align-items:center;padding:.4rem .7rem;border-radius:999px;background:rgba(16,138,99,.13);color:var(--ok);font-weight:700}.pill.off{background:rgba(196,62,49,.12);color:var(--high)}.dot{width:.68rem;height:.68rem;border-radius:50%;background:currentColor}
    .barline{height:10px;background:#e6edf9;border-radius:999px;overflow:hidden}.barline span{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--blue),#0ea5e9,var(--ok))}
    .grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(300px,.95fr);gap:1rem}.g2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
    .row{display:flex;justify-content:space-between;gap:.6rem;align-items:center;flex-wrap:wrap}.chips{display:flex;gap:.4rem;flex-wrap:wrap}.chip{border:1px solid var(--line);background:var(--soft);padding:.4rem .68rem;border-radius:999px;cursor:pointer;font-weight:700;color:var(--muted)}.chip.a{background:#e6efff;color:var(--blue2)}
    .timeline{display:flex;gap:.45rem;align-items:flex-end;min-height:170px;margin-top:.6rem}.bw{flex:1;text-align:center}.b{min-height:8px;border-radius:11px 11px 4px 4px;background:linear-gradient(180deg,var(--blue),#60a5fa)}.ll{font-size:.73rem;color:var(--muted);margin-top:.25rem}
    .line{width:100%;height:190px;margin-top:.6rem;display:block}.area{fill:rgba(37,99,235,.16)}.path{fill:none;stroke:#1d4ed8;stroke-width:2.5}
    .list{display:grid;gap:.55rem;margin-top:.55rem}.it{display:flex;justify-content:space-between;gap:.55rem;padding:.68rem .72rem;border:1px solid var(--line);border-radius:12px;background:var(--soft)}
    .badge{display:inline-block;border-radius:999px;padding:.17rem .48rem;font-size:.78rem;font-weight:700}.bh{color:var(--high);background:rgba(196,62,49,.12)}.bm{color:var(--med);background:rgba(188,123,28,.14)}.bl{color:var(--blue2);background:rgba(37,99,235,.1)}
    .tags{display:flex;gap:.32rem;flex-wrap:wrap;margin-top:.22rem}.tag{font-size:.75rem;padding:.14rem .45rem;border-radius:999px;background:#eaf2ff;color:var(--blue2)}
    form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem}.full{grid-column:1/-1}label{display:block;font-size:.84rem;font-weight:700;margin-bottom:.25rem}
    input,select{width:100%;padding:.66rem .72rem;border:1px solid var(--line);border-radius:11px}.actions{display:flex;gap:.5rem;flex-wrap:wrap}
    table{width:100%;border-collapse:collapse;margin-top:.6rem;border:1px solid var(--line);border-radius:12px;overflow:hidden}th,td{padding:.7rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{font-size:.76rem;text-transform:uppercase;letter-spacing:.05em;color:#4c6180;background:#f3f8ff}
    .pagi{display:flex;justify-content:space-between;gap:.6rem;align-items:center;flex-wrap:wrap;margin-top:.6rem}.empty{border:1px dashed var(--line);padding:.72rem;border-radius:11px;background:var(--soft);color:var(--muted)}
    .pie{width:150px;height:150px;border-radius:50%;margin:auto;position:relative;background:conic-gradient(var(--blue) 0deg,var(--blue) 240deg,#87b4ff 240deg,#87b4ff 315deg,#e5edf8 315deg,#e5edf8 360deg)}.pie:after{content:"";position:absolute;inset:22px;background:#fff;border-radius:50%}.pie strong{position:absolute;inset:0;display:grid;place-items:center;z-index:1}
    @media (max-width:1200px){.grid,.status,.g2,.kpi{grid-template-columns:1fr}.head,.top,.row{flex-direction:column;align-items:flex-start}}@media (max-width:900px){.app{grid-template-columns:1fr}.side{position:relative;height:auto}}@media (max-width:760px){form{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="app">
    <aside class="side">
      <div class="brand"><div class="mark">SO</div><div><strong>Sentinel Ops</strong><div class="small" style="color:rgba(224,231,255,.75)">Security analytics</div></div></div>
      <div class="label">Workspace</div>
      <a class="n active" href="/" title="Overview"><span class="ic"><svg viewBox="0 0 24 24"><path d="M3 13h8v8H3zm10-10h8v18h-8zM3 3h8v8H3z"/></svg></span>Dashboard</a>
      <a class="n" href="/api/dashboard" title="API payload"><span class="ic"><svg viewBox="0 0 24 24"><path d="M4 4h16v4H4zm0 6h6v10H4zm8 0h8v10h-8z"/></svg></span>Data API</a>
      <a class="n" href="/api/alerts" title="Alert feed"><span class="ic"><svg viewBox="0 0 24 24"><path d="M12 2 1 21h22zm1 14h-2v2h2zm0-6h-2v4h2z"/></svg></span>Alerts</a>
      <a class="n" href="/api/live" title="Live data"><span class="ic"><svg viewBox="0 0 24 24"><path d="M12 20a8 8 0 1 1 8-8h2A10 10 0 1 0 12 22zm1-11h-2v5l4.3 2.6 1-1.7-3.3-1.9z"/></svg></span>Live</a>
      <a class="n" href="/api/health" title="Health endpoint"><span class="ic"><svg viewBox="0 0 24 24"><path d="M3 13h4l2-4 4 8 2-4h6v-2h-5l-3 6-4-8-2 4H3z"/></svg></span>Health</a>
      <div class="label">Actions</div>
      <a class="n" href="/export?format=csv" title="Download CSV"><span class="ic"><svg viewBox="0 0 24 24"><path d="M5 20h14v2H5zm7-18 5 5h-3v6h-4V7H7z"/></svg></span>Export CSV</a>
      <a class="n" href="/export?format=json" title="Download JSON"><span class="ic"><svg viewBox="0 0 24 24"><path d="M4 4h16v16H4zm4 4H6v8h2zm4 0h-2v8h2zm6 0h-2v8h2z"/></svg></span>Export JSON</a>
      <a class="n" href="/logout" title="Sign out"><span class="ic"><svg viewBox="0 0 24 24"><path d="M10 17v-2h4V9h-4V7h6v10z"/><path d="M5 3h8v2H7v14h6v2H5z"/><path d="m18 12-3 3v-2h-4v-2h4V9z"/></svg></span>Logout</a>
      <div class="note">Production-style dashboard layout with KPI cards, chart analytics, and live incident operations.</div>
    </aside>
    <main>
      <div class="top"><div class="search"><input id="global-search" type="search" placeholder="Search alerts, rule names, IPs, descriptions, metadata"></div><div class="acts"><button class="btn i" id="refresh-btn" title="Refresh dashboard"><span class="ic"><svg viewBox="0 0 24 24"><path d="M17.7 6.3A8 8 0 1 0 20 12h-2a6 6 0 1 1-1.76-4.24L13 11h7V4z"/></svg></span></button><a class="btn i" href="/api/health" title="Health API"><span class="ic"><svg viewBox="0 0 24 24"><path d="M3 13h4l2-4 4 8 2-4h6v-2h-5l-3 6-4-8-2 4H3z"/></svg></span></a><button class="btn i" title="Notifications"><span class="ic"><svg viewBox="0 0 24 24"><path d="M12 22a2.5 2.5 0 0 0 2.45-2h-4.9A2.5 2.5 0 0 0 12 22m7-6V11a7 7 0 1 0-14 0v5l-2 2v1h18v-1z"/></svg></span></button><div style="display:flex;gap:.45rem;align-items:center"><div class="avatar">AD</div><div><strong>Admin</strong><div class="small muted">SOC Team</div></div></div></div></div>
      <div class="head"><div><h2>Enterprise Threat Dashboard</h2><div class="muted">Modern clean UI with responsive layout, filters, sorting, and dynamic visual analytics.</div></div><div class="acts"><a class="btn g" id="export-csv" href="/export?format=csv">Export CSV</a><a class="btn g" id="export-json" href="/export?format=json">Export JSON</a><a class="btn p" href="/api/dashboard">Open API</a></div></div>
      <div id="error" class="banner err"></div><div id="loading" class="banner load">Loading data...</div>
      <section class="kpi"><div class="card"><div class="small muted">Total Alerts</div><div class="num" id="m-total">0</div><div class="meta">Stored inventory</div></div><div class="card"><div class="small muted">High Severity</div><div class="num" id="m-high">0</div><div class="meta">Critical queue</div></div><div class="card"><div class="small muted">Recent Alerts</div><div class="num" id="m-recent">0</div><div class="meta">Current window</div></div><div class="card"><div class="small muted">Alerts / Minute</div><div class="num" id="m-rate">0</div><div class="meta">Live pressure</div></div></section>
      <section class="status"><div class="card"><div class="row"><div><h3 style="margin:0">Operations Status</h3><div class="muted" id="live-text">Checking feed...</div></div><div class="pill" id="live-pill"><span class="dot"></span><span id="live-pill-text">Checking</span></div></div></div><div class="card"><div class="row"><h3 style="margin:0">Risk Score</h3><strong id="threat-score">0/100</strong></div><div class="barline"><span id="threat-bar"></span></div><div class="small muted" title="Calculated from recent high and medium incidents">Threat pressure for selected date window</div><div class="small muted" id="threat-meta">Waiting for events.</div></div></section>
      <section class="grid">
        <div>
          <div class="card"><div class="row"><div><h3 style="margin:0">Alert Trends</h3><div class="small muted">Bar, line, and pie data updates with filters.</div></div><div class="chips"><button class="chip a" data-window="15">15m</button><button class="chip" data-window="60">1h</button><button class="chip" data-window="240">4h</button><button class="chip" data-window="1440">24h</button></div></div><div class="timeline" id="timeline"></div><svg class="line" id="line" viewBox="0 0 640 220" preserveAspectRatio="none"></svg><div class="small muted" id="timeline-sum">No timeline data.</div></div>
          <div class="g2" style="margin-top:1rem"><div class="card"><h3 style="margin:0">Active Source Tracker</h3><div class="small muted">Top talkers in selected window.</div><div id="tracker" class="list"></div></div><div class="card"><h3 style="margin:0">Live Incident Stream</h3><div class="small muted">Recent detections for analysts.</div><div id="feed" class="list"></div></div></div>
          <div class="card" style="margin-top:1rem"><div class="row"><div><h3 style="margin:0">Alert Table</h3><div class="small muted" id="table-sum">Loading...</div></div><div class="small muted">Search, sort, filter, paginate</div></div><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Description</th></tr></thead><tbody id="table"></tbody></table><div id="pagi" class="pagi"></div></div>
        </div>
        <div style="display:grid;gap:1rem">
          <div class="card"><h3 style="margin:0">Filters & Sorting</h3><form id="filters"><div><label for="severity">Severity</label><select id="severity"></select></div><div><label for="src_ip">Source IP</label><select id="src_ip"></select></div><div><label for="rule">Category / Rule</label><select id="rule"></select></div><div><label for="window">Date Window</label><select id="window"><option value="15">Last 15 minutes</option><option value="60">Last 1 hour</option><option value="240">Last 4 hours</option><option value="1440">Last 24 hours</option></select></div><div><label for="sort_by">Sort By</label><select id="sort_by"><option value="timestamp">Timestamp</option><option value="severity">Severity</option><option value="rule_name">Rule</option><option value="src_ip">Source IP</option><option value="dst_ip">Destination IP</option></select></div><div><label for="sort_dir">Sort Direction</label><select id="sort_dir"><option value="desc">Descending</option><option value="asc">Ascending</option></select></div><div><label for="limit">Rows Per Page</label><select id="limit"><option value="25">25</option><option value="50">50</option><option value="100">100</option><option value="250">250</option></select></div><div class="full"><label for="search">Search</label><input id="search" type="search" placeholder="Search alerts, rule names, and metadata"></div><div class="full actions"><button class="btn p" type="submit">Apply Filters</button><a class="btn g" href="/">Reset</a></div></form></div>
          <div class="card"><div style="display:grid;grid-template-columns:150px 1fr;gap:.8rem;align-items:center"><div class="pie" id="pie"><strong id="pie-total">0</strong></div><div><h3 style="margin:0">Severity Distribution</h3><div id="sev-list" class="list"></div></div></div></div>
          <div class="card"><h3 style="margin:0">Top Sources</h3><div id="top-sources" class="list"></div></div>
          <div class="card"><h3 style="margin:0">Top Rules</h3><div id="top-rules" class="list"></div></div>
          <div class="card"><h3 style="margin:0">Recent Rule Heat</h3><div id="recent-rules" class="list"></div></div>
        </div>
      </section>
    </main>
  </div>
  <script id="initial-data" type="application/json">__INITIAL_DATA__</script>
  <script>
    let state=JSON.parse(document.getElementById("initial-data").textContent),debounce=null;
    const el={error:document.getElementById("error"),loading:document.getElementById("loading"),filters:document.getElementById("filters"),severity:document.getElementById("severity"),src_ip:document.getElementById("src_ip"),rule:document.getElementById("rule"),window:document.getElementById("window"),sort_by:document.getElementById("sort_by"),sort_dir:document.getElementById("sort_dir"),limit:document.getElementById("limit"),search:document.getElementById("search"),globalSearch:document.getElementById("global-search"),chips:Array.from(document.querySelectorAll(".chip"))};
    const esc=v=>String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;"),n=v=>Number(v||0).toLocaleString();
    const sev=s=>{const x=String(s||"").toUpperCase();if(x==="HIGH")return"badge bh";if(x==="MEDIUM")return"badge bm";return"badge bl"};
    const setOpts=(node,arr,val,label)=>{node.innerHTML=[`<option value="">${label}</option>`,...(arr||[]).map(x=>`<option value="${esc(x)}">${esc(x)}</option>`)].join("");node.value=val||""};
    const getF=()=>({severity:el.severity.value||"",src_ip:el.src_ip.value||"",rule:el.rule.value||"",window:el.window.value||"15",sort_by:el.sort_by.value||"timestamp",sort_dir:el.sort_dir.value||"desc",limit:el.limit.value||"50",search:el.search.value||"",page:String((state.filters&&state.filters.page)||1)});
    function syncFilters(){const o=state.filter_options||{},f=state.filters||{};setOpts(el.severity,o.severities,f.severity,"All severities");setOpts(el.src_ip,o.source_ips,f.src_ip,"All source IPs");setOpts(el.rule,o.rules,f.rule,"All rules");["window","sort_by","sort_dir","limit","search"].forEach(k=>{if(f[k]!==undefined&&el[k])el[k].value=String(f[k])});el.globalSearch.value=f.search||"";el.chips.forEach(c=>c.classList.toggle("a",c.dataset.window===String(el.window.value||"15")))}
    const showErr=m=>{el.error.textContent=m;el.error.style.display="block"},clearErr=()=>{el.error.style.display="none";el.error.textContent=""},setLoading=v=>{el.loading.style.display=v?"block":"none"};
    function render(){
      const s=state.summary||{},l=state.live||{},sc=s.severity_counts||{},rt=state.runtime||{};
      document.getElementById("m-total").textContent=n(s.total_alerts||0);document.getElementById("m-high").textContent=n(sc.HIGH||0);document.getElementById("m-recent").textContent=n(l.recent_alert_count||0);document.getElementById("m-rate").textContent=Number(l.alerts_per_minute||0).toFixed(2);
      const live=Boolean(l.is_live);document.getElementById("live-text").textContent=live?`Live feed active. Last alert at ${l.last_alert_at||"recently"}.`:"No fresh events in last minute.";document.getElementById("live-pill-text").textContent=live?"Live":"Idle";document.getElementById("live-pill").classList.toggle("off",!live);
      const score=Number(l.threat_score||0);document.getElementById("threat-score").textContent=`${score}/100`;document.getElementById("threat-bar").style.width=`${Math.max(0,Math.min(100,score))}%`;document.getElementById("threat-meta").textContent=`Mode: ${rt.mode||"idle"}, cycle: ${rt.last_cycle||0}`;
      const tl=l.timeline||[],tEl=document.getElementById("timeline"),line=document.getElementById("line"),sum=document.getElementById("timeline-sum");
      if(!tl.length){tEl.innerHTML='<div class="empty">No timeline points in selected window.</div>';line.innerHTML="";sum.textContent="No trend data available.";}else{const mx=Math.max(1,...tl.map(p=>Number(p.count||0)));tEl.innerHTML=tl.map(p=>{const h=Math.max(8,Math.round((Number(p.count||0)/mx)*130));return`<div class="bw"><div class="b" style="height:${h}px" title="${esc(p.label)}: ${esc(p.count)} alerts"></div><div class="ll">${esc(p.label)}</div></div>`}).join("");const w=640,h=220,p=16,st=tl.length>1?(w-p*2)/(tl.length-1):0,pts=tl.map((x,i)=>{const v=Number(x.count||0),xx=p+st*i,yy=h-p-((h-p*2)*v)/mx;return{xx,yy}}),path=pts.map((z,i)=>`${i?"L":"M"} ${z.xx} ${z.yy}`).join(" "),area=`${path} L ${w-p} ${h-p} L ${p} ${h-p} Z`;line.innerHTML=`<path class="area" d="${area}"></path><path class="path" d="${path}"></path>`;sum.textContent=`${tl.reduce((a,x)=>a+Number(x.count||0),0)} alerts in selected window.`}
      const hi=Number(sc.HIGH||0),md=Number(sc.MEDIUM||0),lo=Number((sc.LOW||0)+(sc.INFO||0)),tot=Math.max(1,hi+md+lo),hD=Math.round((hi/tot)*360),mD=Math.round((md/tot)*360),pie=document.getElementById("pie");pie.style.background=`conic-gradient(var(--blue) 0deg,var(--blue) ${hD}deg,#87b4ff ${hD}deg,#87b4ff ${hD+mD}deg,#e5edf8 ${hD+mD}deg,#e5edf8 360deg)`;document.getElementById("pie-total").textContent=n(hi+md+lo);
      document.getElementById("sev-list").innerHTML=[`<div class="it"><span>High severity</span><strong>${n(hi)}</strong></div>`,`<div class="it"><span>Medium severity</span><strong>${n(md)}</strong></div>`,`<div class="it"><span>Low / Info</span><strong>${n(lo)}</strong></div>`].join("");
      const track=l.source_tracker||[];document.getElementById("tracker").innerHTML=track.length?track.map(r=>`<div class="it"><div><strong>${esc(r.src_ip)}</strong><div class="small muted">Last seen: ${esc(r.last_seen||"n/a")}</div><div class="tags">${(r.destinations||[]).map(d=>`<span class="tag">${esc(d)}</span>`).join("")||'<span class="tag">No destinations</span>'}</div></div><div><strong>${n(r.count||0)}</strong><div class="small muted">${n(r.high_count||0)} high</div></div></div>`).join(""):'<div class="empty">No active sources.</div>';
      const feed=l.feed||[];document.getElementById("feed").innerHTML=feed.length?feed.map(a=>`<div class="it"><div><div><span class="${sev(a.severity)}">${esc(a.severity)}</span> <strong>${esc(a.rule_name)}</strong></div><div class="small muted">${esc(a.src_ip)} -> ${esc(a.dst_ip)}</div><div class="small muted">${esc(a.timestamp)}</div></div></div>`).join(""):'<div class="empty">No incidents in this window.</div>';
      const simple=(id,arr,key,count,msg)=>{document.getElementById(id).innerHTML=arr&&arr.length?arr.map(x=>`<div class="it"><span>${esc(x[key])}</span><strong>${n(x[count])}</strong></div>`).join(""):`<div class="empty">${esc(msg)}</div>`};simple("top-sources",s.top_sources||[],"src_ip","count","No source data.");simple("top-rules",s.top_rules||[],"rule_name","count","No rule data.");simple("recent-rules",l.top_recent_rules||[],"rule_name","count","No recent rule activity.");
      const rows=state.alerts||[],tb=document.getElementById("table"),totF=Number(state.total_filtered||0),pg=Number((state.filters&&state.filters.page)||1),lim=Number((state.filters&&state.filters.limit)||50),pages=Math.max(1,Number(state.total_pages||1));tb.innerHTML=rows.length?rows.map(a=>`<tr><td>${esc(a.timestamp)}</td><td><span class="${sev(a.severity)}">${esc(a.severity)}</span></td><td><a href="/alert?id=${encodeURIComponent(a.fingerprint||"")}">${esc(a.rule_name)}</a></td><td>${esc(a.src_ip)}</td><td>${esc(a.dst_ip)}</td><td>${esc(a.description)}</td></tr>`).join(""):'<tr><td colspan="6"><div class="empty">No matching alerts found.</div></td></tr>';
      const st=totF?((pg-1)*lim+1):0,en=Math.min(pg*lim,totF);document.getElementById("table-sum").textContent=`Showing ${st}-${en} of ${n(totF)} alerts`;document.getElementById("pagi").innerHTML=`<div class="small muted">Page ${pg} of ${pages}</div><div style="display:flex;gap:.5rem"><button class="btn g" id="pr" ${pg<=1?"disabled":""}>Previous</button><button class="btn g" id="nx" ${pg>=pages?"disabled":""}>Next</button></div>`;const pr=document.getElementById("pr"),nx=document.getElementById("nx");if(pr)pr.addEventListener("click",()=>fetchData({page:Math.max(1,pg-1)}));if(nx)nx.addEventListener("click",()=>fetchData({page:Math.min(pages,pg+1)}));
      const q=new URLSearchParams(state.filters||{}).toString();document.getElementById("export-csv").href=`/export?format=csv&${q}`;document.getElementById("export-json").href=`/export?format=json&${q}`;
    }
    async function fetchData(override={},opts={}){const silent=Boolean(opts.silent),keepPage=Boolean(opts.keepPage);if(!silent)setLoading(true);clearErr();const f=getF();if(!keepPage&&!Object.prototype.hasOwnProperty.call(override,"page"))f.page="1";const q=new URLSearchParams({...f,...override});try{const r=await fetch(`/api/dashboard?${q.toString()}`,{headers:{"Accept":"application/json"}});if(!r.ok)throw new Error(`Request failed (${r.status})`);state=await r.json();syncFilters();render()}catch(e){showErr(`Unable to refresh dashboard data. ${e.message}`)}finally{if(!silent)setLoading(false)}}
    syncFilters();render();
    el.filters.addEventListener("submit",e=>{e.preventDefault();fetchData()});el.search.addEventListener("input",()=>{el.globalSearch.value=el.search.value});el.globalSearch.addEventListener("input",()=>{el.search.value=el.globalSearch.value;clearTimeout(debounce);debounce=setTimeout(()=>fetchData(),320)});
    ["severity","src_ip","rule","window","sort_by","sort_dir","limit"].forEach(k=>el[k].addEventListener("change",()=>fetchData()));document.getElementById("refresh-btn").addEventListener("click",()=>fetchData({}, {keepPage:true}));
    el.chips.forEach(c=>c.addEventListener("click",()=>{el.window.value=c.dataset.window||"15";el.chips.forEach(x=>x.classList.remove("a"));c.classList.add("a");fetchData()}));
    setInterval(()=>fetchData({}, {silent:true,keepPage:true}),15000);
  </script>
</body>
</html>
"""
    return template.replace("__INITIAL_DATA__", _json_script_payload(payload))


def _alert_detail_page(alert: dict[str, object]) -> str:
    metadata_rows = "".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>"
        for key, value in dict(alert["metadata"]).items()
    ) or "<tr><td colspan='2'>No metadata</td></tr>"

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Alert Detail</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 0; padding: 1.5rem; background: linear-gradient(135deg, #f6efe2, #dce9ff); color: #10233f; }}
    .card {{ max-width: 960px; margin: 0 auto; background: rgba(255,255,255,0.95); padding: 1.5rem; border-radius: 20px; box-shadow: 0 18px 40px rgba(16,35,63,0.12); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 0.8rem; text-align: left; border-bottom: 1px solid rgba(16,35,63,0.08); vertical-align: top; }}
    th {{ width: 220px; }}
    a {{ color: #10233f; }}
  </style>
</head>
<body>
  <div class="card">
    <p><a href="/">Back to dashboard</a></p>
    <h1>{escape(str(alert["rule_name"]))}</h1>
    <p>{escape(str(alert["description"]))}</p>
    <table>
      <tr><th>Timestamp</th><td>{escape(str(alert["timestamp"]))}</td></tr>
      <tr><th>Severity</th><td>{escape(str(alert["severity"]))}</td></tr>
      <tr><th>Source IP</th><td>{escape(str(alert["src_ip"]))}</td></tr>
      <tr><th>Destination IP</th><td>{escape(str(alert["dst_ip"]))}</td></tr>
      <tr><th>Fingerprint</th><td>{escape(str(alert["fingerprint"]))}</td></tr>
    </table>
    <h2>Metadata</h2>
    <table>
      {metadata_rows}
    </table>
  </div>
</body>
</html>
"""


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], config: IDSConfig, store: AlertStore):
        super().__init__(server_address, DashboardHandler)
        self.config = config
        self.store = store
        self.login_attempts: dict[str, list[float]] = {}


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def do_GET(self) -> None:
        self._auth_context: dict[str, str] | None = None
        self._pending_cookies: list[str] = []
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/login":
            self._send_html(_login_page(warning=self._demo_warning()))
            return
        if path == "/register":
            self._send_html(_register_page(warning=self._demo_warning()))
            return
        if path == "/verify-email":
            token = query.get("token", [""])[0].strip()
            if not token:
                self._send_html(_login_page(error="Verification token is missing."))
                return
            if self.server.store.consume_email_verification_token(token):
                self._send_html(
                    _login_page(info="Email verified successfully. You can sign in now."),
                    status=HTTPStatus.OK,
                )
                return
            self._send_html(
                _login_page(error="Verification link is invalid or expired."),
                status=HTTPStatus.BAD_REQUEST,
            )
            return
        if path == "/forgot-password":
            self._send_html(_forgot_password_page())
            return
        if path == "/reset-password":
            token = query.get("token", [""])[0].strip()
            if not token:
                self._send_html(
                    _forgot_password_page(error="Reset token is missing."),
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            self._send_html(_reset_password_page(token))
            return
        if path == "/logout":
            refresh_token = self._cookie_value(REFRESH_TOKEN_COOKIE)
            if refresh_token:
                self.server.store.revoke_refresh_token(refresh_token)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login")
            self.send_header(
                "Set-Cookie",
                f"{ACCESS_TOKEN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            )
            self.send_header(
                "Set-Cookie",
                f"{REFRESH_TOKEN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            )
            self.end_headers()
            return
        if path == "/":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            self._send_html(_dashboard_page(self._build_dashboard_payload(query)))
            return
        if path == "/alert":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            fingerprint = query.get("id", [""])[0].strip()
            alert = self.server.store.get_alert(fingerprint)
            if alert is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self._send_html(_alert_detail_page(alert))
            return
        if path == "/api/health":
            live = self.server.store.live_snapshot()
            self._send_json(
                {
                    "status": "ok",
                    "timestamp": int(time.time()),
                    "alerts": self.server.store.summary()["total_alerts"],
                    "live": bool(live["is_live"]),
                    "recent_alerts": live["recent_alert_count"],
                    "runtime": self.server.store.runtime_state(),
                }
            )
            return
        if path == "/api/dashboard":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            self._send_json(self._build_dashboard_payload(query))
            return
        if path == "/api/live":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            self._send_json(self.server.store.live_snapshot())
            return
        if path == "/api/summary":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            self._send_json(self.server.store.summary())
            return
        if path == "/api/me":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            self._send_json(
                {
                    "username": self._current_username(),
                    "role": self._current_role(),
                }
            )
            return
        if path == "/api/alerts":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            filters = self._extract_filters(query)
            alerts = self.server.store.list_alerts(
                limit=filters["limit"],
                offset=(filters["page"] - 1) * filters["limit"],
                severity=filters["severity"] or None,
                src_ip=filters["src_ip"] or None,
                rule_name=filters["rule"] or None,
                search=filters["search"] or None,
            )
            total_filtered = self.server.store.count_alerts(
                severity=filters["severity"] or None,
                src_ip=filters["src_ip"] or None,
                rule_name=filters["rule"] or None,
                search=filters["search"] or None,
            )
            self._send_json(
                {
                    "alerts": alerts,
                    "count": len(alerts),
                    "total_filtered": total_filtered,
                    "page": filters["page"],
                    "limit": filters["limit"],
                    "current_role": self._current_role(),
                }
            )
            return
        if path == "/api/users":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            if not self._require_role(ROLE_ADMIN):
                return
            self._send_json({"users": self.server.store.list_users()})
            return
        if path == "/export":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            filters = self._extract_filters(query)
            rows = self.server.store.list_alerts(
                limit=250,
                offset=0,
                severity=filters["severity"] or None,
                src_ip=filters["src_ip"] or None,
                rule_name=filters["rule"] or None,
                search=filters["search"] or None,
            )
            export_format = query.get("format", ["csv"])[0].strip().lower()
            if export_format == "json":
                self._send_download_json(rows, "alerts.json")
                return
            self._send_download_csv(rows, "alerts.csv")
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        self._auth_context = None
        self._pending_cookies = []
        if self.path == "/api/alerts/ack":
            if not self._is_authenticated():
                self._send_json({"error": "Authentication required."}, status=HTTPStatus.UNAUTHORIZED)
                return
            if not self._require_role(ROLE_ADMIN, ROLE_ANALYST):
                return
            fields = self._read_form_fields()
            fingerprint = fields.get("fingerprint", [""])[0].strip()
            actor = self._current_username() or "unknown"
            if not fingerprint:
                self._send_json({"error": "fingerprint is required."}, status=HTTPStatus.BAD_REQUEST)
                return
            acknowledged = self.server.store.acknowledge_alert(fingerprint=fingerprint, acknowledged_by=actor)
            if not acknowledged:
                self._send_json(
                    {"error": "Alert not found or already acknowledged."},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            self._send_json({"status": "ok", "fingerprint": fingerprint, "acknowledged_by": actor})
            return

        if self.path == "/api/users/role":
            if not self._is_authenticated():
                self._send_json({"error": "Authentication required."}, status=HTTPStatus.UNAUTHORIZED)
                return
            if not self._require_role(ROLE_ADMIN):
                return
            fields = self._read_form_fields()
            username = fields.get("username", [""])[0].strip()
            role = fields.get("role", [""])[0].strip().lower()
            if not username or role not in VALID_ROLES:
                self._send_json(
                    {
                        "error": "username and valid role are required.",
                        "valid_roles": sorted(VALID_ROLES),
                    },
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            if not self.server.store.set_user_role(username=username, role=role):
                self._send_json({"error": "User not found or update failed."}, status=HTTPStatus.NOT_FOUND)
                return
            self._send_json({"status": "ok", "username": username, "role": role})
            return

        if self.path not in {"/login", "/register", "/forgot-password", "/reset-password"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        fields = self._read_form_fields()
        if self.path == "/register":
            username = fields.get("username", [""])[0].strip()
            email = fields.get("email", [""])[0].strip()
            password = fields.get("password", [""])[0]
            if not username or not email or not password:
                self._send_html(
                    _register_page(error="Username, email, and password are required."),
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            try:
                token = self.server.store.register_user(username=username, email=email, password=password)
            except RuntimeError as error:
                self._send_html(_register_page(error=str(error)), status=HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            except ValueError as error:
                self._send_html(_register_page(error=str(error)), status=HTTPStatus.BAD_REQUEST)
                return

            if token is None:
                self._send_html(
                    _register_page(error="Username or email already exists."),
                    status=HTTPStatus.CONFLICT,
                )
                return

            verification_url = f"{self._request_origin()}/verify-email?token={token}"
            self.server.store.queue_outbound_email(
                recipient_email=email,
                subject="Verify your IDS dashboard account",
                body=(
                    "Please verify your email to activate your account:\n"
                    f"{verification_url}\n\n"
                    "This link expires in 24 hours."
                ),
            )
            self._send_html(
                _login_page(info="Registration complete. Check your email for a verification link."),
                status=HTTPStatus.CREATED,
            )
            return

        if self.path == "/forgot-password":
            email = fields.get("email", [""])[0].strip()
            reset_token = self.server.store.create_password_reset_token(email)
            if reset_token:
                reset_url = f"{self._request_origin()}/reset-password?token={reset_token}"
                self.server.store.queue_outbound_email(
                    recipient_email=email,
                    subject="Reset your IDS dashboard password",
                    body=(
                        "Use this secure link to reset your password:\n"
                        f"{reset_url}\n\n"
                        "This link expires in 30 minutes."
                    ),
                )
            self._send_html(
                _forgot_password_page(
                    info=(
                        "If the email is registered and verified, a reset link has been sent."
                    )
                ),
                status=HTTPStatus.OK,
            )
            return

        if self.path == "/reset-password":
            token = fields.get("token", [""])[0].strip()
            password = fields.get("password", [""])[0]
            if not token or not password:
                self._send_html(
                    _reset_password_page(token, error="Token and password are required."),
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            try:
                changed = self.server.store.reset_password_with_token(token, password)
            except RuntimeError as error:
                self._send_html(
                    _reset_password_page(token, error=str(error)),
                    status=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return
            except ValueError as error:
                self._send_html(
                    _reset_password_page(token, error=str(error)),
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            if not changed:
                self._send_html(
                    _forgot_password_page(error="Reset link is invalid or expired."),
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            self._send_html(
                _login_page(info="Password updated successfully. Sign in with your new password."),
                status=HTTPStatus.OK,
            )
            return

        client_ip = self.client_address[0]
        if self._too_many_attempts(client_ip):
            self._send_html(
                _login_page(
                    error="Too many login attempts. Please wait a few minutes before retrying.",
                    warning=self._demo_warning(),
                ),
                status=HTTPStatus.TOO_MANY_REQUESTS,
            )
            return

        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]

        role = self.server.store.authenticate_user_with_role(username=username, password=password)
        if role is not None:
            self._start_session(username=username, role=role)
            self.server.login_attempts.pop(client_ip, None)
            return

        if username == self.server.config.dashboard.username and verify_password(
            password=password,
            salt=self.server.config.dashboard.password_salt,
            password_hash=self.server.config.dashboard.password_hash,
        ):
            self._start_session(username=username, role=ROLE_ADMIN)
            self.server.login_attempts.pop(client_ip, None)
            return

        self._record_failed_attempt(client_ip)
        self._send_html(
            _login_page(
                error="Invalid username/password or account is not verified.",
                warning=self._demo_warning(),
            ),
            status=HTTPStatus.UNAUTHORIZED,
        )

    def log_message(self, format: str, *args) -> None:
        return

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self._apply_pending_cookies()
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self._apply_pending_cookies()
        self.end_headers()
        self.wfile.write(encoded)

    def _send_download_json(self, payload: object, filename: str) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(encoded)))
        self._apply_pending_cookies()
        self.end_headers()
        self.wfile.write(encoded)

    def _send_download_csv(self, rows: list[dict[str, object]], filename: str) -> None:
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=[
                "timestamp",
                "severity",
                "rule_name",
                "description",
                "src_ip",
                "dst_ip",
                "fingerprint",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "timestamp": row["timestamp"],
                    "severity": row["severity"],
                    "rule_name": row["rule_name"],
                    "description": row["description"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "fingerprint": row["fingerprint"],
                }
            )
        encoded = buffer.getvalue().encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(encoded)))
        self._apply_pending_cookies()
        self.end_headers()
        self.wfile.write(encoded)

    def _read_form_fields(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        return parse_qs(raw_body)

    def _request_origin(self) -> str:
        host = self.headers.get("Host", "127.0.0.1")
        return f"http://{host}"

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self._apply_pending_cookies()
        self.end_headers()

    def _cookie_value(self, name: str) -> str | None:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(name)
        return morsel.value if morsel else None

    def _start_session(self, *, username: str, role: str) -> None:
        access_token, refresh_token, refresh_exp = self._build_auth_tokens(username=username, role=role)
        self.server.store.store_refresh_token(username=username, refresh_token=refresh_token, expires_at_epoch=refresh_exp)
        self._queue_auth_cookies(access_token=access_token, refresh_token=refresh_token)
        normalized_role = role.strip().lower()
        if normalized_role not in VALID_ROLES:
            normalized_role = ROLE_VIEWER
        self._auth_context = {"username": username, "role": normalized_role}
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self._apply_pending_cookies()
        self.end_headers()

    def _build_auth_tokens(self, *, username: str, role: str) -> tuple[str, str, int]:
        now_epoch = int(time.time())
        normalized_role = role.strip().lower()
        if normalized_role not in VALID_ROLES:
            normalized_role = ROLE_VIEWER
        access_payload: dict[str, object] = {
            "sub": username,
            "role": normalized_role,
            "type": "access",
            "iat": now_epoch,
            "exp": now_epoch + ACCESS_TOKEN_TTL_SECONDS,
        }
        refresh_payload: dict[str, object] = {
            "sub": username,
            "role": normalized_role,
            "type": "refresh",
            "jti": secrets.token_hex(16),
            "iat": now_epoch,
            "exp": now_epoch + REFRESH_TOKEN_TTL_SECONDS,
        }
        access_token = create_jwt(access_payload, self.server.config.dashboard.secret_key)
        refresh_token = create_jwt(refresh_payload, self.server.config.dashboard.secret_key)
        return access_token, refresh_token, int(refresh_payload["exp"])

    def _queue_auth_cookies(self, *, access_token: str, refresh_token: str) -> None:
        self._pending_cookies.append(
            f"{ACCESS_TOKEN_COOKIE}={access_token}; Path=/; HttpOnly; SameSite=Lax"
        )
        self._pending_cookies.append(
            f"{REFRESH_TOKEN_COOKIE}={refresh_token}; Path=/; HttpOnly; SameSite=Lax"
        )

    def _apply_pending_cookies(self) -> None:
        for cookie_value in self._pending_cookies:
            self.send_header("Set-Cookie", cookie_value)
        self._pending_cookies = []

    def _auth_from_tokens(self) -> dict[str, str] | None:
        access_token = self._cookie_value(ACCESS_TOKEN_COOKIE)
        if access_token:
            access_payload = decode_and_verify_jwt(
                access_token,
                self.server.config.dashboard.secret_key,
            )
            if access_payload and access_payload.get("type") == "access":
                username = str(access_payload.get("sub", "")).strip()
                role = str(access_payload.get("role", ROLE_VIEWER)).strip().lower()
                if username:
                    if role not in VALID_ROLES:
                        role = ROLE_VIEWER
                    return {"username": username, "role": role}

        refresh_token = self._cookie_value(REFRESH_TOKEN_COOKIE)
        if not refresh_token:
            return None
        refresh_payload = decode_and_verify_jwt(
            refresh_token,
            self.server.config.dashboard.secret_key,
        )
        if not refresh_payload or refresh_payload.get("type") != "refresh":
            return None

        username = str(refresh_payload.get("sub", "")).strip()
        if not username:
            return None
        consumed_username = self.server.store.consume_refresh_token(refresh_token)
        if consumed_username is None or consumed_username != username:
            return None
        role = self.server.store.get_user_role(username) or ROLE_VIEWER
        new_access_token, new_refresh_token, refresh_exp = self._build_auth_tokens(
            username=username,
            role=role,
        )
        self.server.store.store_refresh_token(
            username=username,
            refresh_token=new_refresh_token,
            expires_at_epoch=refresh_exp,
        )
        self._queue_auth_cookies(access_token=new_access_token, refresh_token=new_refresh_token)
        return {"username": username, "role": role}

    def _is_authenticated(self) -> bool:
        if self._auth_context is None:
            self._auth_context = self._auth_from_tokens()
        return self._auth_context is not None

    def _current_username(self) -> str:
        if not self._is_authenticated():
            return ""
        assert self._auth_context is not None
        return str(self._auth_context.get("username", ""))

    def _current_role(self) -> str:
        if not self._is_authenticated():
            return ROLE_VIEWER
        assert self._auth_context is not None
        role = str(self._auth_context.get("role", ROLE_VIEWER)).strip().lower()
        if role not in VALID_ROLES:
            return ROLE_VIEWER
        return role

    def _require_role(self, *allowed_roles: str) -> bool:
        current_role = self._current_role()
        normalized_allowed = {role.strip().lower() for role in allowed_roles}
        if current_role in normalized_allowed:
            return True
        self._send_json(
            {
                "error": "Forbidden: insufficient role for this action.",
                "required_roles": sorted(normalized_allowed),
                "current_role": current_role,
            },
            status=HTTPStatus.FORBIDDEN,
        )
        return False

    def _extract_filters(self, query: dict[str, list[str]]) -> dict[str, str | int]:
        limit_text = query.get("limit", ["50"])[0].strip() or "50"
        page_text = query.get("page", ["1"])[0].strip() or "1"
        window_text = query.get("window", ["15"])[0].strip() or "15"
        try:
            limit = max(1, min(int(limit_text), 250))
        except ValueError:
            limit = 50
        try:
            page = max(1, int(page_text))
        except ValueError:
            page = 1
        try:
            window = max(5, min(int(window_text), 1440))
        except ValueError:
            window = 15
        sort_by = query.get("sort_by", ["timestamp"])[0].strip() or "timestamp"
        sort_dir = query.get("sort_dir", ["desc"])[0].strip().lower() or "desc"
        if sort_by not in {"timestamp", "severity", "rule_name", "src_ip", "dst_ip"}:
            sort_by = "timestamp"
        if sort_dir not in {"asc", "desc"}:
            sort_dir = "desc"
        return {
            "severity": query.get("severity", [""])[0].strip().upper(),
            "src_ip": query.get("src_ip", [""])[0].strip(),
            "rule": query.get("rule", [""])[0].strip(),
            "search": query.get("search", [""])[0].strip(),
            "limit": limit,
            "page": page,
            "window": window,
            "sort_by": sort_by,
            "sort_dir": sort_dir,
        }

    def _build_dashboard_payload(self, query: dict[str, list[str]]) -> dict[str, object]:
        filters = self._extract_filters(query)
        total_filtered = self.server.store.count_alerts(
            severity=filters["severity"] or None,
            src_ip=filters["src_ip"] or None,
            rule_name=filters["rule"] or None,
            search=filters["search"] or None,
        )
        total_pages = max(1, (total_filtered + filters["limit"] - 1) // filters["limit"])
        current_page = min(filters["page"], total_pages)
        filters["page"] = current_page
        offset = (current_page - 1) * filters["limit"]
        return {
            "summary": self.server.store.summary(),
            "live": self.server.store.live_snapshot(window_minutes=int(filters["window"])),
            "runtime": self.server.store.runtime_state(),
            "current_user": {
                "username": self._current_username(),
                "role": self._current_role(),
            },
            "alerts": self.server.store.list_alerts(
                limit=filters["limit"],
                offset=offset,
                severity=filters["severity"] or None,
                src_ip=filters["src_ip"] or None,
                rule_name=filters["rule"] or None,
                search=filters["search"] or None,
                sort_by=str(filters["sort_by"]),
                sort_dir=str(filters["sort_dir"]),
            ),
            "filter_options": self.server.store.distinct_values(),
            "filters": filters,
            "total_filtered": total_filtered,
            "total_pages": total_pages,
        }

    def _demo_warning(self) -> str:
        if not self.server.store.has_verified_users():
            return (
                "No verified user accounts found. "
                "Create an account and verify your email before signing in."
            )
        return ""

    def _too_many_attempts(self, client_ip: str) -> bool:
        now = time.time()
        attempts = [
            timestamp
            for timestamp in self.server.login_attempts.get(client_ip, [])
            if now - timestamp <= LOGIN_WINDOW_SECONDS
        ]
        self.server.login_attempts[client_ip] = attempts
        return len(attempts) >= MAX_LOGIN_ATTEMPTS

    def _record_failed_attempt(self, client_ip: str) -> None:
        now = time.time()
        attempts = [
            timestamp
            for timestamp in self.server.login_attempts.get(client_ip, [])
            if now - timestamp <= LOGIN_WINDOW_SECONDS
        ]
        attempts.append(now)
        self.server.login_attempts[client_ip] = attempts


def create_server(config: IDSConfig, store: AlertStore, host: str, port: int) -> DashboardServer:
    return DashboardServer((host, port), config=config, store=store)


def run_dashboard(
    config: IDSConfig,
    store: AlertStore,
    host: str,
    port: int,
    debug: bool,
) -> None:
    _ = debug
    if not store.has_verified_users():
        print(
            "Warning: no verified user accounts exist. "
            "Register a user and verify email before signing in."
        )
    server = create_server(config=config, store=store, host=host, port=port)
    print(f"Dashboard running on http://{host}:{port}")
    server.serve_forever()
