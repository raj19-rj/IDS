from __future__ import annotations

import secrets
import json
from html import escape
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from ids.config import DEFAULT_DASHBOARD_PASSWORD_HASH, IDSConfig
from ids.security import verify_password
from ids.storage import AlertStore


def _login_page(error: str = "") -> str:
    error_html = f'<p class="error">{escape(error)}</p>' if error else ""
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IDS Login</title>
  <style>
    body {{ font-family: Georgia, serif; background: linear-gradient(135deg, #f7f3e8, #d9e7ff); color: #10233f; padding: 3rem; }}
    .card {{ max-width: 420px; margin: 6rem auto; background: rgba(255,255,255,0.9); padding: 2rem; border-radius: 18px; box-shadow: 0 20px 50px rgba(16,35,63,0.15); }}
    input {{ width: 100%; padding: 0.75rem; margin: 0.5rem 0 1rem; border-radius: 10px; border: 1px solid #9db4d3; box-sizing: border-box; }}
    button {{ width: 100%; padding: 0.85rem; border: 0; border-radius: 10px; background: #10233f; color: white; font-weight: bold; }}
    .error {{ color: #9d1b1b; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>IDS Dashboard</h1>
    <p>Sign in to review alerts and top sources.</p>
    {error_html}
    <form method="post" action="/login">
      <label>Username</label>
      <input name="username" autocomplete="username">
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>
"""


def _dashboard_page(
    summary: dict[str, object],
    alerts: list[dict[str, object]],
    selected_severity: str,
    selected_src_ip: str,
    selected_rule: str,
    selected_search: str,
    selected_limit: str,
    filter_options: dict[str, list[str]],
) -> str:
    rows = "".join(
        f"""
        <tr>
          <td>{escape(alert['timestamp'])}</td>
          <td><span class="badge badge-{escape(str(alert['severity']).lower())}">{escape(alert['severity'])}</span></td>
          <td><a href="/alert?id={escape(alert['fingerprint'])}">{escape(alert['rule_name'])}</a></td>
          <td>{escape(alert['src_ip'])}</td>
          <td>{escape(alert['dst_ip'])}</td>
          <td>{escape(alert['description'])}</td>
        </tr>
        """
        for alert in alerts
    ) or '<tr><td colspan="6">No alerts stored yet.</td></tr>'

    top_sources = "".join(
        f'<p><span class="pill">{escape(source["src_ip"])}</span> {source["count"]} alert(s)</p>'
        for source in summary["top_sources"]
    ) or "<p>No sources yet.</p>"

    top_rules = "".join(
        f'<p><span class="pill">{escape(rule["rule_name"])}</span> {rule["count"]} hit(s)</p>'
        for rule in summary["top_rules"]
    ) or "<p>No rules fired yet.</p>"

    severity_options = "".join(
        f'<option value="{escape(value)}"{" selected" if value == selected_severity else ""}>{escape(value)}</option>'
        for value in filter_options["severities"]
    )
    source_options = "".join(
        f'<option value="{escape(value)}"{" selected" if value == selected_src_ip else ""}>{escape(value)}</option>'
        for value in filter_options["source_ips"]
    )
    rule_options = "".join(
        f'<option value="{escape(value)}"{" selected" if value == selected_rule else ""}>{escape(value)}</option>'
        for value in filter_options["rules"]
    )

    severity_counts = summary["severity_counts"]
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IDS Dashboard</title>
  <meta http-equiv="refresh" content="30">
  <style>
    :root {{ --ink:#10233f; --card:rgba(255,255,255,0.92); --bg1:#f6efe2; --bg2:#dce9ff; --high:#8a1f1f; --medium:#9c5a00; }}
    body {{ font-family: Georgia, serif; margin: 0; background:
      radial-gradient(circle at top left, rgba(182,77,43,0.15), transparent 30%),
      linear-gradient(135deg, var(--bg1), var(--bg2)); color: var(--ink); }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
    .hero {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom: 1.5rem; }}
    .card {{ background: var(--card); border-radius: 18px; padding: 1.2rem; box-shadow: 0 18px 40px rgba(16,35,63,0.12); }}
    table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 18px; overflow: hidden; box-shadow: 0 18px 40px rgba(16,35,63,0.12); }}
    th, td {{ padding: 0.9rem; text-align: left; border-bottom: 1px solid rgba(16,35,63,0.08); vertical-align: top; }}
    th {{ background: rgba(16,35,63,0.08); }}
    .pill {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; background: rgba(182,77,43,0.15); }}
    .bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }}
    .bar-links {{ display:flex; gap:1rem; align-items:center; }}
    .badge {{ display:inline-block; padding:0.2rem 0.55rem; border-radius:999px; font-size:0.9rem; font-weight:bold; }}
    .badge-high {{ background:rgba(138,31,31,0.12); color:var(--high); }}
    .badge-medium {{ background:rgba(156,90,0,0.12); color:var(--medium); }}
    a {{ color: var(--ink); }}
    form.filters {{ display:grid; gap:0.75rem; }}
    input, select {{ width:100%; padding:0.7rem; border-radius:10px; border:1px solid #9db4d3; box-sizing:border-box; background:white; }}
    .actions {{ display:flex; gap:0.75rem; flex-wrap:wrap; margin-top:0.9rem; }}
    .button {{ display:inline-block; padding:0.7rem 1rem; border-radius:10px; background:#10233f; color:white; text-decoration:none; border:0; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="bar">
      <h1>Intrusion Detection Dashboard</h1>
      <div class="bar-links">
        <a href="/api/summary">Summary API</a>
        <a href="/api/alerts">Alerts API</a>
        <a href="/logout">Logout</a>
      </div>
    </div>
    <div class="hero">
      <div class="card"><h3>Total Alerts</h3><p>{summary["total_alerts"]}</p></div>
      <div class="card"><h3>High Severity</h3><p>{severity_counts.get("HIGH", 0)}</p></div>
      <div class="card"><h3>Medium Severity</h3><p>{severity_counts.get("MEDIUM", 0)}</p></div>
    </div>
    <div class="hero">
      <div class="card">
        <h3>Top Sources</h3>
        {top_sources}
      </div>
      <div class="card">
        <h3>Top Rules</h3>
        {top_rules}
      </div>
      <div class="card">
        <h3>Filter Alerts</h3>
        <form method="get" action="/" class="filters">
          <label>Severity</label>
          <select name="severity">
            <option value="">All severities</option>
            {severity_options}
          </select>
          <label>Source IP</label>
          <select name="src_ip">
            <option value="">All sources</option>
            {source_options}
          </select>
          <label>Rule</label>
          <select name="rule">
            <option value="">All rules</option>
            {rule_options}
          </select>
          <label>Search</label>
          <input name="search" value="{escape(selected_search)}" placeholder="description, source, destination">
          <label>Limit</label>
          <select name="limit">
            <option value="25"{" selected" if selected_limit == "25" else ""}>25</option>
            <option value="50"{" selected" if selected_limit == "50" else ""}>50</option>
            <option value="100"{" selected" if selected_limit == "100" else ""}>100</option>
            <option value="250"{" selected" if selected_limit == "250" else ""}>250</option>
          </select>
          <div class="actions">
            <button type="submit" class="button">Apply</button>
            <a href="/" >Clear</a>
            <a href="/export?format=csv">Export CSV</a>
            <a href="/export?format=json">Export JSON</a>
          </div>
        </form>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Rule</th>
          <th>Source</th>
          <th>Destination</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</body>
</html>
"""


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
  <title>Alert Detail</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 0; padding: 2rem; background: linear-gradient(135deg, #f6efe2, #dce9ff); color: #10233f; }}
    .card {{ max-width: 860px; margin: 0 auto; background: rgba(255,255,255,0.95); padding: 1.5rem; border-radius: 18px; box-shadow: 0 18px 40px rgba(16,35,63,0.12); }}
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
        self.sessions: set[str] = set()


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/login":
            self._send_html(_login_page())
            return
        if path == "/logout":
            session_id = self._session_id()
            if session_id:
                self.server.sessions.discard(session_id)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie", "ids_session=; Path=/; Max-Age=0")
            self.end_headers()
            return
        if path == "/":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            selected_severity = query.get("severity", [""])[0].strip().upper()
            selected_src_ip = query.get("src_ip", [""])[0].strip()
            selected_rule = query.get("rule", [""])[0].strip()
            selected_search = query.get("search", [""])[0].strip()
            selected_limit = query.get("limit", ["100"])[0].strip() or "100"
            try:
                limit = max(1, min(int(selected_limit), 250))
            except ValueError:
                limit = 100
                selected_limit = "100"
            self._send_html(
                _dashboard_page(
                    self.server.store.summary(),
                    self.server.store.list_alerts(
                        limit=limit,
                        severity=selected_severity or None,
                        src_ip=selected_src_ip or None,
                        rule_name=selected_rule or None,
                        search=selected_search or None,
                    ),
                    selected_severity=selected_severity,
                    selected_src_ip=selected_src_ip,
                    selected_rule=selected_rule,
                    selected_search=selected_search,
                    selected_limit=str(limit),
                    filter_options=self.server.store.distinct_values(),
                )
            )
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
        if path == "/api/summary":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            self._send_json(self.server.store.summary())
            return
        if path == "/api/alerts":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            limit_text = query.get("limit", ["100"])[0].strip() or "100"
            try:
                limit = max(1, min(int(limit_text), 250))
            except ValueError:
                limit = 100
            alerts = self.server.store.list_alerts(
                limit=limit,
                severity=query.get("severity", [""])[0].strip().upper() or None,
                src_ip=query.get("src_ip", [""])[0].strip() or None,
                rule_name=query.get("rule", [""])[0].strip() or None,
                search=query.get("search", [""])[0].strip() or None,
            )
            self._send_json({"alerts": alerts, "count": len(alerts)})
            return
        if path == "/export":
            if not self._is_authenticated():
                self._redirect("/login")
                return
            export_format = query.get("format", ["csv"])[0].strip().lower()
            if export_format == "json":
                payload = self.server.store.list_alerts(limit=250)
                data = json.dumps(payload, indent=2).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="alerts.json"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            rows = self.server.store.list_alerts(limit=250)
            csv_lines = ["timestamp,severity,rule_name,description,src_ip,dst_ip,fingerprint"]
            for row in rows:
                values = [
                    str(row["timestamp"]),
                    str(row["severity"]),
                    str(row["rule_name"]),
                    str(row["description"]).replace(",", ";"),
                    str(row["src_ip"]),
                    str(row["dst_ip"]),
                    str(row["fingerprint"]),
                ]
                csv_lines.append(",".join(values))
            data = "\n".join(csv_lines).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="alerts.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/login":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        fields = parse_qs(raw_body)
        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]

        if username == self.server.config.dashboard.username and verify_password(
            password=password,
            salt=self.server.config.dashboard.password_salt,
            password_hash=self.server.config.dashboard.password_hash,
        ):
            session_id = secrets.token_hex(16)
            self.server.sessions.add(session_id)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"ids_session={session_id}; Path=/; HttpOnly")
            self.end_headers()
            return

        self._send_html(_login_page("Invalid username or password."), status=HTTPStatus.UNAUTHORIZED)

    def log_message(self, format: str, *args) -> None:
        return

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.end_headers()

    def _session_id(self) -> str | None:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("ids_session")
        return morsel.value if morsel else None

    def _is_authenticated(self) -> bool:
        session_id = self._session_id()
        return bool(session_id and session_id in self.server.sessions)


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
    if config.dashboard.password_hash == DEFAULT_DASHBOARD_PASSWORD_HASH:
        print(
            "Warning: dashboard is using the demo password. "
            "Set IDS_DASHBOARD_PASSWORD or IDS_DASHBOARD_PASSWORD_HASH before deployment."
        )
    server = create_server(config=config, store=store, host=host, port=port)
    print(f"Dashboard running on http://{host}:{port}")
    server.serve_forever()
