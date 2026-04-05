from __future__ import annotations

import secrets
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
) -> str:
    rows = "".join(
        f"""
        <tr>
          <td>{escape(alert['timestamp'])}</td>
          <td>{escape(alert['severity'])}</td>
          <td>{escape(alert['rule_name'])}</td>
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

    severity_counts = summary["severity_counts"]
    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IDS Dashboard</title>
  <style>
    :root {{ --ink:#10233f; --card:rgba(255,255,255,0.92); --bg1:#f6efe2; --bg2:#dce9ff; }}
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
    a {{ color: var(--ink); }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="bar">
      <h1>Intrusion Detection Dashboard</h1>
      <a href="/logout">Logout</a>
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
        <h3>Filter Alerts</h3>
        <form method="get" action="/">
          <label>Severity</label>
          <input name="severity" value="{escape(selected_severity)}" placeholder="HIGH or MEDIUM">
          <label>Source IP</label>
          <input name="src_ip" value="{escape(selected_src_ip)}" placeholder="10.0.0.5">
          <div style="margin-top: 0.8rem;">
            <button type="submit" style="padding: 0.7rem 1rem; border: 0; border-radius: 10px; background: #10233f; color: white;">Apply</button>
            <a href="/" style="margin-left: 0.8rem;">Clear</a>
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
            self._send_html(
                _dashboard_page(
                    self.server.store.summary(),
                    self.server.store.list_alerts(
                        severity=selected_severity or None,
                        src_ip=selected_src_ip or None,
                    ),
                    selected_severity=selected_severity,
                    selected_src_ip=selected_src_ip,
                )
            )
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
