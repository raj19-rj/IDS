from __future__ import annotations

import argparse
import threading
from pathlib import Path

from ids.config import IDSConfig, load_config
from ids.detector import IntrusionDetector
from ids.ingest import EventLoader
from ids.monitor import IDSMonitor
from ids.responders import ResponderPipeline
from ids.storage import AlertStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Intrusion Detection System with monitoring, storage, and dashboard"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/ids_config.json"),
        help="Path to IDS configuration file",
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze an event file once")
    analyze.add_argument("--input", type=Path, required=True, help="Path to log file")
    analyze.add_argument(
        "--format",
        choices=[
            "jsonl",
            "csv",
            "windows-events-json",
            "sysmon-json",
            "suricata-eve",
            "zeek-conn",
            "windows-firewall",
        ],
        default="jsonl",
        help="Input format",
    )

    monitor = subparsers.add_parser(
        "monitor",
        help="Continuously monitor an event file or live interface",
    )
    monitor.add_argument("--input", type=Path, help="Path to log file to tail")
    monitor.add_argument(
        "--format",
        choices=[
            "jsonl",
            "csv",
            "windows-events-json",
            "sysmon-json",
            "suricata-eve",
            "zeek-conn",
            "windows-firewall",
        ],
        default="jsonl",
        help="Input format for --input",
    )
    monitor.add_argument("--live", action="store_true", help="Capture live traffic")
    monitor.add_argument("--interface", default=None, help="Network interface")
    monitor.add_argument(
        "--packet-count",
        type=int,
        default=100,
        help="Packets per live capture cycle",
    )
    monitor.add_argument(
        "--cycles",
        type=int,
        default=None,
        help="Optional number of monitor cycles before exiting",
    )
    monitor.add_argument(
        "--replay",
        action="store_true",
        help="Replay the full input file every cycle for demos",
    )

    dashboard = subparsers.add_parser("dashboard", help="Run the web dashboard")
    dashboard.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    dashboard.add_argument("--port", type=int, default=5000, help="Dashboard port")
    dashboard.add_argument("--debug", action="store_true", help="Enable debug mode")
    dashboard.add_argument(
        "--tls-cert",
        type=Path,
        default=None,
        help="Path to TLS certificate file (PEM). Requires --tls-key.",
    )
    dashboard.add_argument(
        "--tls-key",
        type=Path,
        default=None,
        help="Path to TLS private key file (PEM). Requires --tls-cert.",
    )
    dashboard.add_argument(
        "--trust-proxy-headers",
        action="store_true",
        help=(
            "Honor X-Forwarded-Proto/X-Forwarded-Host for HTTPS origin and Secure cookies "
            "(use only behind a trusted reverse proxy such as Nginx)."
        ),
    )
    dashboard.add_argument(
        "--force-https-redirect",
        action="store_true",
        help="Redirect all non-HTTPS requests to HTTPS with HTTP 308.",
    )
    dashboard.add_argument("--input", type=Path, help="Optional log file to monitor live")
    dashboard.add_argument(
        "--format",
        choices=[
            "jsonl",
            "csv",
            "windows-events-json",
            "sysmon-json",
            "suricata-eve",
            "zeek-conn",
            "windows-firewall",
        ],
        default="jsonl",
        help="Input format for --input",
    )
    dashboard.add_argument("--live", action="store_true", help="Capture live traffic")
    dashboard.add_argument("--interface", default=None, help="Network interface")
    dashboard.add_argument(
        "--packet-count",
        type=int,
        default=100,
        help="Packets per live capture cycle",
    )
    dashboard.add_argument(
        "--replay",
        action="store_true",
        help="Replay the full input file every cycle for demos",
    )

    export = subparsers.add_parser("export", help="Export stored alerts")
    export.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination file path",
    )
    export.add_argument(
        "--format",
        choices=["csv", "json"],
        required=True,
        help="Export format",
    )

    return parser


def create_runtime(
    config: IDSConfig,
) -> tuple[IntrusionDetector, AlertStore, EventLoader, ResponderPipeline]:
    detector = IntrusionDetector(config)
    store = AlertStore(config.storage.database_path)
    loader = EventLoader()
    responders = ResponderPipeline.from_config(config)
    return detector, store, loader, responders


def command_analyze(config: IDSConfig, input_path: Path, input_format: str) -> int:
    detector, store, loader, responders = create_runtime(config)
    events = loader.load_file(input_path, input_format)
    alerts = detector.process_events(events)
    stored_count = store.save_alerts(alerts)
    responders.handle(alerts)

    if not alerts:
        print("No alerts detected.")
        return 0

    print(f"Detected {len(alerts)} alert(s). Stored {stored_count} new alert(s).")
    for alert in alerts:
        print(
            f"[{alert.severity}] {alert.rule_name}: {alert.description} "
            f"(src={alert.src_ip}, dst={alert.dst_ip}, time={alert.timestamp.isoformat()})"
        )
    return 0


def command_monitor(
    config: IDSConfig,
    input_path: Path | None,
    input_format: str,
    live: bool,
    interface: str | None,
    packet_count: int,
    cycles: int | None,
    replay: bool,
) -> int:
    detector, store, loader, responders = create_runtime(config)
    monitor = IDSMonitor(
        config=config,
        detector=detector,
        store=store,
        loader=loader,
        responders=responders,
    )
    monitor.run(
        input_path=input_path,
        input_format=input_format,
        live=live,
        interface=interface,
        packet_count=packet_count,
        cycles=cycles,
        replay=replay,
    )
    return 0


def command_dashboard(
    config: IDSConfig,
    host: str,
    port: int,
    debug: bool,
    tls_cert: Path | None,
    tls_key: Path | None,
    trust_proxy_headers: bool,
    force_https_redirect: bool,
    input_path: Path | None,
    input_format: str,
    live: bool,
    interface: str | None,
    packet_count: int,
    replay: bool,
) -> int:
    from ids.web import run_dashboard

    detector, store, loader, responders = create_runtime(config)
    if input_path or live:
        monitor = IDSMonitor(
            config=config,
            detector=detector,
            store=store,
            loader=loader,
            responders=responders,
        )
        thread = threading.Thread(
            target=monitor.run,
            kwargs={
                "input_path": input_path,
                "input_format": input_format,
                "live": live,
                "interface": interface,
                "packet_count": packet_count,
                "cycles": None,
                "replay": replay,
            },
            daemon=True,
        )
        thread.start()
        print("Background monitor started for the dashboard.")
    run_dashboard(
        config=config,
        store=store,
        host=host,
        port=port,
        debug=debug,
        tls_cert_path=tls_cert,
        tls_key_path=tls_key,
        trust_proxy_headers=trust_proxy_headers,
        force_https_redirect=force_https_redirect,
    )
    return 0


def command_export(config: IDSConfig, output_path: Path, export_format: str) -> int:
    _, store, _, _ = create_runtime(config)
    resolved_output_path = output_path.resolve()
    exported_count = store.export_alerts(
        output_path=resolved_output_path,
        export_format=export_format,
    )
    print(f"Exported {exported_count} alert(s) to {resolved_output_path}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    config = load_config(args.config)

    if args.command == "analyze":
        return command_analyze(config, args.input, args.format)

    if args.command == "monitor":
        if not args.input and not args.live:
            parser.error("monitor requires either --input or --live")
        return command_monitor(
            config=config,
            input_path=args.input,
            input_format=args.format,
            live=args.live,
            interface=args.interface,
            packet_count=args.packet_count,
            cycles=args.cycles,
            replay=args.replay,
        )

    if args.command == "dashboard":
        return command_dashboard(
            config,
            args.host,
            args.port,
            args.debug,
            args.tls_cert,
            args.tls_key,
            args.trust_proxy_headers,
            args.force_https_redirect,
            args.input,
            args.format,
            args.live,
            args.interface,
            args.packet_count,
            args.replay,
        )

    if args.command == "export":
        return command_export(config, args.output, args.format)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
