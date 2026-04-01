from __future__ import annotations

from datetime import datetime

from ids.models import Event


def sniff_events(iface: str | None = None, packet_count: int = 100) -> list[Event]:
    try:
        from scapy.all import IP, TCP, UDP, sniff  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "Live capture requires scapy. Install dependencies with "
            "'pip install -r requirements.txt'."
        ) from exc

    captured: list[Event] = []

    def on_packet(packet) -> None:
        if IP not in packet:
            return

        protocol = "IP"
        src_port = 0
        dst_port = 0

        if TCP in packet:
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        captured.append(
            Event(
                timestamp=datetime.now(),
                src_ip=str(packet[IP].src),
                dst_ip=str(packet[IP].dst),
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                size=len(packet),
                event_type="packet",
                outcome="unknown",
            )
        )

    sniff(iface=iface, prn=on_packet, count=packet_count, store=False)
    return captured
