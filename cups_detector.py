#!/usr/bin/env python3
"""Detect suspicious CUPS printer-discovery traffic from live capture or offline PCAPs."""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from scapy.all import IP, Raw, UDP, rdpcap, sniff


def decode_payload(packet) -> str:
    if Raw not in packet:
        return ""
    try:
        return bytes(packet[Raw].load).decode("utf-8", errors="replace")
    except Exception:
        return ""


def is_cups_packet(packet) -> bool:
    if UDP not in packet:
        return False
    udp = packet[UDP]
    # Check ports
    if udp.dport == 631 or udp.sport == 631:
        return True
    # Also check payload for IPP/CUPS signatures (in case port is wrong)
    payload = decode_payload(packet).lower()
    return "ipp/" in payload or "cups-" in payload or "printer-" in payload


def infer_device_class(packet) -> str:
    payload = decode_payload(packet).lower()
    if "printer-uri" in payload or "printer-name" in payload:
        return "printer_advertisement"
    if "cups-get-printers" in payload or "ipp/" in payload:
        return "ipp_request"
    return "unknown"


def suspicious_if_altered(packet) -> bool:
    payload_bytes = bytes(packet[Raw].load) if Raw in packet else b""
    # Check for actual control bytes (0x00-0x1F, except 0x09, 0x0A, 0x0D)
    for byte in payload_bytes:
        if byte < 32 and byte not in [9, 10, 13]:  # Not TAB, LF, CR
            return True
    return False


def detect_alerts(packets: Iterable, allowlist: Optional[set] = None) -> List[Dict]:
    allowlist = allowlist or set()
    alerts: List[Dict] = []
    source_activity: Dict[str, List[Dict]] = defaultdict(list)

    for packet in packets:
        if not is_cups_packet(packet):
            continue

        ip = packet[IP]
        udp = packet[UDP]
        payload = decode_payload(packet)
        payload_lower = payload.lower()
        src_ip = ip.src
        dst_ip = ip.dst

        if src_ip in allowlist:
            continue

        if "printer-uri" in payload_lower or "printer-name" in payload_lower:
            if not any(item in payload_lower for item in ["ipp://", "cups:"]):
                alerts.append(
                    {
                        "type": "unauthorized_printer_advertisement",
                        "severity": "high",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": udp.dport,
                        "summary": f"Printer metadata advertised by {src_ip} but without a valid CUPS URI.",
                        "evidence": payload[:200],
                    }
                )
            else:
                alerts.append(
                    {
                        "type": "printer_advertisement",
                        "severity": "medium",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": udp.dport,
                        "summary": f"Printer metadata seen from {src_ip} with discovery fields.",
                        "evidence": payload[:200],
                    }
                )

        if "ipp/" in payload_lower or "cups-get-printers" in payload_lower:
            alerts.append(
                {
                    "type": "suspicious_ipp_connection",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": udp.dport,
                    "summary": f"IPP/CUPS request observed between {src_ip} and {dst_ip}.",
                    "evidence": payload[:200],
                }
            )

        if suspicious_if_altered(packet):
            alerts.append(
                {
                    "type": "malformed_protocol_field",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": udp.dport,
                    "summary": "Unexpected control bytes or malformed protocol metadata detected.",
                    "evidence": payload[:200],
                }
            )

        source_activity[src_ip].append(
            {
                "device_class": infer_device_class(packet),
                "dst_ip": dst_ip,
                "payload_preview": payload[:80],
            }
        )

    for src_ip, records in source_activity.items():
        if len(records) >= 3:
            alerts.append(
                {
                    "type": "repeated_discovery_activity",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_ip": "multiple",
                    "port": 631,
                    "summary": f"{src_ip} generated {len(records)} CUPS discovery messages in a short sequence.",
                    "evidence": records[-1]["payload_preview"],
                }
            )

    deduped = []
    seen = set()
    for alert in alerts:
        key = (alert["type"], alert["src_ip"], alert["dst_ip"], alert["summary"])
        if key not in seen:
            seen.add(key)
            deduped.append(alert)
    return deduped


def analyze_pcap(pcap_path: str, allowlist: Optional[str] = None, threshold: int = 3) -> List[Dict]:
    allowlist_set = {item.strip() for item in (allowlist or "").split(",") if item.strip()}
    packets = rdpcap(pcap_path)
    return detect_alerts(packets, allowlist=allowlist_set)


def live_monitor(interface: str, allowlist: Optional[str] = None, timeout: int = 30, store: bool = False) -> List[Dict]:
    allowlist_set = {item.strip() for item in (allowlist or "").split(",") if item.strip()}
    observed_packets = []

    def handle_packet(packet):
        if is_cups_packet(packet):
            observed_packets.append(packet)
        return True

    sniff(iface=interface, filter="udp port 631", prn=handle_packet, store=store, timeout=timeout)
    return detect_alerts(observed_packets, allowlist=allowlist_set)


def export_csv(alerts: List[Dict], path: str) -> None:
    fieldnames = ["type", "severity", "src_ip", "dst_ip", "port", "summary", "evidence"]
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    with open(path_obj, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow({k: alert.get(k, "") for k in fieldnames})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect suspicious CUPS printer-discovery traffic.")
    parser.add_argument("--pcap", help="Offline PCAP file to analyse.")
    parser.add_argument("--interface", default="lo", help="Live network interface to monitor (for example eth0 or lo).")
    parser.add_argument("--live", action="store_true", help="Monitor live traffic on the specified interface.")
    parser.add_argument("--timeout", type=int, default=30, help="Live capture timeout in seconds.")
    parser.add_argument("--allowlist", default="", help="Comma-separated list of trusted printer IP addresses.")
    parser.add_argument("--output-json", default=None, help="Where to export detection results as JSON.")
    parser.add_argument("--output-csv", default=None, help="Where to export detection results as CSV.")
    parser.add_argument("--threshold", type=int, default=3, help="Repeated-discovery threshold.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.live:
        alerts = live_monitor(args.interface, allowlist=args.allowlist, timeout=args.timeout)
    elif args.pcap:
        alerts = analyze_pcap(args.pcap, allowlist=args.allowlist, threshold=args.threshold)
    else:
        print("Either --live or --pcap is required.", file=sys.stderr)
        sys.exit(2)

    if not alerts:
        print("No suspicious CUPS activity detected.")
    else:
        print(f"Detected {len(alerts)} suspicious events:")
        for alert in alerts:
            print(f"- [{alert['severity']}] {alert['type']} from {alert['src_ip']} -> {alert['dst_ip']} : {alert['summary']}")

    if args.output_json:
        out = Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=2)

    if args.output_csv:
        export_csv(alerts, args.output_csv)


if __name__ == "__main__":
    main()
