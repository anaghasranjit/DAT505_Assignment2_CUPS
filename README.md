# CUPS Printer Discovery Security Lab

This repository contains an ethical-hacking lab focused on the 2024 CUPS
printer-discovery vulnerabilities (CVE-2024-47176, CVE-2024-47076,
CVE-2024-47175). It demonstrates and detects insecure printer discovery
behavior in an isolated environment.

**Assignment:** DAT505 — CUPS Printer Discovery Exploitation and Attack
Detection Using Scapy

## Lab Design

- **Attacker:** Kali Linux VM, Python 3, Scapy, tcpdump
- **Victim:** vulnerable CUPS Docker image (vulhub/cups-browsed:2.0.1)
- **Virtual Printer:** software-based IPP server simulator
- **Network:** Docker bridge network (containers communicate over the
  local Docker network; attacker host and victim container are on the
  same subnet)

## Files

- `cups_attack.py` — sends forged CUPS discovery packets
- `cups_detector.py` — detects suspicious discovery traffic
- `requirements.txt` — Python dependencies (scapy)
- `pcap_files/` — packet captures (normal, unauthorized, malformed, probe,
  before/after mitigation)
- `evidence/` — logs, JSON/CSV results, screenshots

## Setup

### 1) Install Dependencies

```bash
python3 -m pip install -r requirements.txt
```

This installs Scapy, the only runtime dependency. Python 3.8+ is required.

### 2) Build Vulnerable CUPS Environment

```bash
git clone --depth 1 https://github.com/vulhub/vulhub.git /tmp/vulhub
cd /tmp/vulhub/base/cups-browsed/2.0.1
docker build -t vulhub/cups-browsed:2.0.1 .

docker run -d --name cups-victim -p 631:631 vulhub/cups-browsed:2.0.1

# Note the container IP for the commands below
docker inspect cups-victim | grep IPAddress
```

### 3) Generate Lab Artifacts

```bash
# Unauthorized discovery advertisement
python3 cups_attack.py \
  --target <CONTAINER_IP> \
  --printer-name EvilPrinter \
  --printer-uri ipp://<CONTAINER_IP>:631/printers/EvilPrinter \
  --count 5 --interval 1 \
  --pcap pcap_files/unauthorized_discovery.pcap \
  --json-output evidence/attack_summary.json

# Detect the attack traffic
python3 cups_detector.py \
  --pcap pcap_files/unauthorized_discovery.pcap \
  --output-json evidence/unauthorized_alerts.json \
  --output-csv evidence/unauthorized_alerts.csv
```

## Tool Features

### cups_attack.py

- Craft and send custom CUPS discovery packets
- Advertise attacker-controlled virtual printers
- Three payload types: `advertise`, `probe`, `malformed`
- Configurable target, source and ports
- PCAP export and JSON logging

### cups_detector.py

- Offline PCAP analysis and live monitoring
- Four detection rules (unauthorized advertisement, suspicious IPP
  connection, repeated discovery, malformed fields)
- CSV and JSON alert export
- Source allowlisting support

## Experiments Performed

1. **Normal traffic** — baseline capture; legitimate traffic produces no
   alerts when allowlisted.
2. **Unauthorized discovery** — forged advertisement sent to the victim;
   detected by the detector.
3. **Packet manipulation** — malformed and probe variants tested and
   detected.
4. **Detection validation** — normal + attack traffic analyzed; results
   recorded in `evidence/`.

## Security Mitigations

1. **Restrict UDP port 631** to trusted printer hosts (implemented)
2. **Disable cups-browsed** remote discovery (implemented)
3. **Allowlist printer addresses** (recommended)
4. **Patch CUPS** to the latest release (recommended)
5. **Segment printers** from end-user networks (recommended)

## Ethical Use

This lab is run inside an isolated Docker environment only. No third-party
or public systems are targeted; the experiments use simulated printers and
controlled advertisements.