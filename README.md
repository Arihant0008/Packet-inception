# Deep Packet Inspection (DPI) Engine

A Python-based Deep Packet Inspection system that reads network traffic from PCAP files, identifies applications by inspecting packet payloads (TLS SNI, HTTP Headers, DNS queries), applies blocking rules, and outputs a filtered PCAP.

---

## 📖 Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [How SNI Extraction Works](#6-how-sni-extraction-works)
7. [How Blocking Works](#7-how-blocking-works)
8. [Setup and Running](#8-setup-and-running)
9. [Understanding the Output](#9-understanding-the-output)
10. [Extending the Project](#10-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```text
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### A Packet's Structure

Every network packet is like a **Russian nesting doll** — headers wrapped inside headers:

```text
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:
1. **Source IP** (e.g., 192.168.1.100)
2. **Destination IP** (e.g., 142.250.185.206)
3. **Source Port** (e.g., 54321)
4. **Destination Port** (e.g., 443 — HTTPS)
5. **Protocol** (e.g., TCP or UDP)

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection.
- If we block one packet of a connection, we must block all of them. This is how we track stateful flows.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:
1. Your browser sends a "Client Hello" message.
2. This message includes the domain name in **plaintext** (not encrypted yet!).
3. The server uses this to know which certificate to send.

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

This project was originally written in C++ and ported to Python for readability and rapid prototyping. It uses **Scapy** to read and write PCAP files, but performs **manual byte-level payload extraction** for TLS, HTTP, and DNS to mimic exactly how a production DPI engine operates.

---

## 4. File Structure

```text
Packet_analyzer/
├── dpi_python/                  # Core Python Package
│   ├── __init__.py
│   ├── __main__.py              # Allows `python -m dpi_python`
│   ├── main.py                  # CLI entry point (argparse)
│   ├── dpi_engine.py            # Main orchestrator (reads PCAP, applies logic)
│   ├── connection_tracker.py    # Tracks 5-tuple flows and TCP state
│   ├── protocol_inspector.py    # Manual TLS SNI, HTTP Host, DNS parsing
│   ├── rule_manager.py          # IP/App/Domain/Port blocking logic
│   ├── types.py                 # Core enums and dataclasses (AppType, FiveTuple)
│   └── requirements.txt         # Dependencies (scapy)
│
├── generate_test_pcap.py        # Script to generate synthetic PCAP traffic
├── test_dpi.pcap                # Included test capture
├── PROJECT_WORKFLOW.md          # Visual architecture and data flow
├── INTERVIEW_QUESTIONS.md       # Q&A for viva and technical interviews
├── HOW_TO_EXPLAIN.md            # Script and tips for presenting the project
└── README.md                    # This file!
```

---

## 5. The Journey of a Packet

Here is how a packet moves through the `dpi_python` engine:

1. **Read PCAP** (`dpi_engine.py`): Scapy's `rdpcap()` reads all packets.
2. **Extract Headers**: Extracts Ethernet, IP, and TCP/UDP headers to build a `FiveTuple`.
3. **Track Connection** (`connection_tracker.py`): Looks up the `FiveTuple` (and its reverse) in a flow dictionary. Updates TCP state (SYN → SYN-ACK → ESTABLISHED).
4. **Deep Packet Inspection** (`protocol_inspector.py`):
   - If Port 443 → Manually parse TLS Client Hello to extract SNI constraint.
   - If Port 80 → Parse HTTP headers for `Host:`.
   - If Port 53 → Parse DNS wire format.
5. **Rule Checking** (`rule_manager.py`): Checks if the flow's IP, App Type, Domain, or Port match any blocking rules.
6. **Action**:
   - If **FORWARD**: Add packet to output list.
   - If **DROP**: Skip packet and mark the entire flow as blocked.
7. **Write PCAP**: Scapy's `wrpcap()` writes all forwarded packets to a new file.

---

## 6. How SNI Extraction Works

We manually extract the SNI from the TLS Client Hello inside `protocol_inspector.py`.

```text
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
... skip lengths, random, session ID, cipher suites ...

-- Extensions --
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

The algorithm walks this binary structure byte-by-byte, carefully skipping variable-length fields until it finds extension `0x0000`, returning the decoded string.

---

## 7. How Blocking Works

Rules are checked in order from fastest/broadest to slowest/specific:
1. **IP Rules** (e.g., `192.168.1.50`)
2. **Port Rules** (e.g., `8080`)
3. **App Rules** (e.g., `YouTube`, `TikTok`)
4. **Domain Rules** (e.g., `*.facebook.com`)

### Flow-Based Blocking
We block at the **flow** level, not the packet level.
```text
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```
Once the Client Hello identifies the application, the `connection_tracker` remembers the blocked state, dropping all future packets for that 5-tuple immediately.

---

## 8. Setup and Running

### Prerequisites
- Python 3.8+

### Installation
```bash
pip install -r dpi_python/requirements.txt
```

### Basic Usage
Run the engine on the provided test PCAP:
```bash
python -m dpi_python.main test_dpi.pcap output.pcap
```

### Applying Blocking Rules
```bash
# Block an IP and a specific application
python -m dpi_python.main test_dpi.pcap output.pcap \
    --block-ip 192.168.1.50 \
    --block-app YouTube \
    --verbose
```

### Domain Wildcard Blocking
```bash
python -m dpi_python.main test_dpi.pcap output.pcap \
    --block-domain "*.facebook.com"
```

### Loading Rules from a File
Create a `rules.txt` file:
```text
[BLOCKED_APPS]
YouTube
Netflix

[BLOCKED_DOMAINS]
*.tiktok.com
```
Then run:
```bash
python -m dpi_python.main test_dpi.pcap output.pcap --rules rules.txt
```

### Generating New Test Data
```bash
python generate_test_pcap.py
```

---

## 9. Understanding the Output

Upon completion, you will see a processing report:

```text
╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                      ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                             ║
║ Total Bytes:              5738                             ║
║ TCP Packets:                73                             ║
║ UDP Packets:                 4                             ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                  76                             ║
║ Dropped:                     1                             ║
║ Active Flows:               23                             ║
║ Drop Rate:                1.30%                            ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                 16  20.8% ####                  ║
║ DNS                   13  16.9% ###                   ║
║ Facebook               4   5.2% #                     ║
║ YouTube                4   5.2% #                     ║
╚══════════════════════════════════════════════════════════════╝

[Detected Applications/Domains]
  - api.twitter.com -> DNS
  - discord.com -> Discord
  - github.com -> GitHub
  - www.youtube.com -> DNS
  ...
```

- **Forwarded**: Packets written to the output file.
- **Dropped**: Packets blocked by rules.
- **Application Breakdown**: Traffic categorization based on deep packet inspection.

---

## 10. Extending the Project

Here are ideas for further improvement:

1. **IP Fragment Reassembly**: Currently, if a TLS Client Hello spans multiple fragmented IP packets, the SNI goes undetected. Adding reassembly logic would fix this.
2. **QUIC Support**: QUIC runs on UDP 443. Detecting the QUIC Initial packet and extracting its SNI would cover modern Google/YouTube traffic.
3. **Encrypted Client Hello (ECH)**: Detect when TLS 1.3 traffic uses ECH (where the SNI is hidden) and optionally block or flag it.
4. **Live Capture**: Replace Scapy's `rdpcap()` with `sniff()` to inspect and potentially drop packets directly from a live network interface. 
