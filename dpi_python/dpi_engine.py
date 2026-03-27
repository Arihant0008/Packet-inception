"""
dpi_engine.py — Main DPI Engine orchestrator.

C++ equivalents
---------------
- include/dpi_engine.h  →  DPIEngine class
- src/dpi_engine.cpp    →  processFile(), readerThreadFunc(), handleOutput()
- src/main_working.cpp  →  Single-threaded DPI processing loop (primary reference)

This module ties together PCAP reading (via Scapy), protocol inspection,
connection tracking, rule matching, and PCAP writing.
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

# Scapy imports — suppress the interactive startup banner
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import rdpcap, wrpcap, raw  # type: ignore
from scapy.layers.inet import IP, TCP, UDP  # type: ignore
from scapy.packet import Packet as ScapyPacket  # type: ignore

from .types import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
    app_type_to_string,
    sni_to_app_type,
)
from .connection_tracker import ConnectionTracker
from .protocol_inspector import (
    extract_dns_query,
    extract_http_host,
    extract_tls_sni,
)
from .rule_manager import RuleManager


# ═══════════════════════════════════════════════════════════════════════
# Statistics  (mirrors C++ DPIStats)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class DPIStats:
    total_packets:     int = 0
    total_bytes:       int = 0
    forwarded_packets: int = 0
    dropped_packets:   int = 0
    tcp_packets:       int = 0
    udp_packets:       int = 0
    other_packets:     int = 0
    app_counts:        Counter = field(default_factory=Counter)
    detected_snis:     dict = field(default_factory=dict)  # sni → AppType


# ═══════════════════════════════════════════════════════════════════════
# DPI Engine
# ═══════════════════════════════════════════════════════════════════════

class DPIEngine:
    """
    Main Deep Packet Inspection engine.

    Usage::

        engine = DPIEngine(verbose=True)
        engine.block_app("YouTube")
        engine.block_ip("192.168.1.50")
        engine.process_file("input.pcap", "output_filtered.pcap")
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.rule_manager = RuleManager()
        self.conn_tracker = ConnectionTracker()
        self.stats = DPIStats()

    # ── Convenience wrappers for rule management ───────────────────

    def block_ip(self, ip: str) -> None:
        self.rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        self.rule_manager.unblock_ip(ip)

    def block_app(self, app_name: str) -> None:
        self.rule_manager.block_app_by_name(app_name)

    def unblock_app(self, app_name: str) -> None:
        from .types import string_to_app_type
        app = string_to_app_type(app_name)
        if app is not None:
            self.rule_manager.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        self.rule_manager.block_domain(domain)

    def unblock_domain(self, domain: str) -> None:
        self.rule_manager.unblock_domain(domain)

    def load_rules(self, filename: str) -> bool:
        return self.rule_manager.load_rules(filename)

    def save_rules(self, filename: str) -> bool:
        return self.rule_manager.save_rules(filename)

    # ── Main Processing Loop ──────────────────────────────────────

    def process_file(self, input_file: str, output_file: str) -> bool:
        """
        Read *input_file* (PCAP), apply DPI rules, write forwarded
        packets to *output_file* (PCAP).

        Returns True on success.
        """
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0 (Python)                  ║")
        print("║               Deep Packet Inspection System                  ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()
        print(f"[DPIEngine] Processing: {input_file}")
        print(f"[DPIEngine] Output to:  {output_file}")
        print()

        # ── Read packets ──
        try:
            packets = rdpcap(input_file)
        except Exception as e:
            print(f"[DPIEngine] Error reading input file: {e}", file=sys.stderr)
            return False

        print(f"[DPIEngine] Loaded {len(packets)} packets from PCAP")

        forwarded_packets: list[ScapyPacket] = []

        # ── Process each packet ──
        for pkt in packets:
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw(pkt))

            # We only inspect IP packets with TCP or UDP
            if not pkt.haslayer(IP):
                # Forward non-IP packets without inspection
                forwarded_packets.append(pkt)
                self.stats.forwarded_packets += 1
                self.stats.other_packets += 1
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto  # 6=TCP, 17=UDP

            has_tcp = pkt.haslayer(TCP)
            has_udp = pkt.haslayer(UDP)

            if not has_tcp and not has_udp:
                forwarded_packets.append(pkt)
                self.stats.forwarded_packets += 1
                self.stats.other_packets += 1
                continue

            # Determine ports
            if has_tcp:
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = int(tcp_layer.flags)
                self.stats.tcp_packets += 1
            else:
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                tcp_flags = 0
                self.stats.udp_packets += 1

            # ── Build five-tuple & get/create flow ──
            ft = FiveTuple(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=protocol,
            )
            conn = self.conn_tracker.get_or_create(ft)
            self.conn_tracker.update(conn, len(raw(pkt)), is_outbound=True)

            # ── TCP state tracking ──
            if has_tcp:
                self.conn_tracker.update_tcp_state(conn, tcp_flags)

            # ── If already blocked, drop immediately ──
            if conn.state == ConnectionState.BLOCKED:
                self.stats.dropped_packets += 1
                self.stats.app_counts[conn.app_type] += 1
                if conn.sni:
                    self.stats.detected_snis[conn.sni] = conn.app_type
                continue

            # ── Payload inspection (classification) ──
            if conn.state != ConnectionState.CLASSIFIED:
                payload = self._extract_payload(pkt, has_tcp)
                if payload:
                    self._inspect_payload(payload, ft, conn)

            # ── Update app stats ──
            self.stats.app_counts[conn.app_type] += 1
            if conn.sni:
                self.stats.detected_snis[conn.sni] = conn.app_type

            # ── Check blocking rules ──
            action = self._check_rules(ft, conn)
            if action == PacketAction.DROP:
                self.stats.dropped_packets += 1
                if self.verbose:
                    print(
                        f"[BLOCKED] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                        f" ({app_type_to_string(conn.app_type)}"
                        f"{': ' + conn.sni if conn.sni else ''})"
                    )
                continue

            # ── Forward ──
            forwarded_packets.append(pkt)
            self.stats.forwarded_packets += 1

        # ── Write output PCAP ──
        try:
            wrpcap(output_file, forwarded_packets)
        except Exception as e:
            print(f"[DPIEngine] Error writing output file: {e}", file=sys.stderr)
            return False

        # ── Print report ──
        print(self.generate_report())

        return True

    # ── Payload Extraction ─────────────────────────────────────────

    @staticmethod
    def _extract_payload(pkt: ScapyPacket, has_tcp: bool) -> Optional[bytes]:
        """
        Get the application-layer payload bytes from a Scapy packet.

        For TCP this is the data after the TCP header; for UDP it is
        the data after the UDP header.
        """
        try:
            if has_tcp:
                tcp_layer = pkt[TCP]
                payload = bytes(tcp_layer.payload)
            else:
                udp_layer = pkt[UDP]
                payload = bytes(udp_layer.payload)
            return payload if payload else None
        except Exception:
            return None

    # ── Payload Inspection ─────────────────────────────────────────

    def _inspect_payload(
        self,
        payload: bytes,
        ft: FiveTuple,
        conn: Connection,
    ) -> None:
        """
        Attempt to classify a connection by inspecting its payload.
        Precedence: TLS SNI → HTTP Host → DNS query → port fallback.
        """
        # ── TLS SNI (HTTPS, port 443) ──
        if ft.dst_port == 443 and len(payload) > 5:
            sni = extract_tls_sni(payload)
            if sni:
                app = sni_to_app_type(sni)
                self.conn_tracker.classify(conn, app, sni)
                return

        # ── HTTP Host (port 80) ──
        if ft.dst_port == 80 and len(payload) > 10:
            host = extract_http_host(payload)
            if host:
                app = sni_to_app_type(host)
                self.conn_tracker.classify(conn, app, host)
                return

        # ── DNS (port 53) ──
        if ft.dst_port == 53 or ft.src_port == 53:
            domain = extract_dns_query(payload)
            if domain:
                self.conn_tracker.classify(conn, AppType.DNS, domain)
                return
            # Even without a parseable query, port 53 → DNS
            self.conn_tracker.classify(conn, AppType.DNS, "")
            return

        # ── Port-based fallback (don't mark as classified — SNI may come later) ──
        if conn.app_type == AppType.UNKNOWN:
            if ft.dst_port == 443:
                conn.app_type = AppType.HTTPS
            elif ft.dst_port == 80:
                conn.app_type = AppType.HTTP

    # ── Rule Checking ──────────────────────────────────────────────

    def _check_rules(self, ft: FiveTuple, conn: Connection) -> PacketAction:
        """Evaluate all blocking rules against this connection."""
        reason = self.rule_manager.should_block(
            src_ip=ft.src_ip,
            dst_port=ft.dst_port,
            app=conn.app_type,
            domain=conn.sni,
        )

        if reason is not None:
            self.conn_tracker.block(conn)
            return PacketAction.DROP

        return PacketAction.FORWARD

    # ── Report Generation ──────────────────────────────────────────

    def generate_report(self) -> str:
        """
        Produce a formatted statistics report (matches the C++ output
        style).
        """
        s = self.stats
        lines: list[str] = []
        a = lines.append

        a("")
        a("╔══════════════════════════════════════════════════════════════╗")
        a("║                      PROCESSING REPORT                      ║")
        a("╠══════════════════════════════════════════════════════════════╣")
        a(f"║ Total Packets:      {s.total_packets:>10}                             ║")
        a(f"║ Total Bytes:        {s.total_bytes:>10}                             ║")
        a(f"║ TCP Packets:        {s.tcp_packets:>10}                             ║")
        a(f"║ UDP Packets:        {s.udp_packets:>10}                             ║")
        a("╠══════════════════════════════════════════════════════════════╣")
        a(f"║ Forwarded:          {s.forwarded_packets:>10}                             ║")
        a(f"║ Dropped:            {s.dropped_packets:>10}                             ║")
        a(f"║ Active Flows:       {self.conn_tracker.active_count:>10}                             ║")

        if s.total_packets > 0:
            drop_rate = 100.0 * s.dropped_packets / s.total_packets
            a(f"║ Drop Rate:           {drop_rate:>9.2f}%                             ║")

        a("╠══════════════════════════════════════════════════════════════╣")
        a("║                    APPLICATION BREAKDOWN                     ║")
        a("╠══════════════════════════════════════════════════════════════╣")

        # Sort apps by packet count (descending)
        sorted_apps = s.app_counts.most_common()
        for app, count in sorted_apps:
            pct = 100.0 * count / s.total_packets if s.total_packets else 0
            bar_len = int(pct / 5)
            bar = "#" * bar_len
            name = app_type_to_string(app)
            a(f"║ {name:<15}{count:>8} {pct:>5.1f}% {bar:<20}  ║")

        a("╚══════════════════════════════════════════════════════════════╝")

        # Detected SNIs / domains
        if s.detected_snis:
            a("")
            a("[Detected Applications/Domains]")
            for sni, app in sorted(s.detected_snis.items()):
                a(f"  - {sni} -> {app_type_to_string(app)}")

        # Blocking rules summary
        rule_stats = self.rule_manager.get_stats()
        if any([rule_stats.blocked_ips, rule_stats.blocked_apps,
                rule_stats.blocked_domains, rule_stats.blocked_ports]):
            a("")
            a("[Active Blocking Rules]")
            if rule_stats.blocked_ips:
                a(f"  Blocked IPs:     {rule_stats.blocked_ips}")
            if rule_stats.blocked_apps:
                a(f"  Blocked Apps:    {rule_stats.blocked_apps}")
            if rule_stats.blocked_domains:
                a(f"  Blocked Domains: {rule_stats.blocked_domains}")
            if rule_stats.blocked_ports:
                a(f"  Blocked Ports:   {rule_stats.blocked_ports}")

        return "\n".join(lines)
