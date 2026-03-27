"""
rule_manager.py — Manages blocking / filtering rules.

C++ equivalents
---------------
- include/rule_manager.h  →  RuleManager class declaration
- src/rule_manager.cpp    →  IP / App / Domain / Port blocking + persistence

Rules can be:
  1. IP-based        — block specific source IPs.
  2. App-based       — block specific applications (detected via SNI).
  3. Domain-based    — block specific domains (supports ``*.example.com``).
  4. Port-based      — block specific destination ports.

Rule files use the same section-header format as the C++ version:
    [BLOCKED_IPS]
    192.168.1.50

    [BLOCKED_APPS]
    YouTube

    [BLOCKED_DOMAINS]
    *.facebook.com

    [BLOCKED_PORTS]
    8080
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .types import AppType, app_type_to_string, string_to_app_type


# ═══════════════════════════════════════════════════════════════════════
# Block Reason  (mirrors C++ RuleManager::BlockReason)
# ═══════════════════════════════════════════════════════════════════════

class BlockReasonType(Enum):
    IP     = "IP"
    APP    = "APP"
    DOMAIN = "DOMAIN"
    PORT   = "PORT"


@dataclass
class BlockReason:
    type:   BlockReasonType
    detail: str


# ═══════════════════════════════════════════════════════════════════════
# Rule Manager
# ═══════════════════════════════════════════════════════════════════════

class RuleManager:
    """
    Thread-safe in C++; in this single-threaded Python port we simply
    use plain Python sets.

    Provides block / unblock / check helpers for IPs, apps, domains
    (with wildcard support), and ports.
    """

    def __init__(self) -> None:
        self._blocked_ips:      set[str]     = set()   # normalised IP strings
        self._blocked_apps:     set[AppType] = set()
        self._blocked_domains:  set[str]     = set()   # exact domains
        self._domain_patterns:  list[str]    = []       # wildcard patterns like "*.facebook.com"
        self._blocked_ports:    set[int]     = set()

    # ── IP Blocking ─────────────────────────────────────────────────

    def block_ip(self, ip: str) -> None:
        """Block a source IP address."""
        normalised = str(ipaddress.ip_address(ip))
        self._blocked_ips.add(normalised)
        print(f"[RuleManager] Blocked IP: {normalised}")

    def unblock_ip(self, ip: str) -> None:
        normalised = str(ipaddress.ip_address(ip))
        self._blocked_ips.discard(normalised)
        print(f"[RuleManager] Unblocked IP: {normalised}")

    def is_ip_blocked(self, ip: str) -> bool:
        try:
            return str(ipaddress.ip_address(ip)) in self._blocked_ips
        except ValueError:
            return False

    def get_blocked_ips(self) -> list[str]:
        return sorted(self._blocked_ips)

    # ── Application Blocking ───────────────────────────────────────

    def block_app(self, app: AppType) -> None:
        self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def block_app_by_name(self, name: str) -> None:
        """Block an app using its display name (e.g. 'YouTube')."""
        app = string_to_app_type(name)
        if app is not None:
            self.block_app(app)
        else:
            print(f"[RuleManager] Unknown app: {name}")

    def unblock_app(self, app: AppType) -> None:
        self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        return app in self._blocked_apps

    def get_blocked_apps(self) -> list[AppType]:
        return list(self._blocked_apps)

    # ── Domain Blocking ────────────────────────────────────────────

    def block_domain(self, domain: str) -> None:
        """
        Block a domain.  Supports wildcard patterns like ``*.facebook.com``.
        """
        if "*" in domain:
            self._domain_patterns.append(domain)
        else:
            self._blocked_domains.add(domain.lower())
        print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        if "*" in domain:
            try:
                self._domain_patterns.remove(domain)
            except ValueError:
                pass
        else:
            self._blocked_domains.discard(domain.lower())
        print(f"[RuleManager] Unblocked domain: {domain}")

    def is_domain_blocked(self, domain: str) -> bool:
        lower = domain.lower()

        # Exact match
        if lower in self._blocked_domains:
            return True

        # Wildcard patterns
        for pattern in self._domain_patterns:
            if self._domain_matches_pattern(lower, pattern.lower()):
                return True

        return False

    def get_blocked_domains(self) -> list[str]:
        return sorted(self._blocked_domains) + list(self._domain_patterns)

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """
        Check if *domain* matches *pattern*.

        Supports ``*.example.com`` — matches ``foo.example.com`` and
        also the bare ``example.com`` (same logic as C++
        ``RuleManager::domainMatchesPattern``).
        """
        if len(pattern) >= 2 and pattern[0] == "*" and pattern[1] == ".":
            suffix = pattern[1:]           # ".example.com"
            bare   = pattern[2:]           # "example.com"

            if domain.endswith(suffix):
                return True
            if domain == bare:
                return True

        return False

    # ── Port Blocking ──────────────────────────────────────────────

    def block_port(self, port: int) -> None:
        self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        return port in self._blocked_ports

    # ── Combined Check ─────────────────────────────────────────────

    def should_block(
        self,
        src_ip:   str,
        dst_port: int,
        app:      AppType,
        domain:   str,
    ) -> Optional[BlockReason]:
        """
        Check all rules and return a :class:`BlockReason` if the
        packet/connection should be blocked, or ``None`` if allowed.

        Evaluation order matches the C++ version:
        IP → Port → App → Domain.
        """
        if self.is_ip_blocked(src_ip):
            return BlockReason(BlockReasonType.IP, src_ip)

        if self.is_port_blocked(dst_port):
            return BlockReason(BlockReasonType.PORT, str(dst_port))

        if self.is_app_blocked(app):
            return BlockReason(BlockReasonType.APP, app_type_to_string(app))

        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReasonType.DOMAIN, domain)

        return None

    # ── Persistence ────────────────────────────────────────────────

    def save_rules(self, filename: str) -> bool:
        """Save all rules to a file (same format as C++)."""
        try:
            with open(filename, "w") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(f"{ip}\n")

                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(f"{app_type_to_string(app)}\n")

                f.write("\n[BLOCKED_DOMAINS]\n")
                for dom in self.get_blocked_domains():
                    f.write(f"{dom}\n")

                f.write("\n[BLOCKED_PORTS]\n")
                for port in sorted(self._blocked_ports):
                    f.write(f"{port}\n")

            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError as e:
            print(f"[RuleManager] Error saving rules: {e}")
            return False

    def load_rules(self, filename: str) -> bool:
        """Load rules from a file (same section-header format as C++)."""
        path = Path(filename)
        if not path.exists():
            print(f"[RuleManager] Rules file not found: {filename}")
            return False

        try:
            current_section = ""
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue

                if line.startswith("["):
                    current_section = line
                    continue

                if current_section == "[BLOCKED_IPS]":
                    self.block_ip(line)
                elif current_section == "[BLOCKED_APPS]":
                    self.block_app_by_name(line)
                elif current_section == "[BLOCKED_DOMAINS]":
                    self.block_domain(line)
                elif current_section == "[BLOCKED_PORTS]":
                    self.block_port(int(line))

            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except Exception as e:
            print(f"[RuleManager] Error loading rules: {e}")
            return False

    def clear_all(self) -> None:
        """Remove every rule."""
        self._blocked_ips.clear()
        self._blocked_apps.clear()
        self._blocked_domains.clear()
        self._domain_patterns.clear()
        self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    # ── Statistics ─────────────────────────────────────────────────

    @dataclass
    class RuleStats:
        blocked_ips:     int
        blocked_apps:    int
        blocked_domains: int
        blocked_ports:   int

    def get_stats(self) -> RuleStats:
        return self.RuleStats(
            blocked_ips=len(self._blocked_ips),
            blocked_apps=len(self._blocked_apps),
            blocked_domains=len(self._blocked_domains) + len(self._domain_patterns),
            blocked_ports=len(self._blocked_ports),
        )
