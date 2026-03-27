"""
types.py — Enumerations, dataclasses, and app-classification helpers.

C++ equivalents
---------------
- include/types.h  → AppType enum, FiveTuple, Connection, PacketAction, …
- src/types.cpp     → appTypeToString(), sniToAppType()

This module is imported by every other module in the package.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# Application Classification  (mirrors C++ AppType enum)
# ═══════════════════════════════════════════════════════════════════════

class AppType(enum.Enum):
    """
    Identifies the application / service that a connection belongs to.
    Detected via TLS SNI, HTTP Host header, or DNS query name.
    """
    UNKNOWN    = 0
    HTTP       = 1
    HTTPS      = 2
    DNS        = 3
    TLS        = 4
    QUIC       = 5
    # ── Specific applications (detected via SNI / domain) ──
    GOOGLE     = 6
    FACEBOOK   = 7
    YOUTUBE    = 8
    TWITTER    = 9
    INSTAGRAM  = 10
    NETFLIX    = 11
    AMAZON     = 12
    MICROSOFT  = 13
    APPLE      = 14
    WHATSAPP   = 15
    TELEGRAM   = 16
    TIKTOK     = 17
    SPOTIFY    = 18
    ZOOM       = 19
    DISCORD    = 20
    GITHUB     = 21
    CLOUDFLARE = 22


# Human-readable names (same strings as C++ appTypeToString).
_APP_NAMES: dict[AppType, str] = {
    AppType.UNKNOWN:    "Unknown",
    AppType.HTTP:       "HTTP",
    AppType.HTTPS:      "HTTPS",
    AppType.DNS:        "DNS",
    AppType.TLS:        "TLS",
    AppType.QUIC:       "QUIC",
    AppType.GOOGLE:     "Google",
    AppType.FACEBOOK:   "Facebook",
    AppType.YOUTUBE:    "YouTube",
    AppType.TWITTER:    "Twitter/X",
    AppType.INSTAGRAM:  "Instagram",
    AppType.NETFLIX:    "Netflix",
    AppType.AMAZON:     "Amazon",
    AppType.MICROSOFT:  "Microsoft",
    AppType.APPLE:      "Apple",
    AppType.WHATSAPP:   "WhatsApp",
    AppType.TELEGRAM:   "Telegram",
    AppType.TIKTOK:     "TikTok",
    AppType.SPOTIFY:    "Spotify",
    AppType.ZOOM:       "Zoom",
    AppType.DISCORD:    "Discord",
    AppType.GITHUB:     "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}

# Reverse map: name → AppType (case-insensitive lookup used by CLI)
_NAME_TO_APP: dict[str, AppType] = {
    name: app for app, name in _APP_NAMES.items()
}


def app_type_to_string(app: AppType) -> str:
    """Return human-readable name for an AppType."""
    return _APP_NAMES.get(app, "Unknown")


def string_to_app_type(name: str) -> Optional[AppType]:
    """Convert a display name (e.g. 'YouTube') back to an AppType.
    Returns None if the name is not recognised."""
    return _NAME_TO_APP.get(name)


def sni_to_app_type(sni: str) -> AppType:
    """
    Map an SNI / domain string to the most specific AppType.

    This mirrors the substring-matching logic in C++ sniToAppType()
    (src/types.cpp).  The order matters: more specific patterns
    (e.g. YouTube) are checked before their parent (Google).
    """
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    # ── YouTube (before Google, since YouTube domains contain 'google') ──
    if any(kw in lower for kw in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    # ── Google ──
    if any(kw in lower for kw in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # ── Instagram (before Facebook, since Instagram is Meta) ──
    if any(kw in lower for kw in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # ── WhatsApp (before Facebook, owned by Meta) ──
    if any(kw in lower for kw in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    # ── Facebook / Meta ──
    if any(kw in lower for kw in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    # ── Netflix  (must be checked BEFORE Twitter; "netflix.com" contains "t.co") ──
    if any(kw in lower for kw in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # ── Amazon ──
    if any(kw in lower for kw in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # ── Microsoft (must be checked BEFORE Twitter; "microsoft.com" contains "t.co") ──
    if any(kw in lower for kw in ("microsoft", "msn.com", "office", "azure",
                                   "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # ── Twitter / X ──
    #    "t.co" is checked as a domain: the SNI must be exactly "t.co" or
    #    end with ".t.co" to avoid false positives like "netflix.com".
    if any(kw in lower for kw in ("twitter", "twimg", "x.com")):
        return AppType.TWITTER
    if lower == "t.co" or lower.endswith(".t.co"):
        return AppType.TWITTER

    # ── Apple ──
    if any(kw in lower for kw in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # ── Telegram ──
    if any(kw in lower for kw in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # ── TikTok ──
    if any(kw in lower for kw in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # ── Spotify ──
    if any(kw in lower for kw in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # ── Zoom ──
    if "zoom" in lower:
        return AppType.ZOOM

    # ── Discord ──
    if any(kw in lower for kw in ("discord", "discordapp")):
        return AppType.DISCORD

    # ── GitHub ──
    if any(kw in lower for kw in ("github", "githubusercontent")):
        return AppType.GITHUB

    # ── Cloudflare ──
    if any(kw in lower for kw in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # If SNI is present but unrecognised → generic HTTPS
    return AppType.HTTPS


# ═══════════════════════════════════════════════════════════════════════
# Connection State  (mirrors C++ ConnectionState)
# ═══════════════════════════════════════════════════════════════════════

class ConnectionState(enum.Enum):
    NEW         = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLASSIFIED  = "CLASSIFIED"
    BLOCKED     = "BLOCKED"
    CLOSED      = "CLOSED"


# ═══════════════════════════════════════════════════════════════════════
# Packet Action  (mirrors C++ PacketAction)
# ═══════════════════════════════════════════════════════════════════════

class PacketAction(enum.Enum):
    FORWARD  = "FORWARD"
    DROP     = "DROP"
    INSPECT  = "INSPECT"
    LOG_ONLY = "LOG_ONLY"


# ═══════════════════════════════════════════════════════════════════════
# Five-Tuple  (mirrors C++ FiveTuple struct)
# ═══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FiveTuple:
    """
    Uniquely identifies a network flow: (src_ip, dst_ip, src_port, dst_port, protocol).
    Made *frozen* so it can be used as a dict key.
    """
    src_ip:   str          # e.g. "192.168.1.100"
    dst_ip:   str          # e.g. "142.250.185.206"
    src_port: int          # 0-65535
    dst_port: int          # 0-65535
    protocol: int          # 6 = TCP, 17 = UDP

    def reverse(self) -> FiveTuple:
        """Return the reverse tuple (for bidirectional flow matching)."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({proto})"


# ═══════════════════════════════════════════════════════════════════════
# Connection  (mirrors C++ Connection struct)
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class Connection:
    """
    Per-flow state tracked by the connection tracker.
    """
    tuple:      FiveTuple
    state:      ConnectionState = ConnectionState.NEW
    app_type:   AppType         = AppType.UNKNOWN
    sni:        str             = ""

    packets_in:  int = 0
    packets_out: int = 0
    bytes_in:    int = 0
    bytes_out:   int = 0

    action: PacketAction = PacketAction.FORWARD

    # TCP state flags
    syn_seen:     bool = False
    syn_ack_seen: bool = False
    fin_seen:     bool = False
