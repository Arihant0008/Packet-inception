"""
protocol_inspector.py — Deep-packet-inspection helpers for TLS, HTTP, and DNS.

C++ equivalents
---------------
- include/sni_extractor.h   →  SNIExtractor, HTTPHostExtractor, DNSExtractor
- src/sni_extractor.cpp     →  Full extraction implementations

This module works on *raw TCP/UDP payload bytes* and does NOT depend on
Scapy's dissectors — it mirrors the same byte-level parsing the C++ code
performs manually.
"""

from __future__ import annotations

import struct
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════
# TLS SNI Extraction  (mirrors C++ SNIExtractor)
# ═══════════════════════════════════════════════════════════════════════
#
# TLS Client Hello layout (simplified):
#
#   Record Layer (5 bytes):
#     [0]     Content Type   = 0x16 (Handshake)
#     [1-2]   TLS Version
#     [3-4]   Record Length
#
#   Handshake Header (4 bytes):
#     [0]     Handshake Type = 0x01 (Client Hello)
#     [1-3]   Length (24-bit)
#
#   Client Hello Body:
#     [0-1]   Client Version
#     [2-33]  Random          (32 bytes)
#     [34]    Session ID Length → skip
#     ...     Cipher Suites Length → skip
#     ...     Compression Methods → skip
#     ...     Extensions Length
#             Extensions …
#               SNI Extension (type 0x0000):
#                 [0-1] Extension Type = 0x0000
#                 [2-3] Extension Length
#                 [4-5] SNI List Length
#                 [6]   SNI Type = 0x00 (hostname)
#                 [7-8] SNI Length
#                 [9..]  SNI value  ← this is what we want!

_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_EXTENSION_SNI          = 0x0000
_SNI_TYPE_HOSTNAME      = 0x00


def _read_uint16_be(data: bytes, offset: int) -> int:
    """Read a big-endian 16-bit unsigned integer."""
    return (data[offset] << 8) | data[offset + 1]


def _read_uint24_be(data: bytes, offset: int) -> int:
    """Read a big-endian 24-bit unsigned integer."""
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    """
    Return True if *payload* looks like the start of a TLS Client Hello.
    Checks: content type, TLS version range, and handshake type.
    """
    if len(payload) < 9:
        return False

    # Content type must be Handshake (0x16)
    if payload[0] != _CONTENT_TYPE_HANDSHAKE:
        return False

    # TLS version 0x0300 .. 0x0304
    version = _read_uint16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False

    # Record length sanity
    record_length = _read_uint16_be(payload, 3)
    if record_length > len(payload) - 5:
        return False

    # Handshake type must be Client Hello (0x01)
    if payload[5] != _HANDSHAKE_CLIENT_HELLO:
        return False

    return True


def extract_tls_sni(payload: bytes) -> Optional[str]:
    """
    Extract the Server Name Indication (SNI) hostname from a TLS
    Client Hello message.

    *payload* should be the raw TCP payload (bytes starting right after
    the TCP header).

    Returns the hostname string, or None if this is not a TLS Client
    Hello or no SNI extension is found.
    """
    if not is_tls_client_hello(payload):
        return None

    length = len(payload)

    # Skip TLS record header (5 bytes)
    offset = 5

    # Handshake header: type(1) + length(3)
    # handshake_length = _read_uint24_be(payload, offset + 1)  # not needed
    offset += 4

    # Client Hello body:
    #   client_version (2) + random (32)
    offset += 2 + 32

    # Session ID
    if offset >= length:
        return None
    session_id_len = payload[offset]
    offset += 1 + session_id_len

    # Cipher Suites
    if offset + 2 > length:
        return None
    cipher_suites_len = _read_uint16_be(payload, offset)
    offset += 2 + cipher_suites_len

    # Compression Methods
    if offset >= length:
        return None
    comp_methods_len = payload[offset]
    offset += 1 + comp_methods_len

    # Extensions
    if offset + 2 > length:
        return None
    extensions_length = _read_uint16_be(payload, offset)
    offset += 2

    extensions_end = min(offset + extensions_length, length)

    # Walk extensions looking for SNI (type 0x0000)
    while offset + 4 <= extensions_end:
        ext_type = _read_uint16_be(payload, offset)
        ext_len  = _read_uint16_be(payload, offset + 2)
        offset += 4

        if offset + ext_len > extensions_end:
            break

        if ext_type == _EXTENSION_SNI:
            # SNI extension:
            #   list_length(2), type(1), name_length(2), name(…)
            if ext_len < 5:
                break
            # sni_list_length = _read_uint16_be(payload, offset)
            sni_type   = payload[offset + 2]
            sni_length = _read_uint16_be(payload, offset + 3)

            if sni_type != _SNI_TYPE_HOSTNAME:
                break
            if sni_length > ext_len - 5:
                break

            sni = payload[offset + 5 : offset + 5 + sni_length]
            try:
                return sni.decode("ascii")
            except UnicodeDecodeError:
                return sni.decode("utf-8", errors="replace")

        offset += ext_len

    return None


# ═══════════════════════════════════════════════════════════════════════
# HTTP Host Header Extraction  (mirrors C++ HTTPHostExtractor)
# ═══════════════════════════════════════════════════════════════════════

# Common HTTP request method prefixes (4 bytes each)
_HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def is_http_request(payload: bytes) -> bool:
    """Return True if *payload* starts with a known HTTP request method."""
    if len(payload) < 4:
        return False
    return payload[:4] in _HTTP_METHODS


def extract_http_host(payload: bytes) -> Optional[str]:
    """
    Extract the ``Host`` header value from an HTTP request.

    Returns the hostname (without port), or None if this is not an
    HTTP request or no Host header is found.
    """
    if not is_http_request(payload):
        return None

    # Search for "Host:" (case-insensitive) in the payload
    lower_payload = payload.lower()
    idx = lower_payload.find(b"host:")
    if idx == -1:
        return None

    # Skip "Host:" and any leading whitespace
    start = idx + 5
    while start < len(payload) and payload[start:start + 1] in (b" ", b"\t"):
        start += 1

    # Find end of header value (CRLF or LF)
    end = start
    while end < len(payload) and payload[end:end + 1] not in (b"\r", b"\n"):
        end += 1

    if end <= start:
        return None

    host = payload[start:end].decode("ascii", errors="replace").strip()

    # Remove port if present (e.g. "example.com:8080" → "example.com")
    colon = host.find(":")
    if colon != -1:
        host = host[:colon]

    return host if host else None


# ═══════════════════════════════════════════════════════════════════════
# DNS Query Extraction  (mirrors C++ DNSExtractor)
# ═══════════════════════════════════════════════════════════════════════
#
# DNS wire format (after UDP header):
#   Header (12 bytes):
#     [0-1]  Transaction ID
#     [2]    Flags byte 1 — bit 7 is QR (0 = query, 1 = response)
#     [3]    Flags byte 2
#     [4-5]  QDCOUNT (# of questions)
#     …
#   Question Section:
#     Label-encoded domain name, then QTYPE(2) + QCLASS(2)

def is_dns_query(payload: bytes) -> bool:
    """Return True if *payload* looks like a DNS *query* (not a response)."""
    if len(payload) < 12:
        return False
    # QR bit (byte 2, bit 7) must be 0 for a query
    if payload[2] & 0x80:
        return False
    # QDCOUNT > 0
    qdcount = _read_uint16_be(payload, 4)
    return qdcount > 0


def extract_dns_query(payload: bytes) -> Optional[str]:
    """
    Extract the queried domain name from a DNS query packet.

    *payload* is the raw UDP payload (the DNS message starting at the
    transaction ID).

    Returns the domain (e.g. ``"www.google.com"``), or None.
    """
    if not is_dns_query(payload):
        return None

    offset = 12  # Skip DNS header
    labels: list[str] = []

    while offset < len(payload):
        label_len = payload[offset]

        if label_len == 0:
            break  # End of domain name

        if label_len > 63:
            break  # Compression pointer or invalid

        offset += 1
        if offset + label_len > len(payload):
            break

        labels.append(payload[offset : offset + label_len].decode("ascii", errors="replace"))
        offset += label_len

    return ".".join(labels) if labels else None
