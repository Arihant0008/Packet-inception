"""
connection_tracker.py — Per-flow connection table.

C++ equivalents
---------------
- include/connection_tracker.h  →  ConnectionTracker, GlobalConnectionTable
- src/connection_tracker.cpp    →  Flow state management
- (partial) include/fast_path.h →  inspectPayload(), classifyFlow()

In the C++ multi-threaded design each FP thread owns a private
ConnectionTracker.  In this single-threaded Python port we use one
tracker for the whole engine.
"""

from __future__ import annotations

from typing import Optional

from .types import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
    app_type_to_string,
)


class ConnectionTracker:
    """
    Maintains a flow table keyed by :class:`FiveTuple`.

    For every new five-tuple we create a :class:`Connection` entry.
    Classification, blocking, and TCP-state updates are done on
    that entry.
    """

    def __init__(self, max_connections: int = 100_000) -> None:
        self._connections: dict[FiveTuple, Connection] = {}
        self._max_connections = max_connections
        self._total_seen: int = 0
        self._classified_count: int = 0
        self._blocked_count: int = 0

    # ── Lookup / Create ────────────────────────────────────────────

    def get_or_create(self, ft: FiveTuple) -> Connection:
        """
        Return the Connection for *ft*, creating a new entry if one
        does not already exist.  Also checks the reverse tuple so
        that bidirectional flows share the same Connection.
        """
        conn = self._connections.get(ft)
        if conn is not None:
            return conn

        # Try reverse tuple
        rev = ft.reverse()
        conn = self._connections.get(rev)
        if conn is not None:
            return conn

        # Evict oldest if table is full
        if len(self._connections) >= self._max_connections:
            self._evict_oldest()

        conn = Connection(tuple=ft)
        self._connections[ft] = conn
        self._total_seen += 1
        return conn

    def get(self, ft: FiveTuple) -> Optional[Connection]:
        """Return Connection for *ft* (or its reverse), or None."""
        conn = self._connections.get(ft)
        if conn is not None:
            return conn
        return self._connections.get(ft.reverse())

    # ── State Updates ──────────────────────────────────────────────

    def update(self, conn: Connection, packet_size: int, is_outbound: bool = True) -> None:
        """Update per-flow counters."""
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify(self, conn: Connection, app: AppType, sni: str) -> None:
        """Mark a connection as classified (only if not already)."""
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block(self, conn: Connection) -> None:
        """Mark a connection as blocked."""
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def update_tcp_state(self, conn: Connection, tcp_flags: int) -> None:
        """
        Track the TCP handshake / teardown flags.

        Flag constants (same as C++):
            SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04
        """
        SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04

        if tcp_flags & SYN:
            if tcp_flags & ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (tcp_flags & ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & FIN:
            conn.fin_seen = True

        if tcp_flags & RST:
            conn.state = ConnectionState.CLOSED

        if conn.fin_seen and (tcp_flags & ACK):
            conn.state = ConnectionState.CLOSED

    # ── Querying ───────────────────────────────────────────────────

    def get_all_connections(self) -> list[Connection]:
        return list(self._connections.values())

    @property
    def active_count(self) -> int:
        return len(self._connections)

    @property
    def total_seen(self) -> int:
        return self._total_seen

    @property
    def classified_count(self) -> int:
        return self._classified_count

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    def clear(self) -> None:
        self._connections.clear()

    # ── Internals ──────────────────────────────────────────────────

    def _evict_oldest(self) -> None:
        """Remove the oldest entry (by insertion order, Python 3.7+)."""
        if self._connections:
            oldest_key = next(iter(self._connections))
            del self._connections[oldest_key]
