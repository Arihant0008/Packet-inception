#!/usr/bin/env python3
"""
main.py — CLI entry point for the Python DPI Engine.

C++ equivalent
--------------
- src/main_dpi.cpp  →  Command-line parsing and DPIEngine invocation

Usage
-----
    python -m dpi_python.main input.pcap output.pcap [options]

    # Or run directly:
    python dpi_python/main.py input.pcap output.pcap --block-app YouTube

Options
-------
    --block-ip   IP       Block packets from source IP
    --block-app  APP      Block application (YouTube, Facebook, etc.)
    --block-domain DOM    Block domain (supports wildcards: *.facebook.com)
    --block-port PORT     Block destination port
    --rules FILE          Load blocking rules from file
    --verbose             Enable verbose output
"""

from __future__ import annotations

import argparse
import sys

from .dpi_engine import DPIEngine


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="dpi_python",
        description=(
            "DPI Engine v1.0 (Python) — Deep Packet Inspection System\n"
            "Reads a PCAP, applies DPI + blocking rules, writes filtered PCAP."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m dpi_python.main capture.pcap filtered.pcap\n"
            "  python -m dpi_python.main capture.pcap filtered.pcap --block-app YouTube\n"
            "  python -m dpi_python.main capture.pcap filtered.pcap "
            "--block-ip 192.168.1.50 --block-domain *.tiktok.com\n"
            "  python -m dpi_python.main capture.pcap filtered.pcap --rules rules.txt\n"
            "\n"
            "Supported Apps for Blocking:\n"
            "  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,\n"
            "  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom,\n"
            "  Discord, GitHub, Cloudflare\n"
        ),
    )

    parser.add_argument("input_pcap", help="Input PCAP file (captured traffic)")
    parser.add_argument("output_pcap", help="Output PCAP file (filtered traffic)")

    parser.add_argument(
        "--block-ip", action="append", default=[], metavar="IP",
        help="Block packets from this source IP (can be repeated)",
    )
    parser.add_argument(
        "--block-app", action="append", default=[], metavar="APP",
        help="Block application by name, e.g. YouTube (can be repeated)",
    )
    parser.add_argument(
        "--block-domain", action="append", default=[], metavar="DOM",
        help="Block domain (supports wildcards like *.facebook.com)",
    )
    parser.add_argument(
        "--block-port", action="append", default=[], type=int, metavar="PORT",
        help="Block destination port (can be repeated)",
    )
    parser.add_argument(
        "--rules", metavar="FILE",
        help="Load blocking rules from a rules file",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose output (print each blocked packet)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry-point for the DPI engine CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Create engine
    engine = DPIEngine(verbose=args.verbose)

    # Load rules from file first (so CLI flags can override / add)
    if args.rules:
        engine.load_rules(args.rules)

    # Apply CLI blocking rules
    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)
    for port in args.block_port:
        engine.rule_manager.block_port(port)

    # Process
    success = engine.process_file(args.input_pcap, args.output_pcap)

    if success:
        print(f"\nProcessing complete!")
        print(f"Output written to: {args.output_pcap}")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
