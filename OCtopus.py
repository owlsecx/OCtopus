#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════════
#
#    ██████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
#   ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
#   ██║   ██║██║        ██║   ██║   ██║██████╔╝██║   ██║███████╗
#   ██║   ██║██║        ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║
#   ╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
#    ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
#
#   OCTOPUS — Tactical Traffic Dissector & Credential Hunter
#   Version : 1.0
#   Author  : khaled.s.haddad
#   Website : owlsec.org
#
#   Protocols: HTTP · HTTPS(SNI) · DNS · FTP · Telnet · SMTP
#              POP3 · IMAP · SSH · RDP · LDAP · MySQL · Redis
#              Kerberos · NTLM · SIP · MQTT · Modbus
#
#   Features:
#     ✔ Real-time packet capture with BPF filtering
#     ✔ Multi-protocol credential extraction
#     ✔ JSON & plaintext structured logging
#     ✔ Live statistics dashboard
#     ✔ Packet replay / offline PCAP analysis
#     ✔ Protocol-aware flow reconstruction
#     ✔ Geolocation enrichment (optional)
#     ✔ Alert thresholds & credential deduplication
#     ✔ Export to JSON / CSV / HTML report
#     ✔ Configurable via octopus.conf
#
#   Legal Notice:
#     Use only on networks you own or are explicitly authorized to test.
#     Unauthorized interception is illegal under applicable law.
#
# ════════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import argparse
import base64
import csv
import datetime
import hashlib
import html as _html
import ipaddress
import json
import logging
import os
import queue
import re
import signal
import socket
import struct
import sys
import textwrap
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ── Third-party (all optional, graceful degradation) ──────────────────────────
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw,
        get_if_list, get_if_addr, rdpcap, wrpcap,
        load_layer, conf as scapy_conf
    )
    from scapy.layers.l2 import Ether
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    load_layer("http")
    from scapy.layers.http import HTTPRequest, HTTPResponse
    HTTP_LAYER_OK = True
except Exception:
    HTTPRequest = HTTPResponse = None
    HTTP_LAYER_OK = False

try:
    import geoip2.database as geoip2_db
    GEOIP_OK = True
except ImportError:
    GEOIP_OK = False

try:
    import termios
    import tty
    TTY_OK = True
except ImportError:
    TTY_OK = False

# ════════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════════

VERSION   = "1.0"
TOOL_NAME = "OCTOPUS"
AUTHOR    = "khaled.s.haddad"
WEBSITE   = "owlsec.org"

PROTO_PORTS: Dict[str, List[int]] = {
    "FTP_DATA":  [20],
    "FTP":       [21],
    "SSH":       [22],
    "TELNET":    [23],
    "SMTP":      [25, 465, 587],
    "DNS":       [53],
    "HTTP":      [80, 8080, 8000, 8888],
    "POP3":      [110],
    "IMAP":      [143, 993],
    "LDAP":      [389, 636],
    "HTTPS":     [443, 8443],
    "SMB":       [445],
    "MSSQL":     [1433],
    "MYSQL":     [3306],
    "RDP":       [3389],
    "REDIS":     [6379],
    "MQTT":      [1883, 8883],
    "MODBUS":    [502],
    "SIP":       [5060, 5061],
    "KERBEROS":  [88],
}

CRED_KEYWORDS = frozenset([
    "username=", "password=", "passwd=", "pwd=", "user=", "login=",
    "pass=", "auth=", "email=", "mail=", "token=", "secret=",
    "credential=", "api_key=", "apikey=", "access_token=", "bearer ",
    "authorization:", "x-api-key:", "x-auth-token:",
])

SENSITIVE_HEADERS = frozenset([
    "authorization", "proxy-authorization", "x-api-key",
    "x-auth-token", "x-secret", "cookie", "set-cookie",
])

DEFAULT_CONFIG = {
    "log_file":        "octopus.log",
    "json_log":        "octopus_events.json",
    "pcap_out":        None,
    "geoip_db":        None,
    "dedup_ttl":       300,
    "max_flow_bytes":  65536,
    "alert_threshold": 10,
    "verbose":         False,
    "color":           True,
    "quiet":           False,
    "protocols":       list(PROTO_PORTS.keys()),
}


# ════════════════════════════════════════════════════════════════════════════════
#  COLOR ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class C:
    """ANSI color codes with runtime enable/disable support."""
    _enabled: bool = True

    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    DIM     = "\033[2m"
    ORANGE  = "\033[38;5;214m"
    PINK    = "\033[38;5;213m"
    TEAL    = "\033[38;5;51m"
    GREY    = "\033[38;5;240m"
    LIME    = "\033[38;5;154m"
    UNDER   = "\033[4m"
    BLINK   = "\033[5m"
    REVERSE = "\033[7m"

    @classmethod
    def disable(cls) -> None:
        cls._enabled = False
        for attr in vars(cls):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")

    @classmethod
    def c(cls, text: str, *codes: str) -> str:
        if not cls._enabled:
            return str(text)
        return "".join(codes) + str(text) + cls.RESET


def clr(text: str, *codes: str) -> str:
    return C.c(text, *codes)


# ════════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class CredEvent:
    timestamp:  str
    proto:      str
    tag:        str
    src_ip:     str
    src_port:   int
    dst_ip:     str
    dst_port:   int
    data:       Dict[str, Any]
    geo_src:    Optional[str] = None
    geo_dst:    Optional[str] = None
    flow_id:    Optional[str] = None
    severity:   str = "MEDIUM"   # LOW | MEDIUM | HIGH | CRITICAL

    def fingerprint(self) -> str:
        raw = f"{self.proto}{self.src_ip}{self.dst_ip}{json.dumps(self.data, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FlowKey:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    str

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    def __eq__(self, other):
        return (isinstance(other, FlowKey) and
                self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.proto == other.proto)


@dataclass
class FlowBuffer:
    key:      FlowKey
    data:     bytearray = field(default_factory=bytearray)
    created:  float     = field(default_factory=time.time)
    updated:  float     = field(default_factory=time.time)
    pkts:     int       = 0

    def append(self, payload: bytes, max_bytes: int) -> None:
        remaining = max_bytes - len(self.data)
        if remaining > 0:
            self.data.extend(payload[:remaining])
        self.updated = time.time()
        self.pkts   += 1


# ════════════════════════════════════════════════════════════════════════════════
#  STATISTICS
# ════════════════════════════════════════════════════════════════════════════════

class Stats:
    def __init__(self):
        self._lock   = threading.Lock()
        self.start   = time.time()
        self.packets = 0
        self.creds   = 0
        self.events  = 0
        self.by_proto: Dict[str, int] = defaultdict(int)
        self.by_src:   Dict[str, int] = defaultdict(int)
        self.alerts    = 0
        self.flows     = 0
        self.recent: deque = deque(maxlen=5)

    def pkt(self):
        with self._lock:
            self.packets += 1

    def cred(self, proto: str, src: str):
        with self._lock:
            self.creds         += 1
            self.events        += 1
            self.by_proto[proto] += 1
            self.by_src[src]     += 1
            if self.by_src[src] > 10:
                self.alerts += 1

    def add_recent(self, tag: str, src: str):
        with self._lock:
            self.recent.appendleft(f"{tag} ← {src}")

    def uptime(self) -> str:
        secs = int(time.time() - self.start)
        h, rem = divmod(secs, 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "packets": self.packets,
                "creds":   self.creds,
                "events":  self.events,
                "alerts":  self.alerts,
                "uptime":  self.uptime(),
                "by_proto": dict(self.by_proto),
                "top_src":  sorted(self.by_src.items(), key=lambda x: -x[1])[:5],
            }


STATS = Stats()


# ════════════════════════════════════════════════════════════════════════════════
#  LOGGING ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class Logger:
    def __init__(self, log_file: str, json_file: str, quiet: bool = False):
        self.log_file  = Path(log_file)
        self.json_file = Path(json_file)
        self.quiet     = quiet
        self._lock     = threading.Lock()
        self._queue: queue.Queue = queue.Queue()
        self._running  = True
        self._worker   = threading.Thread(target=self._flush_loop, daemon=True)
        self._worker.start()

        # Python stdlib logger for structured text
        self._logger = logging.getLogger("octopus")
        self._logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(str(self.log_file), encoding="utf-8")
        fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
        self._logger.addHandler(fh)

    def log(self, msg: str) -> None:
        self._logger.info(msg)

    def event(self, ev: CredEvent) -> None:
        self._queue.put(ev)

    def _flush_loop(self) -> None:
        buf: List[dict] = []
        while self._running or not self._queue.empty():
            try:
                ev = self._queue.get(timeout=0.5)
                buf.append(ev.to_dict())
                self._logger.info(f"[{ev.tag}] {ev.src_ip}:{ev.src_port} → {ev.dst_ip}:{ev.dst_port} | {ev.data}")
                if len(buf) >= 20:
                    self._write_json(buf)
                    buf.clear()
            except queue.Empty:
                if buf:
                    self._write_json(buf)
                    buf.clear()

    def _write_json(self, records: List[dict]) -> None:
        existing: List[dict] = []
        if self.json_file.exists():
            try:
                with open(self.json_file, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []
        existing.extend(records)
        with open(self.json_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, default=str)

    def stop(self) -> None:
        self._running = False
        self._worker.join(timeout=3)


# ════════════════════════════════════════════════════════════════════════════════
#  GEO ENRICHMENT
# ════════════════════════════════════════════════════════════════════════════════

class GeoLookup:
    def __init__(self, db_path: Optional[str]):
        self._reader = None
        self._cache: Dict[str, str] = {}
        if db_path and GEOIP_OK:
            try:
                self._reader = geoip2_db.Reader(db_path)
            except Exception as e:
                print(clr(f"  [!] GeoIP DB failed: {e}", C.YELLOW))

    def lookup(self, ip: str) -> Optional[str]:
        if not self._reader:
            return None
        if ip in self._cache:
            return self._cache[ip]
        try:
            r  = self._reader.city(ip)
            cc = r.country.iso_code or "??"
            city = r.city.name or ""
            result = f"{cc}/{city}" if city else cc
            self._cache[ip] = result
            return result
        except Exception:
            self._cache[ip] = None
            return None


# ════════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION
# ════════════════════════════════════════════════════════════════════════════════

class Deduplicator:
    def __init__(self, ttl: int = 300):
        self._ttl   = ttl
        self._seen: Dict[str, float] = {}
        self._lock  = threading.Lock()

    def is_new(self, fingerprint: str) -> bool:
        now = time.time()
        with self._lock:
            if fingerprint in self._seen:
                if now - self._seen[fingerprint] < self._ttl:
                    return False
            self._seen[fingerprint] = now
            # Purge expired
            expired = [k for k, v in self._seen.items() if now - v >= self._ttl]
            for k in expired:
                del self._seen[k]
        return True


# ════════════════════════════════════════════════════════════════════════════════
#  FLOW TRACKER
# ════════════════════════════════════════════════════════════════════════════════

class FlowTracker:
    def __init__(self, max_bytes: int = 65536, timeout: int = 60):
        self._flows: Dict[FlowKey, FlowBuffer] = {}
        self._max   = max_bytes
        self._tout  = timeout
        self._lock  = threading.Lock()
        self._cleaner = threading.Thread(target=self._gc, daemon=True)
        self._cleaner.start()

    def feed(self, key: FlowKey, payload: bytes) -> bytes:
        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowBuffer(key=key)
                STATS.flows += 1
            buf = self._flows[key]
            buf.append(payload, self._max)
            return bytes(buf.data)

    def get(self, key: FlowKey) -> bytes:
        with self._lock:
            return bytes(self._flows[key].data) if key in self._flows else b""

    def reset(self, key: FlowKey) -> None:
        with self._lock:
            self._flows.pop(key, None)

    def _gc(self):
        while True:
            time.sleep(30)
            cutoff = time.time() - self._tout
            with self._lock:
                stale = [k for k, v in self._flows.items() if v.updated < cutoff]
                for k in stale:
                    del self._flows[k]


# ════════════════════════════════════════════════════════════════════════════════
#  BANNER & UI
# ════════════════════════════════════════════════════════════════════════════════

BANNER_ART = r"""
   ██████╗  ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
  ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
  ██║   ██║██║        ██║   ██║   ██║██████╔╝██║   ██║███████╗
  ██║   ██║██║        ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║
  ╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
   ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝"""


def banner(sub: str = "") -> None:
    print(clr(BANNER_ART, C.MAGENTA))
    print(clr(f"  Tactical Traffic Dissector & Credential Hunter  v{VERSION}", C.CYAN))
    print(clr("  HTTP·DNS·FTP·Telnet·SMTP·POP3·IMAP·SSH·RDP·LDAP·MySQL·Redis·SIP·MQTT", C.WHITE))
    if sub:
        print(clr(f"  {sub}", C.GREY))
    print()
    print(clr("  " + clr("Author : ", C.DIM + C.WHITE) + clr(AUTHOR, C.CYAN) +
          clr("   |   Website : ", C.DIM + C.WHITE) + clr(WEBSITE, C.CYAN), ""))
    print(clr("─" * 70, C.MAGENTA))
    print()


def section(title: str) -> None:
    print()
    print(clr(f"  ┌─ {title}", C.YELLOW + C.BOLD))


def info(msg: str) -> None:
    print(clr(f"  {clr('[i]', C.CYAN)}  {msg}", C.WHITE))


def ok(msg: str) -> None:
    print(clr(f"  {clr('[✔]', C.GREEN)}  {msg}", C.WHITE))


def warn(msg: str) -> None:
    print(clr(f"  {clr('[!]', C.YELLOW)}  {msg}", C.YELLOW))


def err(msg: str) -> None:
    print(clr(f"  {clr('[✘]', C.RED)}  {msg}", C.RED))


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    input(clr("\n  [↩] Press Enter to continue...", C.YELLOW))


def hr(char: str = "─", width: int = 70, color: str = C.MAGENTA) -> None:
    print(clr(char * width, color))


# ════════════════════════════════════════════════════════════════════════════════
#  HELP
# ════════════════════════════════════════════════════════════════════════════════

HELP_SECTIONS = [
    ("DESCRIPTION", [
        "OCTOPUS captures and dissects network traffic in real-time,",
        "hunting for credentials transmitted in plaintext over unencrypted",
        "protocols. It also supports offline PCAP analysis and rich exports.",
    ]),
    ("USAGE", [
        "sudo python3 octopus.py",
        "sudo python3 octopus.py -i eth0",
        "sudo python3 octopus.py -i eth0 -l session.log --json events.json",
        "sudo python3 octopus.py --pcap capture.pcap",
        "sudo python3 octopus.py -i eth0 --protocols HTTP,FTP,DNS",
        "sudo python3 octopus.py -i eth0 --export html --out report.html",
    ]),
    ("ARGUMENTS", [
        "-i / --interface    Network interface (e.g. eth0, wlan0)",
        "-l / --log          Text log file  (default: octopus.log)",
        "--json              JSON events file (default: octopus_events.json)",
        "--pcap              Analyze existing PCAP file (offline mode)",
        "--write-pcap        Write captured packets to PCAP file",
        "--protocols         Comma-separated protocol filter (e.g. HTTP,FTP)",
        "--geoip             Path to GeoIP2 City DB (.mmdb)",
        "--export            Export format after capture: json|csv|html",
        "--out               Output file for export",
        "--no-color          Disable ANSI colors (for piping / logging)",
        "--quiet             Suppress terminal output (log only)",
        "--verbose           Show all packets, not just credential hits",
        "--dedup-ttl         Seconds before re-alerting same cred (default 300)",
        "-h / --help         Show this help message",
    ]),
    ("SUPPORTED PROTOCOLS", [
        "DNS       : Query logging (UDP 53)",
        "HTTP      : Method, URL, headers, Basic Auth decode (80,8080,8000)",
        "HTTPS     : SNI hostname extraction (443,8443)",
        "FTP       : USER / PASS / PORT capture (21)",
        "SSH       : Version banner detection (22)",
        "Telnet    : Cleartext keyword detection with flow reconstruction (23)",
        "SMTP      : AUTH LOGIN / PLAIN / Base64 (25,465,587)",
        "POP3      : USER / PASS / APOP (110)",
        "IMAP      : LOGIN / AUTHENTICATE commands (143,993)",
        "LDAP      : Bind request credential extraction (389,636)",
        "MySQL     : Login request / handshake auth (3306)",
        "Redis     : AUTH command detection (6379)",
        "RDP       : Connection request detection (3389)",
        "SSH       : Banner & version grab (22)",
        "SIP       : Authentication headers (5060,5061)",
        "MQTT      : CONNECT packet credential extraction (1883,8883)",
        "Modbus    : Function code logging (502)",
        "Kerberos  : AS-REQ / TGS-REQ detection (88)",
        "NTLM      : Challenge / Response detection (any port)",
        "Generic   : Keyword-based credential hunting (all ports)",
    ]),
    ("OUTPUT SEVERITY TAGS", [
        "CRITICAL  : Clear-text credentials fully extracted (user + pass)",
        "HIGH      : Partial credentials or encoded auth detected",
        "MEDIUM    : Possible credentials via keyword match",
        "LOW       : Protocol metadata (DNS query, SSH banner, etc.)",
    ]),
    ("NOTES", [
        "Requires root / Administrator privileges for live capture.",
        "Offline PCAP mode (--pcap) does NOT require root.",
        "All events are timestamped and written to log + JSON.",
        "Press Ctrl+C to stop capture and view final statistics.",
        "Use --export html for a full HTML report with charts.",
    ]),
    ("DISCLAIMER", [
        "Use OCTOPUS only on networks you own or are explicitly",
        "authorized to test. Unauthorized packet interception is",
        "illegal under the CFAA, GDPR, and equivalent legislation.",
        "The author assumes no responsibility for misuse.",
    ]),
]


def show_help() -> None:
    W = 68
    print()
    print(clr("╔" + "═" * W + "╗", C.MAGENTA))
    title = f"  {TOOL_NAME} v{VERSION} — Help & Usage  "
    print(clr("║", C.MAGENTA) +
          clr(title.center(W), C.BOLD + C.WHITE) +
          clr("║", C.MAGENTA))
    print(clr("╠" + "═" * W + "╣", C.MAGENTA))

    for sec_title, lines in HELP_SECTIONS:
        hdr = f"  ┌─ {sec_title}"
        pad = W - len(hdr)
        print(clr("║", C.MAGENTA) + clr(hdr, C.YELLOW) + " " * max(pad, 0) + clr("║", C.MAGENTA))
        for line in lines:
            inner = f"  │  {line}"
            p = W - len(inner)
            print(clr("║", C.MAGENTA) + clr(inner, C.WHITE) + " " * max(p, 0) + clr("║", C.MAGENTA))
        print(clr("║", C.MAGENTA) + " " * W + clr("║", C.MAGENTA))

    print(clr("╚" + "═" * W + "╝", C.MAGENTA))
    print()


# ════════════════════════════════════════════════════════════════════════════════
#  LIVE STATS DASHBOARD
# ════════════════════════════════════════════════════════════════════════════════

class Dashboard:
    def __init__(self, refresh: float = 2.0):
        self._refresh  = refresh
        self._running  = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _loop(self) -> None:
        while self._running:
            self._render()
            time.sleep(self._refresh)

    @staticmethod
    def _render() -> None:
        snap = STATS.snapshot()
        # Move cursor up and overwrite dashboard lines
        lines = [
            clr("─" * 70, C.GREY),
            (
                clr("  STATS", C.BOLD + C.CYAN) + "  " +
                clr(f"Pkts:{snap['packets']}", C.WHITE) + "  " +
                clr(f"Creds:{snap['creds']}", C.RED + C.BOLD) + "  " +
                clr(f"Alerts:{snap['alerts']}", C.YELLOW) + "  " +
                clr(f"Up:{snap['uptime']}", C.DIM + C.WHITE)
            ),
        ]
        if snap["by_proto"]:
            proto_str = "  ".join(
                clr(f"{p}:{n}", C.TEAL)
                for p, n in sorted(snap["by_proto"].items(), key=lambda x: -x[1])[:6]
            )
            lines.append(f"  {clr('Proto:', C.DIM)}  {proto_str}")
        if snap["top_src"]:
            src_str = "  ".join(
                clr(f"{ip}({n})", C.ORANGE)
                for ip, n in snap["top_src"][:4]
            )
            lines.append(f"  {clr('TopSrc:', C.DIM)} {src_str}")
        lines.append(clr("─" * 70, C.GREY))

        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()


# ════════════════════════════════════════════════════════════════════════════════
#  EXPORT ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class Exporter:
    @staticmethod
    def to_csv(events: List[dict], out_path: str) -> None:
        if not events:
            return
        keys = list(events[0].keys())
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(events)

    @staticmethod
    def to_html(events: List[dict], out_path: str) -> None:
        rows = ""
        for ev in events:
            sev   = ev.get("severity", "MEDIUM")
            color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
                     "MEDIUM": "#ffcc00", "LOW": "#44bb44"}.get(sev, "#ccc")
            data  = _html.escape(json.dumps(ev.get("data", {}), indent=2))
            e     = _html.escape
            rows += (
                f"<tr>"
                f"<td>{e(str(ev.get('timestamp','')))}</td>"
                f"<td><span style='color:{color};font-weight:bold'>{e(str(ev.get('tag','')))}</span></td>"
                f"<td>{e(str(ev.get('proto','')))}</td>"
                f"<td>{e(str(ev.get('src_ip','')))}:{e(str(ev.get('src_port','')))}</td>"
                f"<td>{e(str(ev.get('dst_ip','')))}:{e(str(ev.get('dst_port','')))}</td>"
                f"<td>{e(str(ev.get('geo_src','') or ''))}</td>"
                f"<td><pre style='margin:0;font-size:11px'>{data}</pre></td>"
                f"</tr>\n"
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OCTOPUS Report — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
  body  {{ background:#0d0d0d; color:#e0e0e0; font-family:monospace; margin:20px; }}
  h1    {{ color:#cc44ff; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th    {{ background:#1a1a2e; color:#cc44ff; padding:8px; text-align:left; }}
  td    {{ padding:6px 8px; border-bottom:1px solid #222; vertical-align:top; }}
  tr:hover td {{ background:#1a1a1a; }}
  pre   {{ background:#111; padding:4px; border-radius:3px; }}
  .badge{{ display:inline-block; padding:2px 6px; border-radius:3px; font-size:11px; }}
</style>
</head>
<body>
<h1>🐙 OCTOPUS — Credential Hunt Report</h1>
<p>Generated: {datetime.datetime.now().isoformat()} | Total Events: {len(events)}</p>
<table>
<tr>
  <th>Timestamp</th><th>Tag</th><th>Protocol</th>
  <th>Source</th><th>Destination</th><th>Geo</th><th>Data</th>
</tr>
{rows}
</table>
</body>
</html>"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)

    @classmethod
    def export(cls, fmt: str, json_file: str, out_path: str) -> None:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                events = json.load(f)
        except Exception as e:
            err(f"Cannot read events: {e}")
            return

        if fmt == "csv":
            cls.to_csv(events, out_path)
        elif fmt == "html":
            cls.to_html(events, out_path)
        elif fmt == "json":
            import shutil
            shutil.copy(json_file, out_path)
        ok(f"Exported {len(events)} events → {out_path}")


# ════════════════════════════════════════════════════════════════════════════════
#  PROTOCOL DISSECTORS
# ════════════════════════════════════════════════════════════════════════════════

class Dissector:
    """Base class for all protocol dissectors."""

    def __init__(self, logger: Logger, geo: GeoLookup, dedup: Deduplicator,
                 flows: FlowTracker, cfg: dict):
        self.logger = logger
        self.geo    = geo
        self.dedup  = dedup
        self.flows  = flows
        self.cfg    = cfg

    def _make_event(self, proto: str, tag: str, src: str, sport: int,
                    dst: str, dport: int, data: dict,
                    severity: str = "MEDIUM") -> Optional[CredEvent]:
        ev = CredEvent(
            timestamp = datetime.datetime.now().isoformat(),
            proto     = proto,
            tag       = tag,
            src_ip    = src,
            src_port  = sport,
            dst_ip    = dst,
            dst_port  = dport,
            data      = data,
            geo_src   = self.geo.lookup(src),
            geo_dst   = self.geo.lookup(dst),
            severity  = severity,
        )
        fp = ev.fingerprint()
        if not self.dedup.is_new(fp):
            return None
        return ev

    def _emit(self, ev: CredEvent, display_fn: Callable) -> None:
        if ev is None:
            return
        STATS.cred(ev.proto, ev.src_ip)
        STATS.add_recent(ev.tag, ev.src_ip)
        self.logger.event(ev)
        if not self.cfg.get("quiet"):
            display_fn(ev)

    def process(self, pkt) -> None:
        raise NotImplementedError


def _tag_line(tag: str, color_code: str, src: str, sport: int,
              dst: str, dport: int, extra: str = "") -> None:
    geo = ""
    ts  = datetime.datetime.now().strftime("%H:%M:%S")
    print(
        f"  {clr(ts, C.GREY)}  "
        f"{clr(f'[{tag}]', color_code):<28}"
        f"  {clr(src, C.WHITE)}:{clr(str(sport), C.DIM)}"
        f" → {clr(dst, C.WHITE)}:{clr(str(dport), C.DIM)}"
        + (f"\n  {clr('│', C.DIM)}  {clr(extra, C.YELLOW)}" if extra else "")
    )


# ────────────────────────────────────────────────────────────────────────────────

class DNSDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        try:
            qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            src   = pkt[IP].src if pkt.haslayer(IP) else "?"
            ev    = self._make_event("DNS", "DNS QUERY", src, 0, "0.0.0.0", 53,
                                     {"query": qname}, severity="LOW")
            if ev:
                self._emit(ev, lambda e: _tag_line("DNS", C.CYAN, e.src_ip, e.src_port,
                                                   e.dst_ip, e.dst_port, qname))
        except Exception:
            pass


class HTTPDissector(Dissector):
    def process(self, pkt) -> None:
        if not (HTTP_LAYER_OK and pkt.haslayer(HTTPRequest)):
            return
        try:
            src    = pkt[IP].src if pkt.haslayer(IP) else "?"
            sport  = pkt[TCP].sport if pkt.haslayer(TCP) else 0
            dport  = pkt[TCP].dport if pkt.haslayer(TCP) else 80
            dst    = pkt[IP].dst   if pkt.haslayer(IP) else "?"
            req    = pkt[HTTPRequest]
            host   = (req.Host   or b"").decode(errors="ignore")
            path   = (req.Path   or b"/").decode(errors="ignore")
            method = (req.Method or b"?").decode(errors="ignore")
            url    = f"http://{host}{path}"

            ev = self._make_event("HTTP", "HTTP REQUEST", src, sport, dst, dport,
                                  {"method": method, "url": url}, severity="LOW")
            if ev:
                self._emit(ev, lambda e: _tag_line("HTTP", C.GREEN, e.src_ip, e.src_port,
                                                   e.dst_ip, e.dst_port, f"{method} {url}"))

            # Authorization header
            auth_val = None
            if hasattr(req, "Authorization") and req.Authorization:
                auth_val = req.Authorization.decode(errors="ignore").strip()
            # Cookie
            cookie_val = None
            if hasattr(req, "Cookie") and req.Cookie:
                cookie_val = req.Cookie.decode(errors="ignore")[:200]

            if auth_val and auth_val.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth_val[6:]).decode("utf-8", errors="ignore")
                    parts   = decoded.split(":", 1)
                    data    = {"user": parts[0], "pass": parts[1] if len(parts) > 1 else ""}
                    ev2     = self._make_event("HTTP", "BASIC AUTH", src, sport, dst, dport,
                                              data, severity="CRITICAL")
                    if ev2:
                        self._emit(ev2, lambda e: _tag_line("BASIC AUTH", C.RED + C.BOLD,
                                                            e.src_ip, e.src_port,
                                                            e.dst_ip, e.dst_port,
                                                            f"{data['user']} : {data['pass']}"))
                except Exception:
                    pass

            elif auth_val and auth_val.lower().startswith("bearer "):
                token = auth_val[7:].strip()
                ev2   = self._make_event("HTTP", "BEARER TOKEN", src, sport, dst, dport,
                                        {"token": token[:80]}, severity="HIGH")
                if ev2:
                    self._emit(ev2, lambda e: _tag_line("BEARER TOKEN", C.RED,
                                                        e.src_ip, e.src_port,
                                                        e.dst_ip, e.dst_port, token[:60]))
            if cookie_val:
                ev3 = self._make_event("HTTP", "COOKIE", src, sport, dst, dport,
                                       {"cookie": cookie_val}, severity="MEDIUM")
                if ev3:
                    self._emit(ev3, lambda e: _tag_line("COOKIE", C.ORANGE,
                                                        e.src_ip, e.src_port,
                                                        e.dst_ip, e.dst_port, cookie_val[:80]))
        except Exception:
            pass


class HTTPSDissector(Dissector):
    """Extracts SNI from TLS ClientHello."""
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        if dport not in (443, 8443):
            return
        try:
            raw = pkt[Raw].load
            sni = self._extract_sni(raw)
            if sni:
                src   = pkt[IP].src if pkt.haslayer(IP) else "?"
                dst   = pkt[IP].dst if pkt.haslayer(IP) else "?"
                sport = pkt[TCP].sport
                ev    = self._make_event("HTTPS", "TLS SNI", src, sport, dst, dport,
                                        {"sni": sni}, severity="LOW")
                if ev:
                    self._emit(ev, lambda e: _tag_line("TLS SNI", C.TEAL,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, sni))
        except Exception:
            pass

    @staticmethod
    def _extract_sni(data: bytes) -> Optional[str]:
        try:
            if data[0] != 0x16:   # TLS Handshake
                return None
            if data[5] != 0x01:   # ClientHello
                return None
            idx = 43
            idx += data[idx] + 1          # session id
            cs_len = struct.unpack("!H", data[idx:idx+2])[0]
            idx += 2 + cs_len
            cm_len = data[idx]
            idx += 1 + cm_len
            ext_len = struct.unpack("!H", data[idx:idx+2])[0]
            idx += 2
            end = idx + ext_len
            while idx < end:
                ext_type = struct.unpack("!H", data[idx:idx+2])[0]
                ext_data_len = struct.unpack("!H", data[idx+2:idx+4])[0]
                if ext_type == 0:  # SNI
                    sni_list_len = struct.unpack("!H", data[idx+4:idx+6])[0]
                    name_type    = data[idx+6]
                    name_len     = struct.unpack("!H", data[idx+7:idx+9])[0]
                    sni          = data[idx+9:idx+9+name_len].decode("utf-8", errors="ignore")
                    return sni
                idx += 4 + ext_data_len
        except Exception:
            pass
        return None


class FTPDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 21 and sport != 21:
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            up      = payload.upper()

            if up.startswith("USER "):
                user = payload[5:].strip()
                ev   = self._make_event("FTP", "FTP USER", src, sport, dst, dport,
                                       {"user": user}, severity="MEDIUM")
                if ev:
                    self._emit(ev, lambda e: _tag_line("FTP USER", C.YELLOW,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, user))
            elif up.startswith("PASS "):
                pw  = payload[5:].strip()
                ev  = self._make_event("FTP", "FTP PASS", src, sport, dst, dport,
                                      {"pass": pw}, severity="CRITICAL")
                if ev:
                    self._emit(ev, lambda e: _tag_line("FTP PASS", C.RED + C.BOLD,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, pw))
            elif up.startswith("PORT "):
                ev = self._make_event("FTP", "FTP PORT", src, sport, dst, dport,
                                      {"cmd": payload}, severity="LOW")
                if ev:
                    self._emit(ev, lambda e: _tag_line("FTP PORT", C.DIM + C.WHITE,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, payload))
        except Exception:
            pass


class SSHDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if 22 not in (sport, dport):
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
            if payload.startswith("SSH-"):
                banner_line = payload.splitlines()[0].strip()
                ev = self._make_event("SSH", "SSH BANNER", src, sport, dst, dport,
                                      {"banner": banner_line}, severity="LOW")
                if ev:
                    self._emit(ev, lambda e: _tag_line("SSH BANNER", C.BLUE,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, banner_line))
        except Exception:
            pass


class TelnetDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 23 and sport != 23:
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            fkey = FlowKey(src, dst, sport, dport, "TCP")
            full = self.flows.feed(fkey, pkt[Raw].load)
            text = full.decode("utf-8", errors="ignore")
            text_clean = re.sub(r"\xff[\xfa-\xff][\x00-\xff]*?\xff\xf0|[\x00-\x08\x0b-\x1f\x7f]", "", text)

            kws = ["password", "passwd", "login", "username"]
            if any(kw in text_clean.lower() for kw in kws):
                snippet = text_clean.strip()[:150]
                ev = self._make_event("TELNET", "TELNET CREDS?", src, sport, dst, dport,
                                      {"snippet": snippet}, severity="HIGH")
                if ev:
                    self._emit(ev, lambda e: _tag_line("TELNET CREDS?", C.RED,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, snippet[:100]))
        except Exception:
            pass


class SMTPDissector(Dissector):
    PORTS = frozenset([25, 465, 587])

    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in self.PORTS:
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            up      = payload.upper()

            if "AUTH LOGIN" in up:
                ev = self._make_event("SMTP", "SMTP AUTH LOGIN", src, sport, dst, dport,
                                      {"detail": "AUTH LOGIN sequence started"}, severity="HIGH")
                if ev:
                    self._emit(ev, lambda e: _tag_line("SMTP AUTH LOGIN", C.YELLOW,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port,
                                                       "AUTH LOGIN initiated"))

            if "AUTH PLAIN" in up:
                parts = payload.split()
                if len(parts) > 2:
                    try:
                        raw_b64 = parts[-1]
                        decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
                        creds   = decoded.split("\x00")
                        if len(creds) >= 3:
                            user = creds[1]
                            pw   = creds[2]
                            ev   = self._make_event("SMTP", "SMTP AUTH PLAIN",
                                                    src, sport, dst, dport,
                                                    {"user": user, "pass": pw},
                                                    severity="CRITICAL")
                            if ev:
                                self._emit(ev, lambda e: _tag_line("SMTP AUTH PLAIN",
                                                                   C.RED + C.BOLD,
                                                                   e.src_ip, e.src_port,
                                                                   e.dst_ip, e.dst_port,
                                                                   f"{user} : {pw}"))
                    except Exception:
                        pass

            # Base64 blob (mid-session AUTH LOGIN credential exchange)
            stripped = payload.strip()
            if (len(stripped) > 10 and
                    re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped)):
                try:
                    decoded = base64.b64decode(stripped).decode("utf-8", errors="ignore")
                    if "@" in decoded or ":" in decoded or len(decoded) > 3:
                        ev = self._make_event("SMTP", "SMTP BASE64 CRED",
                                              src, sport, dst, dport,
                                              {"decoded": decoded}, severity="HIGH")
                        if ev:
                            self._emit(ev, lambda e: _tag_line("SMTP BASE64",
                                                               C.RED, e.src_ip,
                                                               e.src_port, e.dst_ip,
                                                               e.dst_port, decoded[:80]))
                except Exception:
                    pass
        except Exception:
            pass


class POP3Dissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 110:
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            up      = payload.upper()

            if up.startswith("USER "):
                user = payload[5:].strip()
                ev   = self._make_event("POP3", "POP3 USER", src, sport, dst, dport,
                                       {"user": user}, severity="MEDIUM")
                if ev:
                    self._emit(ev, lambda e: _tag_line("POP3 USER", C.YELLOW,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, user))
            elif up.startswith("PASS "):
                pw  = payload[5:].strip()
                ev  = self._make_event("POP3", "POP3 PASS", src, sport, dst, dport,
                                      {"pass": pw}, severity="CRITICAL")
                if ev:
                    self._emit(ev, lambda e: _tag_line("POP3 PASS", C.RED + C.BOLD,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, pw))
            elif up.startswith("APOP "):
                ev = self._make_event("POP3", "POP3 APOP", src, sport, dst, dport,
                                      {"cmd": payload[:80]}, severity="MEDIUM")
                if ev:
                    self._emit(ev, lambda e: _tag_line("POP3 APOP", C.YELLOW,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port,
                                                       "MD5 challenge-response"))
        except Exception:
            pass


class IMAPDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in (143, 993):
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
            up      = payload.upper()

            if "LOGIN" in up:
                parts = payload.split(maxsplit=3)
                if len(parts) >= 4 and parts[1].upper() == "LOGIN":
                    user = parts[2].strip('"')
                    pw   = parts[3].strip('"')
                    ev   = self._make_event("IMAP", "IMAP LOGIN", src, sport, dst, dport,
                                           {"user": user, "pass": pw}, severity="CRITICAL")
                    if ev:
                        self._emit(ev, lambda e: _tag_line("IMAP LOGIN", C.RED + C.BOLD,
                                                           e.src_ip, e.src_port,
                                                           e.dst_ip, e.dst_port,
                                                           f"{user} : {pw}"))

            if "AUTHENTICATE PLAIN" in up or "AUTHENTICATE LOGIN" in up:
                ev = self._make_event("IMAP", "IMAP AUTHENTICATE", src, sport, dst, dport,
                                      {"cmd": payload[:80]}, severity="HIGH")
                if ev:
                    self._emit(ev, lambda e: _tag_line("IMAP AUTH", C.RED,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port,
                                                       payload[:60]))
        except Exception:
            pass


class LDAPDissector(Dissector):
    """Detects LDAP Simple Bind credentials (cleartext)."""
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in (389, 636):
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            raw = pkt[Raw].load
            # LDAP BindRequest: tag 0x60, within that look for simple auth (0x80)
            if len(raw) > 5 and raw[0] == 0x30:  # SEQUENCE
                text = raw.decode("latin-1", errors="ignore")
                # Crude heuristic: look for printable strings after 0x80 tag
                idx = raw.find(b"\x80")
                if idx > 0:
                    length = raw[idx+1]
                    cred   = raw[idx+2:idx+2+length].decode("utf-8", errors="ignore")
                    if cred and len(cred) > 1:
                        ev = self._make_event("LDAP", "LDAP BIND CRED", src, sport, dst, dport,
                                              {"credential": cred}, severity="CRITICAL")
                        if ev:
                            self._emit(ev, lambda e: _tag_line("LDAP BIND CRED", C.RED + C.BOLD,
                                                               e.src_ip, e.src_port,
                                                               e.dst_ip, e.dst_port, cred[:80]))
        except Exception:
            pass


class MySQLDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 3306 and sport != 3306:
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            raw = pkt[Raw].load
            # MySQL handshake Login Request: packet #1 from client, capability flags at offset 4
            if len(raw) > 36 and raw[3] == 0x01:  # sequence = 1 (client response)
                # Skip 4-byte header + 4-byte capability + 4 max_packet + 1 charset + 23 reserved
                offset = 4 + 4 + 4 + 1 + 23
                null   = raw.find(b"\x00", offset)
                if null > offset:
                    username = raw[offset:null].decode("utf-8", errors="ignore")
                    if username.isascii() and len(username) > 0:
                        ev = self._make_event("MYSQL", "MYSQL LOGIN", src, sport, dst, dport,
                                              {"user": username}, severity="HIGH")
                        if ev:
                            self._emit(ev, lambda e: _tag_line("MYSQL LOGIN", C.ORANGE,
                                                               e.src_ip, e.src_port,
                                                               e.dst_ip, e.dst_port,
                                                               f"user={username}"))
        except Exception:
            pass


class RedisDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 6379:
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
            if "AUTH" in payload.upper():
                lines = payload.splitlines()
                for i, line in enumerate(lines):
                    if line.strip().upper() == "AUTH" and i + 1 < len(lines):
                        pw  = lines[i+1].strip()
                        ev  = self._make_event("REDIS", "REDIS AUTH", src, sport, dst, dport,
                                              {"pass": pw}, severity="CRITICAL")
                        if ev:
                            self._emit(ev, lambda e: _tag_line("REDIS AUTH", C.RED + C.BOLD,
                                                               e.src_ip, e.src_port,
                                                               e.dst_ip, e.dst_port, pw))
        except Exception:
            pass


class RDPDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 3389:
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            raw = pkt[Raw].load
            # RDP Connection Request (TPKT + COTP + X.224)
            if len(raw) > 11 and raw[0] == 0x03 and raw[1] == 0x00:
                ev = self._make_event("RDP", "RDP CONNECT", src, sport, dst, dport,
                                      {"note": "RDP connection request"}, severity="LOW")
                if ev:
                    self._emit(ev, lambda e: _tag_line("RDP CONNECT", C.BLUE,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port,
                                                       "RDP connection attempt"))
        except Exception:
            pass


class NTLMDissector(Dissector):
    """Detects NTLM messages embedded in any protocol."""
    NTLM_SIG = b"NTLMSSP\x00"

    def process(self, pkt) -> None:
        if not pkt.haslayer(Raw):
            return
        raw = pkt[Raw].load
        if self.NTLM_SIG not in raw:
            return
        try:
            src   = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst   = pkt[IP].dst if pkt.haslayer(IP) else "?"
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else 0
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else 0
            idx   = raw.index(self.NTLM_SIG)
            msg_type = struct.unpack("<I", raw[idx+8:idx+12])[0] if len(raw) > idx+12 else 0
            type_str  = {1: "NEGOTIATE", 2: "CHALLENGE", 3: "AUTHENTICATE"}.get(msg_type, f"TYPE{msg_type}")
            ev = self._make_event("NTLM", f"NTLM {type_str}", src, sport, dst, dport,
                                  {"type": type_str}, severity="HIGH")
            if ev:
                self._emit(ev, lambda e: _tag_line(f"NTLM {type_str}", C.PINK,
                                                   e.src_ip, e.src_port,
                                                   e.dst_ip, e.dst_port,
                                                   f"NTLM {type_str} detected"))
        except Exception:
            pass


class SIPDissector(Dissector):
    def process(self, pkt) -> None:
        if not pkt.haslayer(Raw):
            return
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        if dport not in (5060, 5061):
            return
        try:
            src     = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst     = pkt[IP].dst if pkt.haslayer(IP) else "?"
            sport   = pkt[TCP].sport if pkt.haslayer(TCP) else 0
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
            if "Authorization:" in payload or "Proxy-Authorization:" in payload:
                for line in payload.splitlines():
                    if "Authorization:" in line or "Proxy-Authorization:" in line:
                        ev = self._make_event("SIP", "SIP AUTH", src, sport, dst, dport,
                                              {"header": line.strip()[:150]}, severity="HIGH")
                        if ev:
                            self._emit(ev, lambda e: _tag_line("SIP AUTH", C.LIME,
                                                               e.src_ip, e.src_port,
                                                               e.dst_ip, e.dst_port,
                                                               line.strip()[:80]))
        except Exception:
            pass


class MQTTDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in (1883, 8883):
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            raw = pkt[Raw].load
            # MQTT CONNECT: first byte = 0x10
            if len(raw) > 10 and raw[0] == 0x10:
                # Parse protocol name length
                proto_len = struct.unpack("!H", raw[4:6])[0]
                proto_name = raw[6:6+proto_len].decode("utf-8", errors="ignore")
                if proto_name in ("MQTT", "MQIsdp"):
                    conn_flags = raw[9] if len(raw) > 9 else 0
                    has_user   = bool(conn_flags & 0x80)
                    has_pass   = bool(conn_flags & 0x40)
                    idx = 12 + proto_len  # skip fixed fields
                    # Skip client ID
                    cid_len = struct.unpack("!H", raw[idx:idx+2])[0]
                    idx += 2 + cid_len
                    user = pw = ""
                    if has_user and idx + 2 <= len(raw):
                        u_len = struct.unpack("!H", raw[idx:idx+2])[0]
                        user  = raw[idx+2:idx+2+u_len].decode("utf-8", errors="ignore")
                        idx  += 2 + u_len
                    if has_pass and idx + 2 <= len(raw):
                        p_len = struct.unpack("!H", raw[idx:idx+2])[0]
                        pw    = raw[idx+2:idx+2+p_len].decode("utf-8", errors="ignore")

                    ev = self._make_event("MQTT", "MQTT CONNECT",
                                         src, sport, dst, dport,
                                         {"user": user, "pass": pw, "clientid": ""},
                                         severity="CRITICAL" if pw else "HIGH")
                    if ev:
                        self._emit(ev, lambda e: _tag_line("MQTT CONNECT", C.RED + C.BOLD,
                                                           e.src_ip, e.src_port,
                                                           e.dst_ip, e.dst_port,
                                                           f"{user} : {pw}"))
        except Exception:
            pass


class KerberosDissector(Dissector):
    def process(self, pkt) -> None:
        if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport
        if dport != 88 and sport != 88:
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            raw = pkt[Raw].load
            # Kerberos AS-REQ: application tag 0x6a (APPLICATION 10)
            if len(raw) > 10 and raw[4] == 0x6a:
                ev = self._make_event("KERBEROS", "KRB5 AS-REQ",
                                      src, sport, dst, dport,
                                      {"note": "Kerberos AS-REQ detected"}, severity="MEDIUM")
                if ev:
                    self._emit(ev, lambda e: _tag_line("KRB5 AS-REQ", C.TEAL,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port,
                                                       "Authentication Service Request"))
            elif len(raw) > 10 and raw[4] == 0x6c:  # TGS-REQ
                ev = self._make_event("KERBEROS", "KRB5 TGS-REQ",
                                      src, sport, dst, dport,
                                      {"note": "Kerberos TGS-REQ detected"}, severity="MEDIUM")
                if ev:
                    self._emit(ev, lambda e: _tag_line("KRB5 TGS-REQ", C.TEAL,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port,
                                                       "Ticket Granting Service Request"))
        except Exception:
            pass


class ModbusDissector(Dissector):
    FUNCTION_CODES = {
        1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Regs",
        4: "Read Input Regs", 5: "Write Single Coil", 6: "Write Single Reg",
        15: "Write Multiple Coils", 16: "Write Multiple Regs",
    }
    def process(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 502:
            return
        try:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            raw = pkt[Raw].load
            if len(raw) >= 8:
                func_code = raw[7]
                desc = self.FUNCTION_CODES.get(func_code, f"FC {func_code}")
                ev = self._make_event("MODBUS", "MODBUS FC",
                                      src, sport, dst, dport,
                                      {"function": desc}, severity="LOW")
                if ev:
                    self._emit(ev, lambda e: _tag_line("MODBUS FC", C.GREY,
                                                       e.src_ip, e.src_port,
                                                       e.dst_ip, e.dst_port, desc))
        except Exception:
            pass


class GenericCredHunter(Dissector):
    """Last-resort keyword-based credential hunter on all ports."""
    def process(self, pkt) -> None:
        if not pkt.haslayer(Raw):
            return
        try:
            src   = pkt[IP].src  if pkt.haslayer(IP)  else "?"
            dst   = pkt[IP].dst  if pkt.haslayer(IP)  else "?"
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)

            raw  = pkt[Raw].load
            text = raw.decode("utf-8", errors="ignore")
            text_lower = text.lower()

            hits = [kw for kw in CRED_KEYWORDS if kw in text_lower]
            if not hits:
                return

            lines = [
                line.strip()[:120]
                for line in text.splitlines()
                if any(kw in line.lower() for kw in hits)
            ]
            if not lines:
                return

            snippet = " | ".join(lines[:3])
            proto   = self._guess_proto(dport)
            ev      = self._make_event(proto, "POSSIBLE CREDS",
                                       src, sport, dst, dport,
                                       {"keywords": hits[:5], "snippet": snippet},
                                       severity="MEDIUM")
            if ev:
                self._emit(ev, lambda e: _tag_line(f"POSSIBLE CREDS/{proto}",
                                                   C.RED + C.BOLD,
                                                   e.src_ip, e.src_port,
                                                   e.dst_ip, e.dst_port, snippet[:100]))
        except Exception:
            pass

    @staticmethod
    def _guess_proto(dport: int) -> str:
        for proto, ports in PROTO_PORTS.items():
            if dport in ports:
                return proto
        return "GENERIC"


# ════════════════════════════════════════════════════════════════════════════════
#  ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class OctopusEngine:
    def __init__(self, cfg: dict):
        self.cfg    = cfg
        self.logger = Logger(cfg["log_file"], cfg["json_log"], cfg.get("quiet", False))
        self.geo    = GeoLookup(cfg.get("geoip_db"))
        self.dedup  = Deduplicator(cfg.get("dedup_ttl", 300))
        self.flows  = FlowTracker(cfg.get("max_flow_bytes", 65536))
        self.dash   = Dashboard()
        self._captured_pkts: List = []
        self._pcap_out = cfg.get("pcap_out")

        args = (self.logger, self.geo, self.dedup, self.flows, cfg)
        enabled = set(cfg.get("protocols", list(PROTO_PORTS.keys())))

        self.dissectors: List[Dissector] = []
        mapping = {
            "DNS":      DNSDissector,
            "HTTP":     HTTPDissector,
            "HTTPS":    HTTPSDissector,
            "FTP":      FTPDissector,
            "SSH":      SSHDissector,
            "TELNET":   TelnetDissector,
            "SMTP":     SMTPDissector,
            "POP3":     POP3Dissector,
            "IMAP":     IMAPDissector,
            "LDAP":     LDAPDissector,
            "MYSQL":    MySQLDissector,
            "REDIS":    RedisDissector,
            "RDP":      RDPDissector,
            "SIP":      SIPDissector,
            "MQTT":     MQTTDissector,
            "KERBEROS": KerberosDissector,
            "MODBUS":   ModbusDissector,
        }
        for name, cls in mapping.items():
            if name in enabled:
                self.dissectors.append(cls(*args))

        # NTLM and Generic run always
        self.dissectors.append(NTLMDissector(*args))
        self.dissectors.append(GenericCredHunter(*args))

    def handle(self, pkt) -> None:
        STATS.pkt()
        if self._pcap_out:
            self._captured_pkts.append(pkt)
        for d in self.dissectors:
            d.process(pkt)

    def _build_bpf(self) -> str:
        parts = []
        enabled = set(self.cfg.get("protocols", list(PROTO_PORTS.keys())))
        for proto in enabled:
            ports = PROTO_PORTS.get(proto, [])
            for p in ports:
                layer = "udp" if proto == "DNS" else "tcp"
                parts.append(f"{layer} port {p}")
        return " or ".join(parts) if parts else ""

    def run_live(self, iface: str) -> None:
        bpf = self._build_bpf()
        ok(f"Interface : {clr(iface, C.CYAN)}")
        ok(f"Log file  : {clr(self.cfg['log_file'], C.CYAN)}")
        ok(f"JSON log  : {clr(self.cfg['json_log'], C.CYAN)}")
        ok(f"Protocols : {clr(', '.join(self.cfg.get('protocols', [])), C.CYAN)}")
        if self._pcap_out:
            ok(f"PCAP out  : {clr(self._pcap_out, C.CYAN)}")
        info(clr("Press Ctrl+C to stop capture", C.YELLOW))
        print()
        hr()
        print()

        self.dash.start()
        try:
            sniff(iface=iface, prn=self.handle, filter=bpf, store=False)
        except PermissionError:
            err("Permission denied — run as root.")
        finally:
            self._shutdown()

    def run_pcap(self, pcap_path: str) -> None:
        ok(f"Analyzing PCAP : {clr(pcap_path, C.CYAN)}")
        info("Offline mode — no root required")
        print()
        hr()
        print()
        try:
            pkts = rdpcap(pcap_path)
            info(f"Loaded {len(pkts)} packets from {pcap_path}")
            for pkt in pkts:
                self.handle(pkt)
        except Exception as e:
            err(f"Failed to read PCAP: {e}")
        finally:
            self._shutdown()

    def _shutdown(self) -> None:
        self.dash.stop()
        self.logger.stop()
        if self._pcap_out and self._captured_pkts:
            try:
                wrpcap(self._pcap_out, self._captured_pkts)
                ok(f"PCAP saved → {self._pcap_out}")
            except Exception as e:
                err(f"Failed to write PCAP: {e}")
        self._print_summary()

    def _print_summary(self) -> None:
        snap = STATS.snapshot()
        print()
        hr("═")
        print(clr(f"  SESSION SUMMARY — {snap['uptime']}", C.BOLD + C.CYAN))
        hr()
        print(f"  {clr('Total Packets :', C.DIM)}  {clr(str(snap['packets']), C.WHITE)}")
        print(f"  {clr('Credentials   :', C.DIM)}  {clr(str(snap['creds']), C.RED + C.BOLD)}")
        print(f"  {clr('Events Logged :', C.DIM)}  {clr(str(snap['events']), C.YELLOW)}")
        print(f"  {clr('Alerts Fired  :', C.DIM)}  {clr(str(snap['alerts']), C.ORANGE)}")
        if snap["by_proto"]:
            print()
            print(f"  {clr('Hits by Protocol:', C.DIM)}")
            for proto, count in sorted(snap["by_proto"].items(), key=lambda x: -x[1]):
                bar = "█" * min(count, 40)
                print(f"    {clr(proto.ljust(16), C.CYAN)} {clr(bar, C.MAGENTA)} {clr(str(count), C.WHITE)}")
        if snap["top_src"]:
            print()
            print(f"  {clr('Top Sources:', C.DIM)}")
            for ip, count in snap["top_src"]:
                print(f"    {clr(ip.ljust(18), C.ORANGE)}  {clr(str(count), C.WHITE)} hits")
        hr("═")
        print()


# ════════════════════════════════════════════════════════════════════════════════
#  INTERFACE SELECTOR
# ════════════════════════════════════════════════════════════════════════════════

def select_interface() -> str:
    section("Available Interfaces")
    ifaces = get_if_list()
    for i, iface in enumerate(ifaces, 1):
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "?"
        print(f"  {clr(f'[{i}]', C.GREEN)}  {clr(iface.ljust(18), C.WHITE)}  {clr(ip, C.DIM)}")
    print()
    while True:
        try:
            choice = int(input(clr("  [»] Select interface number → ", C.CYAN)).strip())
            if 1 <= choice <= len(ifaces):
                return ifaces[choice - 1]
            err(f"Choose between 1 and {len(ifaces)}.")
        except ValueError:
            err("Enter a valid number.")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)


def select_protocols() -> List[str]:
    section("Protocol Selection")
    all_p = list(PROTO_PORTS.keys())
    for i, p in enumerate(all_p, 1):
        ports = ",".join(str(x) for x in PROTO_PORTS[p][:4])
        print(f"  {clr(f'[{i:2d}]', C.GREEN)}  {clr(p.ljust(12), C.WHITE)}  {clr(f'port {ports}', C.DIM)}")
    print(f"  {clr('[A]', C.CYAN)}   All protocols (default)")
    print()
    raw = input(clr("  [»] Enter numbers (comma-sep) or A for all: ", C.CYAN)).strip()
    if not raw or raw.upper() == "A":
        return all_p
    selected = []
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit():
            idx = int(tok) - 1
            if 0 <= idx < len(all_p):
                selected.append(all_p[idx])
    return selected if selected else all_p


# ════════════════════════════════════════════════════════════════════════════════
#  DECODE LAB  (offline multi-codec decoder)
# ════════════════════════════════════════════════════════════════════════════════

def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for x in b if 9 <= x <= 13 or 32 <= x <= 126)
    return printable / len(b)

def _fmt_bytes(b: bytes) -> str:
    if _printable_ratio(b) >= 0.85:
        return b.decode("utf-8", errors="replace")
    return b.hex(" ")

def _decode_attempts(raw: bytes):
    """Return list of (codec, ok, output-str) attempts for the given bytes."""
    import binascii, gzip, zlib, codecs, urllib.parse
    results = []
    text = raw.decode("utf-8", errors="ignore").strip()

    # base64 (standard)
    try:
        dec = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
        if dec and _printable_ratio(dec) >= 0.6:
            results.append(("base64", True, _fmt_bytes(dec)))
    except Exception:
        pass
    # base64 url-safe
    try:
        dec = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        if dec and _printable_ratio(dec) >= 0.6 and ("-" in text or "_" in text):
            results.append(("base64url", True, _fmt_bytes(dec)))
    except Exception:
        pass
    # hex
    try:
        cleaned = text.replace(" ", "").replace("\n", "")
        if len(cleaned) >= 2 and len(cleaned) % 2 == 0:
            dec = bytes.fromhex(cleaned)
            results.append(("hex", True, _fmt_bytes(dec)))
    except Exception:
        pass
    # URL percent-encoding
    try:
        if "%" in text:
            dec = urllib.parse.unquote_to_bytes(text)
            if dec != raw:
                results.append(("url-decode", True, _fmt_bytes(dec)))
    except Exception:
        pass
    # ROT13
    try:
        results.append(("rot13", True, codecs.decode(text, "rot_13")))
    except Exception:
        pass
    # gzip
    try:
        if raw[:2] == b"\x1f\x8b":
            results.append(("gzip", True, _fmt_bytes(gzip.decompress(raw))))
    except Exception:
        pass
    # zlib
    try:
        results.append(("zlib", True, _fmt_bytes(zlib.decompress(raw))))
    except Exception:
        pass
    return results

def _smart_recursive_b64(text: str, depth: int = 8):
    """Peel repeated base64 layers; return list of (layer, decoded-text)."""
    import re as _re
    layers = []
    cur = text.strip()
    for i in range(depth):
        if len(cur) < 4 or not _re.fullmatch(r"[A-Za-z0-9+/_\-]+=*", cur):
            break
        try:
            dec = base64.b64decode(cur + "=" * (-len(cur) % 4), validate=False)
        except Exception:
            break
        if not dec or _printable_ratio(dec) < 0.6:
            break
        txt = dec.decode("utf-8", errors="replace")
        layers.append((i + 1, txt))
        cur = txt.strip()
    return layers

def decode_lab() -> None:
    section("Offline Multi-Codec Decoder")
    print(f"  {clr('[1]', C.GREEN)}  Decode a string (auto-detect all codecs)")
    print(f"  {clr('[2]', C.GREEN)}  Decode a file")
    print(f"  {clr('[3]', C.GREEN)}  Smart recursive base64 (peel nested layers)")
    print()
    try:
        sel = input(clr("  [»] Select [1-3]: ", C.CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        return

    if sel == "1":
        data = input(clr("  [»] Input string: ", C.CYAN)).encode("utf-8", "ignore")
        attempts = _decode_attempts(data)
        section("Decode Results")
        if not attempts:
            warn("No codec produced a plausible decode.")
            return
        for codec, okflag, out in attempts:
            print(f"  {clr(f'[{codec}]', C.TEAL):<24} {clr(out[:400], C.WHITE)}")

    elif sel == "2":
        path = input(clr("  [»] File path: ", C.CYAN)).strip()
        if not Path(path).is_file():
            err(f"File not found: {path}")
            return
        try:
            raw = Path(path).read_bytes()
        except Exception as ex:
            err(f"Cannot read file: {ex}")
            return
        attempts = _decode_attempts(raw[:1_000_000])
        section("Decode Results")
        if not attempts:
            warn("No codec produced a plausible decode.")
            return
        for codec, okflag, out in attempts:
            print(f"  {clr(f'[{codec}]', C.TEAL):<24} {clr(out[:400], C.WHITE)}")

    elif sel == "3":
        data = input(clr("  [»] Base64 string: ", C.CYAN)).strip()
        layers = _smart_recursive_b64(data)
        section("Recursive Decode Layers")
        if not layers:
            warn("No base64 layers detected.")
            return
        for depth, txt in layers:
            print(f"  {clr(f'Layer {depth}', C.ORANGE):<18} {clr(txt[:400], C.WHITE)}")
    else:
        err("Unknown selection.")


# ════════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════════════════════════

MENU_ITEMS = [
    ("1", C.GREEN,  "Live Capture",       "Sniff on a network interface"),
    ("2", C.BLUE,   "Analyze PCAP",       "Offline analysis of a .pcap file"),
    ("3", C.CYAN,   "Export Report",      "Convert events to CSV / HTML / JSON"),
    ("4", C.YELLOW, "View Statistics",    "Show session / log statistics"),
    ("5", C.MAGENTA,"Decode Lab",         "Offline base64/hex/url/gzip decoder"),
    ("H", C.YELLOW, "Help",               "Protocols, tags, and usage guide"),
    ("0", C.RED,    "Exit",               "Quit OCTOPUS"),
]


def draw_menu() -> None:
    for key, clr_code, label, desc in MENU_ITEMS:
        print(
            f"  {clr(f'[{key}]', clr_code)}"
            f"  {clr(label.ljust(20), C.WHITE)}"
            f"  {clr(desc, C.DIM)}"
        )


def main_menu(args: argparse.Namespace) -> None:
    # Non-interactive fast-path: interface provided via CLI
    if args.interface or args.pcap:
        cfg = build_config(args)
        engine = OctopusEngine(cfg)
        if args.pcap:
            engine.run_pcap(args.pcap)
        else:
            engine.run_live(args.interface)
        if args.export:
            out = args.out or f"octopus_report.{args.export}"
            Exporter.export(args.export, cfg["json_log"], out)
        return

    # Interactive TUI loop
    while True:
        clear_screen()
        banner("Interactive Mode")
        draw_menu()
        print()
        hr()

        try:
            choice = input(clr("\n  [»] Select option: ", C.CYAN)).strip().upper()
        except (EOFError, KeyboardInterrupt):
            choice = "0"

        if choice == "0":
            print(clr(f"\n  [✔] Goodbye! — {WEBSITE}\n", C.GREEN))
            sys.exit(0)

        elif choice == "H":
            clear_screen()
            banner()
            show_help()
            pause()

        elif choice == "1":
            clear_screen()
            banner("Live Capture")
            if os.getuid() != 0:
                err("Live capture requires root privileges.")
                pause()
                continue
            iface     = select_interface()
            protocols = select_protocols()
            log_file  = input(clr("\n  [»] Log file (Enter=octopus.log): ", C.CYAN)).strip() or "octopus.log"
            json_file = input(clr("  [»] JSON file (Enter=octopus_events.json): ", C.CYAN)).strip() or "octopus_events.json"
            pcap_out  = input(clr("  [»] Write PCAP to (Enter=skip): ", C.CYAN)).strip() or None

            cfg = {**DEFAULT_CONFIG,
                   "log_file": log_file, "json_log": json_file,
                   "protocols": protocols, "pcap_out": pcap_out}
            section("Starting Capture")
            engine = OctopusEngine(cfg)
            try:
                engine.run_live(iface)
            except KeyboardInterrupt:
                pass

            exp = input(clr("\n  [»] Export report? (json/csv/html/skip): ", C.CYAN)).strip().lower()
            if exp in ("json", "csv", "html"):
                out_path = input(clr(f"  [»] Output path (Enter=octopus_report.{exp}): ", C.CYAN)).strip()
                if not out_path:
                    out_path = f"octopus_report.{exp}"
                Exporter.export(exp, json_file, out_path)
            pause()

        elif choice == "2":
            clear_screen()
            banner("PCAP Analysis")
            pcap_path = input(clr("  [»] PCAP file path: ", C.CYAN)).strip()
            if not Path(pcap_path).exists():
                err(f"File not found: {pcap_path}")
                pause()
                continue
            protocols = select_protocols()
            cfg = {**DEFAULT_CONFIG, "protocols": protocols}
            engine = OctopusEngine(cfg)
            engine.run_pcap(pcap_path)

            exp = input(clr("\n  [»] Export? (json/csv/html/skip): ", C.CYAN)).strip().lower()
            if exp in ("json", "csv", "html"):
                out_path = input(clr(f"  [»] Output path: ", C.CYAN)).strip() or f"octopus_report.{exp}"
                Exporter.export(exp, cfg["json_log"], out_path)
            pause()

        elif choice == "3":
            clear_screen()
            banner("Export Report")
            json_src = input(clr("  [»] Source JSON events file (Enter=octopus_events.json): ", C.CYAN)).strip() or "octopus_events.json"
            fmt      = input(clr("  [»] Format (json/csv/html): ", C.CYAN)).strip().lower()
            if fmt not in ("json", "csv", "html"):
                err("Unknown format. Use json, csv, or html.")
                pause()
                continue
            out_path = input(clr(f"  [»] Output file: ", C.CYAN)).strip() or f"octopus_report.{fmt}"
            Exporter.export(fmt, json_src, out_path)
            pause()

        elif choice == "4":
            clear_screen()
            banner("Statistics")
            snap = STATS.snapshot()
            info(f"Packets captured : {clr(str(snap['packets']), C.WHITE)}")
            info(f"Credentials found: {clr(str(snap['creds']), C.RED + C.BOLD)}")
            info(f"Total events     : {clr(str(snap['events']), C.YELLOW)}")
            info(f"Alerts fired     : {clr(str(snap['alerts']), C.ORANGE)}")
            info(f"Uptime           : {clr(snap['uptime'], C.CYAN)}")
            if snap["by_proto"]:
                section("Hits by Protocol")
                for p, n in sorted(snap["by_proto"].items(), key=lambda x: -x[1]):
                    print(f"    {clr(p.ljust(14), C.CYAN)}  {clr(str(n), C.WHITE)}")
            pause()

        elif choice == "5":
            clear_screen()
            banner("Decode Lab")
            decode_lab()
            pause()

        else:
            err("Invalid option. Press H for help.")
            pause()


# ════════════════════════════════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER
# ════════════════════════════════════════════════════════════════════════════════

def build_config(args: argparse.Namespace) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg["log_file"]  = args.log     if args.log     else DEFAULT_CONFIG["log_file"]
    cfg["json_log"]  = args.json    if args.json    else DEFAULT_CONFIG["json_log"]
    cfg["pcap_out"]  = args.write_pcap
    cfg["geoip_db"]  = args.geoip
    cfg["verbose"]   = args.verbose
    cfg["quiet"]     = args.quiet
    cfg["dedup_ttl"] = args.dedup_ttl
    if not args.color:
        C.disable()
    if args.protocols:
        requested = [p.strip().upper() for p in args.protocols.split(",")]
        cfg["protocols"] = [p for p in requested if p in PROTO_PORTS]
        if not cfg["protocols"]:
            cfg["protocols"] = list(PROTO_PORTS.keys())
    return cfg


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="octopus",
        description=f"OCTOPUS v{VERSION} — Tactical Traffic Dissector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--interface",  metavar="IFACE")
    p.add_argument("-l", "--log",        metavar="FILE",    default=None)
    p.add_argument(      "--json",       metavar="FILE",    default=None)
    p.add_argument(      "--pcap",       metavar="FILE",    default=None)
    p.add_argument(      "--write-pcap", metavar="FILE",    default=None, dest="write_pcap")
    p.add_argument(      "--protocols",  metavar="PROTOS",  default=None)
    p.add_argument(      "--geoip",      metavar="DB",      default=None)
    p.add_argument(      "--export",     metavar="FORMAT",  choices=["json","csv","html"], default=None)
    p.add_argument(      "--out",        metavar="FILE",    default=None)
    p.add_argument(      "--dedup-ttl",  metavar="SECS",    type=int, default=300, dest="dedup_ttl")
    p.add_argument(      "--no-color",   action="store_false", dest="color", default=True)
    p.add_argument(      "--quiet",      action="store_true", default=False)
    p.add_argument(      "--verbose",    action="store_true", default=False)
    return p.parse_args()


# ════════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════════

def main() -> None:
    args = parse_args()

    if not args.color:
        C.disable()

    if not SCAPY_OK:
        print("ERROR: scapy is not installed. Install with: pip install scapy")
        sys.exit(1)

    # Silence scapy noise
    import logging as _logging
    _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
    scapy_conf.verb = 0

    clear_screen()
    banner()

    # Root check for live capture
    if args.interface and os.getuid() != 0:
        err("Live capture requires root / sudo.")
        sys.exit(1)

    try:
        main_menu(args)
    except KeyboardInterrupt:
        print(clr(f"\n\n  [✔] OCTOPUS stopped. — {WEBSITE}\n", C.YELLOW))
    except Exception as e:
        err(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
