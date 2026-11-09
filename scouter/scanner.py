"""Port scanning and service identification.

Two backends:

* ``socket`` - pure standard library TCP connect scan with banner grabbing.
  Works anywhere (including Termux without root).
* ``nmap``   - wraps ``nmap -sT -sV`` (no root needed) for better service
  detection when nmap is installed.

Scouter only performs TCP connect scans. It never sends exploit payloads.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional, Tuple


class ScanError(RuntimeError):
    """Raised when a backend cannot complete a scan."""


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @property
    def label(self) -> str:
        detail = " ".join(p for p in (self.product, self.version) if p)
        return "%s (%s)" % (self.name, detail) if detail else self.name


# --------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------

COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3000: "http", 3306: "mysql", 3389: "ms-wbt-server",
    5000: "http", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http", 8080: "http-proxy", 8443: "https", 8888: "http",
    9200: "elasticsearch", 27017: "mongodb",
}

DEFAULT_PORTS: List[int] = sorted(COMMON_PORTS)

TLS_PORTS = {443, 465, 636, 993, 995, 8443}
HTTP_PORTS = {80, 3000, 5000, 8000, 8080, 8888, 9200}


def parse_ports(spec: str) -> List[int]:
    """Parse ``22,80,8000-8100``, ``top`` or ``all`` into a sorted port list."""
    spec = spec.strip().lower()
    if spec in ("top", "default"):
        return list(DEFAULT_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                low_text, high_text = part.split("-", 1)
                low, high = int(low_text), int(high_text)
                if low > high:
                    raise ValueError
                ports.update(range(low, high + 1))
            else:
                ports.add(int(part))
        except ValueError:
            raise ValueError("invalid port spec: %r" % part)
    if not ports:
        raise ValueError("no ports given")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def ports_to_spec(ports: List[int]) -> str:
    """Compress a port list into nmap's ``-p`` syntax (``22,80-90``)."""
    ports = sorted(set(ports))
    if not ports:
        return ""
    ranges: List[Tuple[int, int]] = []
    start = prev = ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append((start, prev))
        start = prev = port
    ranges.append((start, prev))
    return ",".join(str(a) if a == b else "%d-%d" % (a, b) for a, b in ranges)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe limiter: at most ``rate`` connection attempts per second."""

    def __init__(self, rate: float = 0):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


# --------------------------------------------------------------------------
# Service identification
# --------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_SSH_RE = re.compile(r"^SSH-[\d.]+-([A-Za-z]+)[_-]?([\w.]+)?")
_SERVER_RE = re.compile(r"^server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def clean_banner(data: bytes, limit: int = 200) -> str:
    text = data.decode("latin-1", "replace")
    text = _CONTROL.sub("", text.replace("\r", "")).strip()
    return text[:limit]


def identify(port: int, banner: str) -> Tuple[str, str, str]:
    """Return ``(name, product, version)`` from a banner, falling back to the port."""
    first = banner.split("\n", 1)[0].strip()
    upper = first.upper()
    if first.startswith("SSH-"):
        match = _SSH_RE.match(first)
        product = match.group(1) if match else ""
        version = (match.group(2) or "") if match else ""
        return "ssh", product, version
    if first.startswith("HTTP/"):
        match = _SERVER_RE.search(banner)
        server = match.group(1).strip() if match else ""
        product, _, version = server.partition("/")
        return "http", product.strip(), version.split(" ")[0].strip()
    if upper.startswith("220") and "FTP" in upper:
        return "ftp", "", ""
    if upper.startswith("220") and "SMTP" in upper:
        return "smtp", "", ""
    if upper.startswith("+OK"):
        return "pop3", "", ""
    if upper.startswith("* OK"):
        return "imap", "", ""
    return COMMON_PORTS.get(port, "unknown"), "", ""


# --------------------------------------------------------------------------
# Socket backend
# --------------------------------------------------------------------------

def _grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    sock.settimeout(min(timeout, 1.5))
    try:
        if port in HTTP_PORTS:
            request = "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: scouter\r\n\r\n" % host
            sock.sendall(request.encode("ascii", "ignore"))
        elif port in TLS_PORTS:
            return ""  # TLS handshake is out of scope for the socket backend
        return clean_banner(sock.recv(512))
    except (socket.timeout, OSError):
        return ""


def _probe(host: str, port: int, timeout: float, limiter: RateLimiter) -> Optional[Service]:
    limiter.wait()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = _grab_banner(sock, host, port, timeout)
    except OSError:
        return None
    name, product, version = identify(port, banner)
    return Service(port=port, name=name, product=product, version=version, banner=banner)


def scan_socket(
    host: str,
    ports: List[int],
    threads: int = 50,
    timeout: float = 1.5,
    rate: float = 0,
    on_open: Optional[Callable[[Service], None]] = None,
) -> List[Service]:
    limiter = RateLimiter(rate)
    found: List[Service] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        for service in pool.map(lambda p: _probe(host, p, timeout, limiter), ports):
            if service is not None:
                found.append(service)
                if on_open:
                    on_open(service)
    return sorted(found, key=lambda s: s.port)


# --------------------------------------------------------------------------
# nmap backend
# --------------------------------------------------------------------------

def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def parse_nmap_xml(xml_text: str) -> List[Service]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError("could not parse nmap output: %s" % exc)
    services: List[Service] = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        attrs = svc.attrib if svc is not None else {}
        extra = attrs.get("extrainfo", "")
        services.append(Service(
            port=int(port.get("portid", "0")),
            proto=port.get("protocol", "tcp"),
            name=attrs.get("name", "unknown"),
            product=attrs.get("product", ""),
            version=attrs.get("version", ""),
            banner=extra,
        ))
    return sorted(services, key=lambda s: s.port)


def scan_nmap(
    host: str,
    ports: List[int],
    rate: float = 0,
    timeout: int = 900,
) -> Tuple[List[Service], str]:
    """Run nmap (TCP connect + version detection). Returns (services, raw_xml)."""
    cmd = ["nmap", "-sT", "-sV", "-Pn", "--open", "-p", ports_to_spec(ports), "-oX", "-"]
    if rate and rate > 0:
        cmd += ["--max-rate", str(int(max(1, rate)))]
    cmd.append(host)  # host was validated by scouter.scope.validate_target
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError("nmap timed out after %ds" % timeout)
    except OSError as exc:
        raise ScanError("could not run nmap: %s" % exc)
    if proc.returncode != 0:
        raise ScanError("nmap failed: %s" % (proc.stderr.strip() or proc.returncode))
    return parse_nmap_xml(proc.stdout), proc.stdout
