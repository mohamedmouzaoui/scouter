"""Scope handling: the authorization guard of Scouter.

A scope file lists what you are *allowed* to scan. Scouter refuses to touch
anything that does not match an include rule, or that matches an exclude rule
(prefixed with ``!``).

Supported rules (one per line, ``#`` starts a comment)::

    192.168.56.10        single IP
    10.10.10.0/28        CIDR range
    app.example.com      exact hostname
    *.example.com        wildcard (subdomains only)
    !10.10.10.5          exclusion (always wins)
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional


class ScopeError(ValueError):
    """Raised for invalid scope rules or targets."""


_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(r"^(?=.{1,253}$)%s(?:\.%s)*$" % (_LABEL, _LABEL))


@dataclass
class ScopeRule:
    raw: str
    kind: str  # "ip" | "cidr" | "host" | "wildcard"
    network: Optional[object] = None  # ipaddress network
    host: Optional[str] = None


def parse_rule(text: str) -> ScopeRule:
    raw = text.strip()
    if not raw:
        raise ScopeError("empty rule")
    if raw.startswith("*."):
        suffix = raw[2:].lower()
        if not _HOST_RE.match(suffix):
            raise ScopeError("invalid wildcard rule: %r" % raw)
        return ScopeRule(raw, "wildcard", host=suffix)
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        net = None
    if net is not None:
        kind = "ip" if net.num_addresses == 1 else "cidr"
        return ScopeRule(raw, kind, network=net)
    if _HOST_RE.match(raw):
        return ScopeRule(raw, "host", host=raw.lower())
    raise ScopeError("invalid scope rule: %r" % raw)


def validate_target(target: str) -> str:
    """Return a normalised target or raise ScopeError.

    Targets are validated strictly so they can never look like a command-line
    option (e.g. ``-oN``) when passed to an external tool.
    """
    t = target.strip().rstrip(".")
    if not t:
        raise ScopeError("empty target")
    try:
        ipaddress.ip_address(t)
        return t
    except ValueError:
        pass
    if _HOST_RE.match(t):
        return t.lower()
    raise ScopeError("invalid target: %r" % target)


def resolve(target: str) -> Optional[str]:
    """Resolve a hostname to an IP string (IPs are returned unchanged)."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    return infos[0][4][0] if infos else None


def _as_ip(value: Optional[str]):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _matches(rule: ScopeRule, target: str, ip: Optional[str]) -> bool:
    if rule.kind in ("ip", "cidr"):
        addr = _as_ip(ip) or _as_ip(target)
        return addr is not None and addr in rule.network
    name = target.lower().rstrip(".")
    if rule.kind == "host":
        return name == rule.host
    if rule.kind == "wildcard":
        return name.endswith("." + rule.host)
    return False


class Scope:
    def __init__(self, includes: Iterable[ScopeRule], excludes: Iterable[ScopeRule]):
        self.includes: List[ScopeRule] = list(includes)
        self.excludes: List[ScopeRule] = list(excludes)

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "Scope":
        includes: List[ScopeRule] = []
        excludes: List[ScopeRule] = []
        for number, line in enumerate(lines, start=1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            negate = text.startswith("!")
            try:
                rule = parse_rule(text[1:] if negate else text)
            except ScopeError as exc:
                raise ScopeError("line %d: %s" % (number, exc))
            (excludes if negate else includes).append(rule)
        if not includes:
            raise ScopeError("scope has no include rules")
        return cls(includes, excludes)

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_lines(handle.read().splitlines())

    @classmethod
    def from_targets(cls, targets: Iterable[str]) -> "Scope":
        return cls.from_lines([validate_target(t) for t in targets])

    def allows(self, target: str, ip: Optional[str] = None) -> bool:
        """True if target (and its resolved IP, if known) is in scope."""
        if any(_matches(rule, target, ip) for rule in self.excludes):
            return False
        return any(_matches(rule, target, ip) for rule in self.includes)

    def expand(self, max_hosts: int = 256) -> List[str]:
        """Concrete targets from the include rules (wildcards are skipped)."""
        out: List[str] = []
        for rule in self.includes:
            if rule.kind == "ip":
                out.append(str(rule.network.network_address))
            elif rule.kind == "cidr":
                if rule.network.num_addresses > max_hosts:
                    raise ScopeError(
                        "%s expands to %d addresses (limit %d); raise --max-hosts "
                        "if this is intentional" % (rule.raw, rule.network.num_addresses, max_hosts)
                    )
                out.extend(str(h) for h in rule.network.hosts())
            elif rule.kind == "host":
                out.append(rule.host)
        seen = set()
        unique = []
        for target in out:
            if target not in seen and self.allows(target):
                seen.add(target)
                unique.append(target)
        return unique

    @property
    def wildcards(self) -> List[str]:
        return [r.raw for r in self.includes if r.kind == "wildcard"]
