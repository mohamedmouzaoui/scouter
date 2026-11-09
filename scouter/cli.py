"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from scouter import __version__
from scouter.report import (HostResult, now_iso, render_host_report, safe_name,
                            write_host_output, write_summary)
from scouter.scanner import (DEFAULT_PORTS, ScanError, nmap_available, parse_ports,
                             scan_nmap, scan_socket)
from scouter.scope import Scope, ScopeError, resolve, validate_target

BANNER = "Scouter %s - scope-aware recon. Scan only what you are authorised to test." % __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scouter",
        description="Scope-aware recon and service enumeration that writes a "
                    "folder and a report per target.",
        epilog="Only scan systems you own or have written permission to test.",
    )
    p.add_argument("-t", "--target", action="append", default=[], metavar="HOST",
                   help="target IP or hostname (repeatable)")
    p.add_argument("-s", "--scope", metavar="FILE",
                   help="scope file listing what you are authorised to scan")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="required with -t when no scope file is given: "
                        "confirms you are authorised to scan the targets")
    p.add_argument("-p", "--ports", default="top", metavar="SPEC",
                   help="ports: 'top' (default, %d common), 'all', or e.g. 22,80,8000-8100" % len(DEFAULT_PORTS))
    p.add_argument("-o", "--output", default="scouter-output", metavar="DIR",
                   help="output directory (default: scouter-output)")
    p.add_argument("--backend", choices=("auto", "socket", "nmap"), default="auto",
                   help="scan backend (auto uses nmap when installed)")
    p.add_argument("--threads", type=int, default=50, help="concurrent connections (default 50)")
    p.add_argument("--timeout", type=float, default=1.5, help="connect timeout in seconds (default 1.5)")
    p.add_argument("--rate", type=float, default=0,
                   help="max connection attempts per second (default: unlimited)")
    p.add_argument("--max-hosts", type=int, default=256,
                   help="refuse to expand a CIDR beyond this many hosts (default 256)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be scanned without sending any traffic")
    p.add_argument("-q", "--quiet", action="store_true", help="less output")
    p.add_argument("--version", action="version", version="scouter " + __version__)
    return p


def _say(args, message: str = "") -> None:
    if not args.quiet:
        print(message)


def _build_targets(args, scope: Optional[Scope]):
    """Return (scope, targets, errors)."""
    if args.scope:
        scope = Scope.from_file(args.scope)
        if args.target:
            targets = [validate_target(t) for t in args.target]
        else:
            targets = scope.expand(args.max_hosts)
            for wildcard in scope.wildcards:
                print("note: wildcard %s cannot be expanded; pass hosts with -t" % wildcard, file=sys.stderr)
        return scope, targets
    if not args.target:
        raise ScopeError("give a scope file (-s) or at least one target (-t)")
    if not args.confirm_authorized:
        raise ScopeError("without a scope file, add --confirm-authorized to confirm you may scan these targets")
    targets = [validate_target(t) for t in args.target]
    return Scope.from_targets(targets), targets


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        scope, targets = _build_targets(args, None)
    except (ScopeError, ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    # Hard stop on anything explicitly requested but out of scope.
    refused = [t for t in targets if not scope.allows(t, resolve(t))]
    if refused and args.target:
        print("error: out of scope, refusing to scan: %s" % ", ".join(refused), file=sys.stderr)
        return 2

    backend = args.backend
    if backend == "auto":
        backend = "nmap" if nmap_available() else "socket"
    if backend == "nmap" and not nmap_available():
        print("error: nmap backend requested but nmap is not installed", file=sys.stderr)
        return 2

    _say(args, BANNER)
    _say(args, "Targets: %d | ports: %d | backend: %s%s" % (
        len(targets), len(ports), backend, " | DRY RUN" if args.dry_run else ""))

    results: List[HostResult] = []
    skipped: List[str] = []

    for target in targets:
        ip = resolve(target)
        if ip is None:
            skipped.append("%s (does not resolve)" % target)
            _say(args, "- %s: skipped, does not resolve" % target)
            continue
        if not scope.allows(target, ip):
            skipped.append("%s (resolves to %s, out of scope)" % (target, ip))
            _say(args, "- %s: skipped, %s is out of scope" % (target, ip))
            continue
        if args.dry_run:
            _say(args, "- %s (%s): would scan %d ports" % (target, ip, len(ports)))
            continue

        _say(args, "- scanning %s (%s)..." % (target, ip))
        started = now_iso()
        raw = {}
        try:
            if backend == "nmap":
                services, xml_text = scan_nmap(ip, ports, rate=args.rate)
                raw["nmap.xml"] = xml_text
            else:
                services = scan_socket(ip, ports, args.threads, args.timeout, args.rate)
        except ScanError as exc:
            skipped.append("%s (%s)" % (target, exc))
            print("  error: %s" % exc, file=sys.stderr)
            continue

        result = HostResult(target=target, ip=ip, backend=backend, ports_scanned=len(ports),
                            started=started, finished=now_iso(), services=services, raw=raw)
        folder = write_host_output(args.output, result)
        results.append(result)
        for s in services:
            _say(args, "    %5d/tcp  %s" % (s.port, s.label))
        _say(args, "  -> %s/report.md" % folder)

    if args.dry_run:
        return 0

    summary = write_summary(args.output, results, skipped)
    power = sum(len(r.services) for r in results)
    _say(args, "Power level: %d open services across %d host(s). Summary: %s" % (power, len(results), summary))
    return 0 if results or not targets else 1
