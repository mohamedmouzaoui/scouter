"""Markdown and JSON output."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from scouter import __version__
from scouter.recommendations import prioritised
from scouter.scanner import Service

PRIORITY_LABEL = {1: "Review first", 2: "Review", 3: "Routine"}


@dataclass
class HostResult:
    target: str
    ip: str
    backend: str
    ports_scanned: int
    started: str
    finished: str
    services: List[Service] = field(default_factory=list)
    raw: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "ip": self.ip,
            "backend": self.backend,
            "ports_scanned": self.ports_scanned,
            "started": self.started,
            "finished": self.finished,
            "services": [s.to_dict() for s in self.services],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target) or "target"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ") if text else ""


def render_host_report(result: HostResult) -> str:
    lines = [
        "# Scouter report: %s" % result.target,
        "",
        "- Resolved IP: `%s`" % result.ip,
        "- Backend: `%s`" % result.backend,
        "- Ports scanned: %d" % result.ports_scanned,
        "- Started: %s" % result.started,
        "- Finished: %s" % result.finished,
        "- Open services: **%d**" % len(result.services),
        "",
    ]
    if not result.services:
        lines += ["No open TCP services found among the scanned ports.", ""]
        return "\n".join(lines)

    lines += ["## Open services", "", "| Port | Service | Details |", "|-----:|---------|---------|"]
    for s in result.services:
        detail = " ".join(p for p in (s.product, s.version) if p) or s.banner
        lines.append("| %d/%s | %s | %s |" % (s.port, s.proto, _cell(s.name), _cell(detail)[:80]))
    lines.append("")

    lines += ["## Suggested next steps", "",
              "_Manual checks only. Scouter does not run them. Use them only on targets you are authorised to test._", ""]
    for item in prioritised(result.services, result.target):
        lines.append("### %d/%s - %s  _(%s)_" % (
            item.service.port, item.service.proto, item.rule.title, PRIORITY_LABEL[item.rule.priority]))
        lines.append("")
        for check in item.checks:
            lines.append("- [ ] %s" % check)
        if item.rule.hardening:
            lines += ["", "**Hardening:** %s" % item.rule.hardening]
        lines.append("")
    return "\n".join(lines)


def render_summary(results: List[HostResult], skipped: List[str]) -> str:
    total = sum(len(r.services) for r in results)
    lines = [
        "# Scouter summary",
        "",
        "- Scouter version: %s" % __version__,
        "- Hosts scanned: %d" % len(results),
        "- Open services (power level): **%d**" % total,
        "",
        "| Target | IP | Open ports | Report |",
        "|--------|----|------------|--------|",
    ]
    for r in results:
        ports = ", ".join(str(s.port) for s in r.services) or "-"
        lines.append("| %s | %s | %s | [report](%s/report.md) |" % (r.target, r.ip, ports, safe_name(r.target)))
    if skipped:
        lines += ["", "## Skipped", ""] + ["- %s" % s for s in skipped]
    lines.append("")
    return "\n".join(lines)


def write_host_output(base_dir: str, result: HostResult) -> str:
    host_dir = os.path.join(base_dir, safe_name(result.target))
    raw_dir = os.path.join(host_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    with open(os.path.join(host_dir, "scan.json"), "w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2)
    with open(os.path.join(host_dir, "report.md"), "w", encoding="utf-8") as handle:
        handle.write(render_host_report(result))
    banners = "\n".join("%d/%s: %s" % (s.port, s.proto, s.banner) for s in result.services if s.banner)
    if banners:
        result.raw.setdefault("banners.txt", banners + "\n")
    for name, content in result.raw.items():
        with open(os.path.join(raw_dir, name), "w", encoding="utf-8") as handle:
            handle.write(content)
    return host_dir


def write_summary(base_dir: str, results: List[HostResult], skipped: List[str]) -> str:
    os.makedirs(base_dir, exist_ok=True)
    path = os.path.join(base_dir, "summary.md")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_summary(results, skipped))
    return path
