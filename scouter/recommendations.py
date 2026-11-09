"""Per-service "next steps".

Scouter never executes these. They are checks a tester can run by hand against
a target they are authorised to assess, each paired with a hardening note so
the same report is useful to a defender.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from scouter.scanner import TLS_PORTS, Service

SINGLE_JS = "https://github.com/mohamedmouzaoui/scanning-script"
TLS_NAMES = {"https", "imaps", "pop3s", "smtps", "ldaps"}


@dataclass
class Rule:
    key: str
    title: str
    names: List[str]
    ports: List[int]
    priority: int  # 1 = review first, 3 = routine
    checks: List[str]
    hardening: str = ""


RULES: List[Rule] = [
    Rule("http", "Web service", ["http", "https", "http-proxy", "http-alt", "ssl/http"],
         [80, 443, 3000, 5000, 8000, 8080, 8443, 8888], 2,
         [
             "Review response headers: curl -sI {scheme}://{host}:{port}/",
             "Look for robots.txt, sitemap.xml and /.well-known/ files",
             "Identify the technology stack and compare versions with public advisories",
             "Collect the page's JavaScript files and run Single_JS on each one (" + SINGLE_JS + ")",
         ],
         "Send HSTS, CSP and X-Content-Type-Options headers and hide version banners."),
    Rule("tls", "TLS configuration", [], sorted(TLS_PORTS), 3,
         [
             "Check protocol versions and certificate expiry: openssl s_client -connect {host}:{port} -brief",
             "Check the certificate names match the host you expect",
         ],
         "Allow TLS 1.2+ only, renew certificates before expiry."),
    Rule("ssh", "SSH", ["ssh"], [22], 2,
         [
             "Record the banner and compare the version with public advisories",
             "List accepted auth methods: ssh -p {port} -o PreferredAuthentications=none {host}",
             "Confirm password authentication is off where keys are expected",
         ],
         "Disable root and password login, restrict with AllowUsers, use keys."),
    Rule("ftp", "FTP", ["ftp"], [21], 1,
         [
             "Check whether anonymous login is accepted: ftp -p {host} {port} (user: anonymous)",
             "Note that credentials are sent in clear text without TLS",
         ],
         "Prefer SFTP or FTPS and disable anonymous access."),
    Rule("telnet", "Telnet", ["telnet"], [23], 1,
         ["Confirm why Telnet is exposed: everything, including passwords, is clear text"],
         "Replace with SSH and close the port."),
    Rule("smb", "SMB / NetBIOS", ["microsoft-ds", "netbios-ssn", "smb"], [139, 445], 1,
         [
             "Check SMB protocols and signing: nmap --script smb-protocols,smb-security-mode -p {port} {host}",
             "List shares without credentials: smbclient -L //{host} -N",
         ],
         "Disable SMBv1, require signing, block 445 from untrusted networks."),
    Rule("rdp", "Remote Desktop", ["ms-wbt-server", "rdp"], [3389], 1,
         ["Check encryption and NLA: nmap --script rdp-enum-encryption -p {port} {host}"],
         "Require NLA and keep RDP behind a VPN or gateway."),
    Rule("redis", "Redis", ["redis"], [6379], 1,
         ["Check whether authentication is required: redis-cli -h {host} -p {port} ping"],
         "Bind to localhost or a private network and set requirepass or ACLs."),
    Rule("database", "Database", ["mysql", "postgresql", "mssql", "ms-sql-s", "oracle", "mongodb", "elasticsearch"],
         [1433, 1521, 3306, 5432, 9200, 27017], 1,
         [
             "Check whether this port should be reachable from this network at all",
             "Confirm authentication is enforced (read-only test, no data changes)",
         ],
         "Bind to private interfaces, firewall the port and require TLS plus strong credentials."),
    Rule("smtp", "Mail (SMTP)", ["smtp", "smtps", "submission"], [25, 465, 587], 2,
         [
             "Check STARTTLS and supported commands: nmap --script smtp-commands -p {port} {host}",
             "Check SPF, DKIM and DMARC records for the mail domain",
         ],
         "Require authentication and TLS, publish SPF, DKIM and DMARC."),
    Rule("dns", "DNS", ["dns", "domain"], [53], 2,
         [
             "Check that zone transfers are refused: dig axfr @{host} <domain>",
             "Check for open recursion: dig @{host} example.com",
         ],
         "Restrict AXFR to secondaries and disable open recursion."),
    Rule("vnc", "VNC", ["vnc"], [5900], 1,
         ["Check whether a password is required and the protocol is encrypted"],
         "Tunnel VNC through SSH or a VPN."),
    Rule("ldap", "LDAP", ["ldap", "ldaps"], [389, 636], 2,
         ["Check anonymous bind: ldapsearch -x -H ldap://{host}:{port} -s base namingContexts"],
         "Disable anonymous bind and require LDAPS or StartTLS."),
    Rule("mail-retrieval", "Mail retrieval", ["pop3", "imap", "pop3s", "imaps"], [110, 143, 993, 995], 2,
         ["Check STARTTLS or implicit TLS is enforced before credentials are sent"],
         "Disable plaintext POP3/IMAP and enforce TLS."),
]

FALLBACK = Rule(
    "unknown", "Unidentified service", [], [], 3,
    [
        "Identify the service manually: nc -nv {host} {port}",
        "Search the banner or version in vendor advisories",
    ],
    "Close the port if nothing needs it.",
)


@dataclass
class Advice:
    service: Service
    rule: Rule
    checks: List[str] = field(default_factory=list)


def _scheme(service: Service) -> str:
    return "https" if service.port in TLS_PORTS or "https" in service.name or "ssl" in service.name else "http"


def _matching_rules(service: Service) -> List[Rule]:
    name = service.name.lower()
    matched = [r for r in RULES if name in r.names or (service.port in r.ports and r.key != "tls")]
    # Add the TLS rule for TLS ports regardless of which service rule matched.
    if service.port in TLS_PORTS or "ssl" in name or name in TLS_NAMES:
        matched.append(next(r for r in RULES if r.key == "tls"))
    # Drop duplicates, keep order.
    unique: List[Rule] = []
    for rule in matched:
        if rule not in unique:
            unique.append(rule)
    return unique or [FALLBACK]


def advise(service: Service, host: str) -> List[Advice]:
    advice: List[Advice] = []
    for rule in _matching_rules(service):
        checks = [
            c.format(host=host, port=service.port, scheme=_scheme(service))
            for c in rule.checks
        ]
        advice.append(Advice(service=service, rule=rule, checks=checks))
    return advice


def prioritised(services: List[Service], host: str) -> List[Advice]:
    items: List[Advice] = []
    for service in services:
        items.extend(advise(service, host))
    return sorted(items, key=lambda a: (a.rule.priority, a.service.port))
