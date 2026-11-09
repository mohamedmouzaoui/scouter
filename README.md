# Scouter

[![CI](https://github.com/mohamedmouzaoui/scouter/actions/workflows/ci.yml/badge.svg)](https://github.com/mohamedmouzaoui/scouter/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

**Scope-aware recon and service enumeration.** Scouter scans the hosts you are
allowed to test, creates a folder per target, and writes a Markdown report with
suggested next steps for every service it finds, each paired with a hardening
note so the same report helps both a tester and a defender.

> Inspired by [Reconnoitre](https://github.com/codingo/Reconnoitre) by codingo.
> Scouter is an independent implementation written from scratch; no code was copied.

## Why another recon tool?

Most recon scripts will scan anything you point them at. Scouter treats
**authorization as a first-class feature**:

- **Scope file with exclusions.** Targets outside scope are refused, and a hostname that resolves into an excluded IP is skipped.
- **Explicit confirmation.** Without a scope file you must pass `--confirm-authorized`.
- **Dry run.** `--dry-run` shows exactly what would be scanned and sends no traffic.
- **Rate limiting and host caps.** `--rate` limits connection attempts per second, and large CIDRs are refused unless you raise `--max-hosts`.
- **No exploitation.** TCP connect scans and banner reads only. The suggested checks are written to the report, never executed.

## Features

- Threaded TCP connect scanner with banner grabbing and service identification (SSH, HTTP, FTP, SMTP, POP3, IMAP, plus a port map).
- Optional `nmap -sT -sV` backend (no root needed) when nmap is installed, selected automatically.
- Per-target output: `scan.json`, `report.md`, `raw/` and a top-level `summary.md`.
- Findings ranked **Review first / Review / Routine** with checklists and hardening advice.
- Pure standard library. Runs on Linux, macOS, Windows and **Termux** (no root).
- Unit tests plus a CI matrix on Python 3.9 to 3.12.

## Install

```bash
git clone https://github.com/mohamedmouzaoui/scouter.git
cd scouter
python -m scouter --help        # no install needed
# or: pip install .             # gives you the `scouter` command
```

Termux: `pkg install python git nmap` (nmap is optional).

## Usage

```bash
# Your own machine, quick check
python -m scouter -t 127.0.0.1 --confirm-authorized

# A lab network driven by a scope file
python -m scouter -s examples/scope.txt

# Custom ports, rate limited, preview first
python -m scouter -s examples/scope.txt -p 22,80,443,8000-8100 --rate 100 --dry-run
```

### Scope file

```text
127.0.0.1              # single IP
192.168.56.0/28        # CIDR range
lab.example.com        # exact hostname
*.test.example.com     # wildcard (pass hosts with -t, wildcards are not expanded)
!192.168.56.1          # exclusion always wins
```

### Options

| Option | Meaning |
|--------|---------|
| `-t, --target` | Target IP or hostname (repeatable) |
| `-s, --scope` | Scope file of authorised targets |
| `--confirm-authorized` | Required with `-t` when there is no scope file |
| `-p, --ports` | `top` (default), `all`, or `22,80,8000-8100` |
| `-o, --output` | Output directory (default `scouter-output`) |
| `--backend` | `auto`, `socket` or `nmap` |
| `--threads`, `--timeout`, `--rate` | Concurrency, connect timeout, max attempts per second |
| `--max-hosts` | CIDR expansion cap (default 256) |
| `--dry-run` | Show the plan, send nothing |

## Example

Scanning three local test services:

```text
Scouter 0.1.0 - scope-aware recon. Scan only what you are authorised to test.
Targets: 1 | ports: 4 | backend: socket
- scanning 127.0.0.1 (127.0.0.1)...
     2121/tcp  ftp
     2222/tcp  ssh (OpenSSH 9.6p1)
     8080/tcp  http (nginx 1.24.0)
  -> scouter-output/127.0.0.1/report.md
Power level: 3 open services across 1 host(s). Summary: scouter-output/summary.md
```

```text
scouter-output/
├── summary.md
└── 127.0.0.1/
    ├── report.md      # open services + prioritised checklist
    ├── scan.json      # machine-readable results
    └── raw/           # banners.txt (and nmap.xml with the nmap backend)
```

An excerpt of `report.md`:

```markdown
### 2121/tcp - FTP  _(Review first)_

- [ ] Check whether anonymous login is accepted: ftp -p 127.0.0.1 2121 (user: anonymous)
- [ ] Note that credentials are sent in clear text without TLS

**Hardening:** Prefer SFTP or FTPS and disable anonymous access.
```

## How it works

```
scope file / -t  ->  validate + resolve  ->  scope check (includes, exclusions)
                                                   |
                          socket or nmap backend (threaded, rate limited)
                                                   |
                     identify services  ->  rank advice  ->  report + JSON
```

| Module | Role |
|--------|------|
| `scope.py` | Rule parsing, target validation, scope checks, CIDR expansion |
| `scanner.py` | Port specs, rate limiter, socket scanner, nmap wrapper and parser |
| `recommendations.py` | Service rules: checks plus hardening notes |
| `report.py` | Markdown and JSON output |
| `cli.py` | Argument handling and the scan loop |

Targets are validated against a strict hostname/IP pattern before they reach any
external tool, so a target can never be interpreted as a command-line option.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers scope rules, port parsing, banner identification, the rate
limiter, the nmap XML parser, a real scan against a local test server, and the
CLI's refusal paths.

## Roadmap

- [ ] TLS handshake details for the socket backend (certificate names, expiry)
- [ ] HTML report
- [ ] Optional UDP checks for DNS and SNMP
- [ ] Export to the Sentinel XDR asset inventory format

## Legal

Use Scouter only on systems you own or have **explicit written permission** to
test. You are responsible for complying with the law and with the rules of any
bug bounty program you participate in. The authors accept no liability for misuse.

## Author

Mohamed Mouzaoui ([Mo.Life](https://github.com/mohamedmouzaoui)) - cybersecurity graduate building offensive and defensive tooling.

Also see: [Single_JS](https://github.com/mohamedmouzaoui/scanning-script) (static JavaScript recon), [Gotenks](https://github.com/mohamedmouzaoui/gotenks) (persistence scanner) and [Sentinel XDR](https://github.com/mohamedmouzaoui/sentinel-xdr).
