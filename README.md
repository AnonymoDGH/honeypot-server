<div align="center">

# 🍯 Honeypot Server

<img src="https://raw.githubusercontent.com/AnonymoDGH/honeypot-server/main/logo.png" alt="Honeypot Server" width="180"/>

**Fake services that log everyone who knocks.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-honeypot--server-orange.svg)](https://pypi.org/project/honeypot-server/)
[![Platform](https://img.shields.io/badge/platform-osx%20%7C%20linux%20%7C%20windows-lightgrey.svg)]()

> *"They didn't break in. They just told us they were here."*

</div>

---

## What is it?

A **low-interaction honeypot and deception platform**: eight convincing decoys
that speak real protocol grammar, plus the layer around them that turns raw
log lines into intelligence. Every handshake, banner grab, login attempt and
probe lands in a JSONL log; from there the platform profiles attackers, maps
their behaviour to simplified MITRE ATT&CK ids, exports IOC feeds, renders
dashboards, and grades how believable your own deployment is.

Defensive tooling for networks you own. Pure standard library — zero
dependencies.

## Features

- 🖥️ **Eight decoys**: `http`, `ftp`, `ssh`, `smtp`, `dns` (UDP), `telnet`, `redis`, `mysql`
- 🎭 **Persona engine** — one seeded fake identity (hostname, OS, versions,
  user roster) told consistently across every protocol surface
- 🕸️ **Tar pit mode** — configurable per-service delays that waste attacker
  time while staying human-plausible
- 🐦 **Canary tokens & documents** — fake AWS keys, API tokens, JWTs, canary
  URLs and bait files (password lists, VPN rosters, shell history) that raise
  critical alerts the moment they are touched
- 🕵️ **Attacker profiling** — per-IP behaviour tracking with a TTP classifier
  mapping events to simplified MITRE ATT&CK ids (T1046 scanning, T1110 brute
  force, T1078 valid accounts, T1105 tool transfer, ...)
- 📊 **Deception score** — a 0-100 grade of how convincing your deployment
  looks to an adversary, with per-check breakdowns
- 📤 **IOC feeds** — blocklists, STIX 2.1 bundles and fail2ban lines
- 📈 **Dashboards** — ANSI terminal dashboard and a self-contained HTML report
- ⏪ **Session replay** — record attacker sessions from the log and replay
  them into another deployment at any speed
- 📝 JSONL logging with rotation, enrichment and redaction
- 📦 Zero dependencies

## Install

```bash
pip install honeypot-server
```

From source:

```bash
git clone https://github.com/AnonymoDGH/honeypot-server
cd honeypot-server
pip install -e .
```

## Quickstart

```bash
# Deploy decoys on their classic ports, log everything to trap.jsonl
honeypot run --services http,ftp,ssh,smtp --log trap.jsonl
# [+] http decoy on 0.0.0.0:80   -> trap.jsonl
# [+] ftp decoy on 0.0.0.0:21    -> trap.jsonl
# [+] ssh decoy on 0.0.0.0:22    -> trap.jsonl
# [+] smtp decoy on 0.0.0.0:25   -> trap.jsonl
# [*] 4 decoys live. Ctrl+C to stop and log out.
```

The classic flag-style invocation still works unchanged:

```bash
honeypot --services http,ftp,ssh,smtp --log trap.jsonl
```

Now point a scanner at yourself, or wait for the curious. Every knock lands in
the log:

```json
{"ts": "2026-08-13 03:33:33", "service": "http", "src": "192.168.1.50:51234", "event": "request", "data": "GET /admin HTTP/1.1"}
{"ts": "2026-08-13 03:33:34", "service": "ftp", "src": "192.168.1.50:51240", "event": "login_attempt", "user": "admin"}
```

## CLI reference

| Command | What it does |
|---|---|
| `honeypot run` | Start decoys (`--services`, `--host`, `--ports`, `--log`, `--persona`, `--tarpit`, `--rotate`, `--canary`, `--config`) |
| `honeypot status --log trap.jsonl` | Summarise a log: events, sources, services |
| `honeypot report --log trap.jsonl` | Terminal dashboard (`--html out.html` for a static report) |
| `honeypot blocklist --log trap.jsonl --out feeds/` | Export blocklist, STIX bundle, fail2ban lines |
| `honeypot canary tokens --seed 7` | Generate canary tokens (`docs` writes bait files) |
| `honeypot replay --log trap.jsonl --record sessions.json` | Record sessions; `--recording` replays them |
| `honeypot diff a.jsonl b.jsonl` | Compare two logs by behaviour fingerprints |
| `honeypot score --seed 7` | Grade the deployment's deception score |
| `honeypot config --write-default` | Emit a starter deployment config |

## Personas, tar pits and canaries

```bash
# One seeded identity across every protocol, slowed-down responses,
# and a standard set of planted canary tokens:
honeypot run --services http,ftp,ssh,telnet,redis \
    --persona acme-dc1 --tarpit 0.4 --canary --log trap.jsonl

# Grade how believable that persona is:
honeypot score --seed acme-dc1
# Deception score: 100/100 (grade A)
```

Canary documents plant fake password lists, VPN rosters, AWS credential files
and shell history under the FTP decoy's `/internal` tree — each seeded with
unique tokens, so a download or a reused secret raises a critical
`canary_hit`.

## How it works

<img src="https://raw.githubusercontent.com/AnonymoDGH/honeypot-server/main/assets/architecture.svg" alt="Architecture" width="820"/>

## Tests

```bash
pip install pytest
pytest
```

## License

[MIT](LICENSE) — defensive deception for networks you own. Run decoys on
infrastructure you control and let the real fun stay in the manuscript.
