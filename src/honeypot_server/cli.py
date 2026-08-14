"""Command-line interface for the Honeypot Server."""

from __future__ import annotations

import argparse
import signal
import sys
import threading

from . import DEFAULT_PORTS, run


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="honeypot",
        description="Fake services that log everyone who knocks.",
        epilog="Example: honeypot --services http,ftp,ssh --log trap.jsonl",
    )
    p.add_argument("--services", default="http,ftp,ssh,smtp",
                   help="comma list of decoys (default: http,ftp,ssh,smtp)")
    p.add_argument("--host", default="0.0.0.0", help="bind address")
    p.add_argument("--ports", default=None,
                   help="custom ports, e.g. http=8080,ssh=2222")
    p.add_argument("--log", default=None, help="JSONL log file (default: console)")
    args = p.parse_args(argv)

    services = [s.strip() for s in args.services.split(",") if s.strip()]
    for svc in services:
        if svc not in DEFAULT_PORTS:
            print(f"[!] Unknown service: {svc} (known: {', '.join(DEFAULT_PORTS)})")
            sys.exit(1)

    ports = {}
    if args.ports:
        for pair in args.ports.split(","):
            name, _, port = pair.partition("=")
            if name.strip() in DEFAULT_PORTS:
                ports[name.strip()] = int(port)

    stop = threading.Event()
    servers = run(services, args.host, ports, args.log, stop)
    print(f"[*] {len(servers)} decoys live. Ctrl+C to stop and log out.")

    def _halt(*_):
        print("\n[-] Shutting down decoys...")
        stop.set()
        for s in servers:
            s.shutdown()
            s.server_close()

    signal.signal(signal.SIGINT, _halt)
    signal.signal(signal.SIGTERM, _halt)

    try:
        while not stop.is_set():
            signal.pause()
    except AttributeError:
        stop.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
