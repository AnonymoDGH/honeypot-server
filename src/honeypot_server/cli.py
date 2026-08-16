"""Command-line interface for the Honeypot Server.

Subcommands (new in 0.2.0):

    honeypot run       start decoys (same flags as the classic invocation)
    honeypot status    summarise a JSONL log: events, sources, services
    honeypot report    terminal dashboard or static HTML report from a log
    honeypot blocklist export attacker IPs / STIX bundle / fail2ban lines
    honeypot canary    generate canary tokens or bait documents
    honeypot replay    record sessions from a log, or replay a recording
    honeypot diff      compare two logs by behaviour fingerprints
    honeypot score     grade the deployment's deception score

The classic flag-style invocation keeps working unchanged:

    honeypot --services http,ftp,ssh --log trap.jsonl

is treated as "honeypot run" with those flags.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from . import DEFAULT_PORTS
from .core.logger import Logger, read_events
from .core.persona import persona_from_seed
from .core.server import HoneypotManager
from .core.tarpit import Tarpit

#: Services this build can run (legacy DEFAULT_PORTS plus the new decoys).
EXTRA_DEFAULT_PORTS = {"telnet": 23, "redis": 6379, "mysql": 3306}
ALL_PORTS = {**DEFAULT_PORTS, **EXTRA_DEFAULT_PORTS}

SUBCOMMANDS = ("run", "status", "report", "blocklist", "canary",
               "replay", "diff", "score", "config")

#: Optional external stop event for cmd_run (embedding and tests). When
#: set, cmd_run waits on this event instead of a private one.
RUN_STOP_HOOK: threading.Event | None = None


def _parse_ports(spec: str | None) -> dict[str, int]:
    """Parse --ports "http=8080,ssh=2222" into a dict."""
    ports: dict[str, int] = {}
    if not spec:
        return ports
    for pair in spec.split(","):
        name, _, port = pair.partition("=")
        name = name.strip()
        if name in ALL_PORTS and port.strip().isdigit():
            ports[name] = int(port)
    return ports


def _parse_services(spec: str) -> list[str]:
    services = [s.strip() for s in spec.split(",") if s.strip()]
    unknown = [s for s in services if s not in ALL_PORTS]
    if unknown:
        print(f"[!] Unknown service(s): {', '.join(unknown)} "
              f"(known: {', '.join(ALL_PORTS)})")
        sys.exit(1)
    return services


def _add_run_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--services", default="http,ftp,ssh,smtp",
                   help="comma list of decoys (default: http,ftp,ssh,smtp)")
    p.add_argument("--host", default="0.0.0.0", help="bind address")
    p.add_argument("--ports", default=None,
                   help="custom ports, e.g. http=8080,ssh=2222")
    p.add_argument("--log", default=None, help="JSONL log file (default: console)")
    p.add_argument("--persona", default=None,
                   help="persona seed (int or string) for one fake identity")
    p.add_argument("--tarpit", default=None, metavar="SECONDS",
                   help="enable tar-pit mode with this base delay for all services")
    p.add_argument("--rotate", action="store_true",
                   help="rotate the log file instead of growing it forever")
    p.add_argument("--canary", action="store_true",
                   help="plant a standard set of canary tokens")
    p.add_argument("--config", default=None,
                   help="JSON deployment config file (overrides other flags)")


def cmd_run(args: argparse.Namespace) -> int:
    """Start the decoy fleet and block until interrupted."""
    if args.config:
        return _run_from_config(args)
    services = _parse_services(args.services)
    tarpit = Tarpit()
    if args.tarpit is not None:
        tarpit.enable(base=float(args.tarpit))
    manager = HoneypotManager(args.log, host=args.host,
                              persona=args.persona, tarpit=tarpit,
                              rotate=args.rotate)
    if args.canary:
        from .canary.tokens import CanaryTokenFactory
        manager.add_many(services, _parse_ports(args.ports))
        manager.start()
        factory = CanaryTokenFactory(seed=manager.persona.seed,
                                     domain=manager.persona.domain)
        factory.standard_set()
        if manager.canaries is not None:
            factory.attach(manager.canaries)
        print(f"[+] planted {len(factory.tokens)} canary tokens")
    else:
        manager.add_many(services, _parse_ports(args.ports))
        manager.start()

    for name, record in manager.records.items():
        if record.running:
            print(f"[+] {name} decoy on {record.host}:{record.port}"
                  + (f"  -> {args.log}" if args.log else "  (console)"))
        else:
            print(f"[!] {name} decoy failed to start on port {record.port}")
    live = sum(1 for r in manager.records.values() if r.running)
    print(f"[*] {live} decoys live. Ctrl+C to stop and log out.")

    stop = RUN_STOP_HOOK if RUN_STOP_HOOK is not None else threading.Event()
    stop.clear()

    def _halt(*_):
        print("\n[-] Shutting down decoys...")
        stop.set()
        manager.stop_all()

    # signal handlers only install from the main thread; embedded/test
    # runs in worker threads fall back to the stop-event loop.
    try:
        signal.signal(signal.SIGINT, _halt)
        signal.signal(signal.SIGTERM, _halt)
    except ValueError:
        pass
    try:
        while not stop.is_set():
            stop.wait(0.2)
    except KeyboardInterrupt:
        _halt()
    return 0


def _run_from_config(args: argparse.Namespace) -> int:
    """Start the fleet described by a JSON deployment config file."""
    from .core.config import ConfigError, from_file
    try:
        cfg = from_file(args.config)
    except (ConfigError, OSError) as exc:
        print(f"[!] config error: {exc}")
        return 1
    manager = cfg.build_manager()
    manager.start()
    if cfg.canary_enabled and manager.canaries is not None:
        from .canary.tokens import CanaryTokenFactory
        factory = CanaryTokenFactory(seed=cfg.canary_seed or manager.persona.seed,
                                     domain=manager.persona.domain)
        factory.standard_set()
        factory.attach(manager.canaries)
        print(f"[+] planted {len(factory.tokens)} canary tokens")
    for name, record in manager.records.items():
        if record.running:
            print(f"[+] {name} decoy on {record.host}:{record.port}"
                  + (f"  -> {cfg.log}" if cfg.log else "  (console)"))
        else:
            print(f"[!] {name} decoy failed to start on port {record.port}")
    live = sum(1 for r in manager.records.values() if r.running)
    print(f"[*] {live} decoys live. Ctrl+C to stop and log out.")

    stop = RUN_STOP_HOOK if RUN_STOP_HOOK is not None else threading.Event()
    stop.clear()

    def _halt(*_):
        print("\n[-] Shutting down decoys...")
        stop.set()
        manager.stop_all()

    try:
        signal.signal(signal.SIGINT, _halt)
        signal.signal(signal.SIGTERM, _halt)
    except ValueError:
        pass
    try:
        while not stop.is_set():
            stop.wait(0.2)
    except KeyboardInterrupt:
        _halt()
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Validate a deployment config or write a starter template."""
    from .core.config import ConfigError, default_config_dict, from_file
    if args.write_default:
        text = json.dumps(default_config_dict(), indent=2)
        if args.write_default is True:
            print(text)
        else:
            Path(args.write_default).write_text(text + "\n", encoding="utf-8")
            print(f"[+] starter config written to {args.write_default}")
        return 0
    if not args.file:
        print("[!] provide --file to validate or --write-default to emit a template")
        return 1
    try:
        cfg = from_file(args.file)
    except (ConfigError, OSError) as exc:
        print(f"[!] config error: {exc}")
        return 1
    print(f"[+] config OK: {len(cfg.services)} service(s) on {cfg.host}")
    for name, port in cfg.services.items():
        print(f"    {name:<8} -> {port}")
    return 0


def _load_log(args: argparse.Namespace) -> list[dict]:
    if not args.log:
        print("[!] --log is required for this command")
        sys.exit(1)
    path = Path(args.log)
    if not path.exists():
        print(f"[!] log file not found: {path}")
        sys.exit(1)
    return list(read_events(path))


def cmd_status(args: argparse.Namespace) -> int:
    """Summarise a log file: totals, services, top sources."""
    events = _load_log(args)
    from .intel.dashboard import summarize
    data = summarize(events)
    print(f"events:  {data['total']}")
    print(f"sources: {len(data['sources'])}")
    print(f"window:  {data['first_ts'] or '-'}  ->  {data['last_ts'] or '-'}")
    print("services:")
    for svc, count in data["services"].most_common():
        print(f"  {svc:<10} {count}")
    print("top sources:")
    for ip, count in data["sources"].most_common(5):
        print(f"  {ip:<16} {count}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Render the terminal dashboard or write an HTML report."""
    events = _load_log(args)
    if args.html:
        from .intel.dashboard import render_html_report
        page = render_html_report(events, title=args.title)
        out = Path(args.html)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(page, encoding="utf-8")
        print(f"[+] report written to {out}")
        return 0
    from .intel.dashboard import render_terminal
    print(render_terminal(events, color=not args.no_color))
    return 0


def cmd_blocklist(args: argparse.Namespace) -> int:
    """Export IOC feeds from a log."""
    events = _load_log(args)
    from .intel.feeds import export_feeds
    outdir = Path(args.out)
    paths = export_feeds(events, outdir, min_severity=args.min_severity)
    for name, path in paths.items():
        print(f"[+] {name:<9} -> {path}")
    return 0


def cmd_canary(args: argparse.Namespace) -> int:
    """Generate canary tokens or bait documents."""
    from .canary.tokens import CanaryTokenFactory
    persona = persona_from_seed(args.seed)
    factory = CanaryTokenFactory(seed=args.seed or 0, domain=persona.domain)
    if args.what == "docs":
        from .canary.docs import DocumentGenerator
        generator = DocumentGenerator(persona, factory)
        docs = generator.full_set()
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        for doc in docs:
            (outdir / doc.filename).write_text(doc.content, encoding="utf-8")
            print(f"[+] {doc.filename} ({len(doc.tokens)} tokens)")
        factory.save(str(outdir / "tokens.json"))
        print(f"[+] token manifest -> {outdir / 'tokens.json'}")
        return 0
    tokens = factory.standard_set()
    if args.out:
        factory.save(args.out)
        print(f"[+] {len(tokens)} tokens -> {args.out}")
    else:
        print(json.dumps(factory.export(), indent=2))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Record sessions from a log, or replay a recording into a log."""
    from .intel.replay import (SessionRecorder, load_recording,
                               replay_session)
    if args.record:
        events = _load_log(args)
        recorder = SessionRecorder()
        recorder.observe_all(events)
        out = Path(args.record)
        recorder.save(out)
        print(f"[+] recorded {len(recorder.sessions)} sessions -> {out}")
        return 0
    if not args.recording:
        print("[!] provide --record OUT.json (from --log) or --recording IN.json")
        return 1
    records = load_recording(args.recording)
    logger = Logger(args.log) if args.log else Logger(None)
    total = 0
    for record in records:
        total += replay_session(record, logger.log, speed=args.speed)
    print(f"[+] replayed {total} events from {len(records)} session(s)")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two logs by behaviour fingerprints."""
    from .intel.replay import diff_logs
    result = diff_logs(args.log_a, args.log_b)
    print(f"common fingerprints: {result['common']}")
    print(f"only in A ({result['total_a']} total):")
    for fp in result["only_a"]:
        print(f"  {fp}")
    print(f"only in B ({result['total_b']} total):")
    for fp in result["only_b"]:
        print(f"  {fp}")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Grade the deployment's deception score for a persona seed."""
    from .intel.deception import score_deployment
    persona = persona_from_seed(args.seed)
    delays = {}
    if args.tarpit is not None:
        delays = {svc: float(args.tarpit) for svc in ALL_PORTS}
    report = score_deployment(persona, delays or None)
    print(f"persona: {persona.fqdn} ({persona.os} {persona.os_version})")
    print(report.render())
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The full argument parser with every subcommand."""
    p = argparse.ArgumentParser(
        prog="honeypot",
        description="Fake services that log everyone who knocks.",
        epilog="Example: honeypot run --services http,ftp,ssh --log trap.jsonl",
    )
    sub = p.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="start decoys")
    _add_run_flags(p_run)
    p_run.set_defaults(func=cmd_run)

    p_status = sub.add_parser("status", help="summarise a log file")
    p_status.add_argument("--log", required=True)
    p_status.set_defaults(func=cmd_status)

    p_report = sub.add_parser("report", help="dashboard or HTML report")
    p_report.add_argument("--log", required=True)
    p_report.add_argument("--html", default=None, help="write HTML report here")
    p_report.add_argument("--title", default="Honeypot Report")
    p_report.add_argument("--no-color", action="store_true")
    p_report.set_defaults(func=cmd_report)

    p_block = sub.add_parser("blocklist", help="export IOC feeds")
    p_block.add_argument("--log", required=True)
    p_block.add_argument("--out", default="feeds")
    p_block.add_argument("--min-severity", default="info")
    p_block.set_defaults(func=cmd_blocklist)

    p_canary = sub.add_parser("canary", help="generate canary tokens/docs")
    p_canary.add_argument("what", choices=["tokens", "docs"])
    p_canary.add_argument("--seed", default=None)
    p_canary.add_argument("--out", default=None)
    p_canary.set_defaults(func=cmd_canary)

    p_replay = sub.add_parser("replay", help="record or replay sessions")
    p_replay.add_argument("--log", default=None)
    p_replay.add_argument("--record", default=None, metavar="OUT_JSON")
    p_replay.add_argument("--recording", default=None, metavar="IN_JSON")
    p_replay.add_argument("--speed", type=float, default=0.0)
    p_replay.set_defaults(func=cmd_replay)

    p_diff = sub.add_parser("diff", help="compare two logs")
    p_diff.add_argument("log_a")
    p_diff.add_argument("log_b")
    p_diff.set_defaults(func=cmd_diff)

    p_score = sub.add_parser("score", help="deception score for a persona")
    p_score.add_argument("--seed", default=None)
    p_score.add_argument("--tarpit", default=None, metavar="SECONDS")
    p_score.set_defaults(func=cmd_score)

    p_config = sub.add_parser("config", help="validate/write deployment configs")
    p_config.add_argument("--file", default=None, help="config file to validate")
    p_config.add_argument("--write-default", nargs="?", const=True,
                          default=None, metavar="PATH",
                          help="emit a starter config (to PATH or stdout)")
    p_config.set_defaults(func=cmd_config)

    return p


def _force_utf8_stdio() -> None:
    """Windows consoles default to cp1252, which cannot encode the
    dashboard's block characters. Reconfigure stdout/stderr to UTF-8
    with replacement so rendering never crashes on a narrow codepage."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    """Entry point. Handles both subcommands and the legacy flag style."""
    _force_utf8_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    # Legacy compatibility: "honeypot --services ..." means "honeypot run".
    if argv and (argv[0].startswith("-") or argv[0] not in SUBCOMMANDS):
        argv = ["run"] + argv
    elif not argv:
        argv = ["run"]

    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
