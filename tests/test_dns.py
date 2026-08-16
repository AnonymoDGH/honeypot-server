"""Tests for the DNS decoy: codec, zone, live UDP answers."""

import socket
import struct
import time

from honeypot_server.core.logger import Logger
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import build_server
from honeypot_server.protocols.dns import (
    DNSHandler,
    DNSQuestion,
    DNSZone,
    RCODE_NXDOMAIN,
    RCODE_OK,
    TYPE_A,
    TYPE_MX,
    TYPE_TXT,
    build_response,
    encode_name,
    parse_question,
    rdata_for,
)

PERSONA = Persona.generate(51)


def _query(name: str, qtype: int = TYPE_A, txid: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, 1)


def _start(tmp_path):
    logger = Logger(tmp_path / "dns.jsonl")
    server = build_server(DNSHandler, "127.0.0.1", 0, logger, udp=True,
                          persona=PERSONA, start=True)
    return server, logger, server.server_address[1]


def _ask(port, packet: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(packet, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
        return data
    finally:
        s.close()


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestCodec:
    def test_encode_name(self):
        assert encode_name("a.bc") == b"\x01a\x02bc\x00"
        assert encode_name("x.") == b"\x01x\x00"

    def test_parse_question_roundtrip(self):
        packet = _query("www.example.com", TYPE_A, txid=0xBEEF)
        txid, q = parse_question(packet)
        assert txid == 0xBEEF
        assert q.name == "www.example.com" and q.qtype == TYPE_A

    def test_parse_question_short(self):
        assert parse_question(b"\x00" * 5) is None
        assert parse_question(_query("x.y")[:14]) is None

    def test_parse_question_no_questions(self):
        header = struct.pack(">HHHHHH", 1, 0, 0, 0, 0, 0)
        assert parse_question(header + encode_name("a.b")) is None

    def test_parse_question_rejects_compression(self):
        header = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0)
        bad = header + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
        assert parse_question(bad) is None

    def test_rdata_a(self):
        assert rdata_for(TYPE_A, "10.1.2.3") == b"\x0a\x01\x02\x03"
        assert rdata_for(TYPE_A, "junk") == b"\x7f\x00\x00\x01"

    def test_rdata_txt(self):
        rdata = rdata_for(TYPE_TXT, "hello")
        assert rdata == b"\x05hello"

    def test_rdata_mx(self):
        rdata = rdata_for(TYPE_MX, "10 mail.x.y")
        assert rdata[:2] == struct.pack(">H", 10)
        assert rdata[2:] == encode_name("mail.x.y")

    def test_build_response_ok(self):
        q = DNSQuestion(name="a.b", qtype=TYPE_A, qclass=1)
        resp = build_response(0x11, q, rcode=RCODE_OK,
                              answers=[(TYPE_A, b"\x01\x02\x03\x04")])
        txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp[:12])
        assert txid == 0x11 and an == 1 and ns == 0
        assert flags & 0x8000  # QR bit set
        assert resp.endswith(b"\x01\x02\x03\x04")

    def test_build_response_nxdomain_has_soa(self):
        q = DNSQuestion(name="gone.b", qtype=TYPE_A, qclass=1)
        resp = build_response(0x22, q, rcode=RCODE_NXDOMAIN, soa_name="b")
        _, flags, _, an, ns, _ = struct.unpack(">HHHHHH", resp[:12])
        assert flags & 0x0003 == 3  # rcode NXDOMAIN
        assert an == 0 and ns == 1


class TestDNSZone:
    def test_default_records_from_persona(self):
        zone = DNSZone(persona=PERSONA)
        assert zone.lookup(PERSONA.fqdn, TYPE_A) == PERSONA.ip_story
        assert zone.lookup(f"www.{PERSONA.domain}", TYPE_A) == PERSONA.ip_story
        assert zone.lookup(f"mail.{PERSONA.domain}", TYPE_MX)
        assert zone.lookup("unknown.example", TYPE_A) is None

    def test_lookup_case_insensitive(self):
        zone = DNSZone(persona=PERSONA)
        assert zone.lookup(PERSONA.fqdn.upper(), TYPE_A) == PERSONA.ip_story

    def test_from_zone_text(self):
        text = """
        ; fake zone
        @ A 192.168.7.7
        intranet@ A 192.168.7.8
        intranet@ TXT "secret share"
        """
        zone = DNSZone.from_zone_text(text, PERSONA)
        assert zone.lookup(PERSONA.domain, TYPE_A) == "192.168.7.7"
        assert zone.lookup(f"intranet.{PERSONA.domain}", TYPE_A) == "192.168.7.8"
        assert zone.lookup(f"intranet.{PERSONA.domain}", TYPE_TXT)

    def test_from_zone_text_ignores_bad_lines(self):
        zone = DNSZone.from_zone_text("onlyonefield\n\n; comment", PERSONA)
        assert zone.records == {}


class TestLiveDNS:
    def test_zone_query_answered(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            resp = _ask(port, _query(PERSONA.fqdn, txid=0xAAAA))
            txid, flags, _, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
            assert txid == 0xAAAA and an == 1
            assert resp.endswith(bytes(int(x) for x in PERSONA.ip_story.split(".")))
            assert _wait_for(logger.path, "\"event\": \"query\"")
            assert _wait_for(logger.path, PERSONA.fqdn)
        finally:
            server.shutdown(); server.server_close()

    def test_unknown_name_gets_nxdomain(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            resp = _ask(port, _query("does.not.exist.example"))
            _, flags, _, an, ns, _ = struct.unpack(">HHHHHH", resp[:12])
            assert flags & 0x000F == 3
            assert an == 0 and ns == 1
            assert _wait_for(logger.path, "nxdomain")
        finally:
            server.shutdown(); server.server_close()

    def test_custom_zone_served(self, tmp_path):
        server, logger, port = _start(tmp_path)
        server.dns_zone = DNSZone.from_zone_text(
            "honey A 172.16.9.9", PERSONA)
        try:
            resp = _ask(port, _query("honey"))
            assert resp.endswith(b"\xac\x10\x09\x09")
        finally:
            server.shutdown(); server.server_close()

    def test_malformed_query_logged(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.sendto(b"junk", ("127.0.0.1", port))
            try:
                s.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                pass
            s.close()
            assert _wait_for(logger.path, "malformed_query")
        finally:
            server.shutdown(); server.server_close()
