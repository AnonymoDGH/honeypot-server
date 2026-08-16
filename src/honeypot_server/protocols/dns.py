"""DNS decoy -- query logging, fake zone answers and NXDOMAIN bait.

A UDP decoy that parses real DNS queries, logs every name asked for, and
answers from a fake zone file:

* names inside the persona's zone resolve to persona-controlled fake
  addresses (the honeypot's own "internal" IPs), which lures the next
  stage of the attack toward other decoys;
* everything else gets a convincing NXDOMAIN with SOA, so resolvers
  cache the refusal and keep believing the server is real;
* canary hostnames (see honeypot_server.canary) raise critical alerts
  the moment they are resolved.

The wire codec here is deliberately small: enough of RFC 1035 to answer
one-question queries, which is all scanners and malware ever send.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..core.persona import Persona
from .base import UDPProtocolHandler

#: DNS record types we understand.
TYPE_A = 1
TYPE_TXT = 16
TYPE_MX = 15

#: Response codes.
RCODE_OK = 0
RCODE_NXDOMAIN = 3


@dataclass
class DNSQuestion:
    """One parsed question from a DNS query."""

    name: str
    qtype: int
    qclass: int


@dataclass
class DNSZone:
    """Fake authoritative zone built from the persona."""

    persona: Persona
    records: dict[str, dict[str, str]] | None = None

    def __post_init__(self) -> None:
        # None means "derive from the persona"; an explicit (even empty)
        # dict is honoured as-is, which is how from_zone_text builds zones.
        if self.records is None:
            self.records = self.default_records()

    def default_records(self) -> dict[str, dict[str, str]]:
        """Zone entries derived from the persona (name -> {type: value})."""
        p = self.persona
        ip = p.ip_story
        return {
            p.fqdn: {"A": ip, "TXT": f"v=spf1 ip4:{ip} -all"},
            f"www.{p.domain}": {"A": ip},
            f"mail.{p.domain}": {"A": ip, "MX": f"10 {p.fqdn}"},
            f"db.{p.domain}": {"A": ip},
            f"vpn.{p.domain}": {"A": ip},
            p.domain: {"A": ip, "TXT": "internal zone"},
        }

    def lookup(self, name: str, qtype: int) -> str | None:
        """Return the record value for (name, type) or None."""
        entry = self.records.get(name.lower())
        if entry is None:
            return None
        type_name = {TYPE_A: "A", TYPE_TXT: "TXT", TYPE_MX: "MX"}.get(qtype)
        if type_name is None:
            return None
        return entry.get(type_name)

    @classmethod
    def from_zone_text(cls, text: str, persona: Persona) -> "DNSZone":
        """Parse a tiny zone-file dialect into a DNSZone.

        Supported lines: ``name TYPE value`` (whitespace separated).
        ``@`` stands for the persona domain; ``name@`` for a subdomain of
        it. Blank lines and ``;`` comments are ignored.
        """
        zone = cls(persona=persona, records={})
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split(None, 2)
            if len(parts) != 3:
                continue
            name, rtype, value = parts
            name = name.lower()
            if name == "@":
                name = persona.domain
            elif name.endswith("@"):
                name = f"{name[:-1]}.{persona.domain}"
            zone.records.setdefault(name, {})[rtype.upper()] = value
        return zone


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS label wire format."""
    out = bytearray()
    for label in name.strip(".").split("."):
        raw = label.encode("ascii", "replace")[:63]
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def parse_question(data: bytes) -> tuple[int, DNSQuestion] | None:
    """Parse header + first question. Returns (txid, question) or None."""
    if len(data) < 12:
        return None
    txid, flags, qdcount = struct.unpack(">HHH", data[:6])
    if qdcount < 1:
        return None
    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:  # compression pointer in a query: malformed
            return None
        if offset + 1 + length > len(data):
            return None
        labels.append(data[offset + 1:offset + 1 + length])
        offset += 1 + length
    else:
        return None
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    name = b".".join(labels).decode("ascii", "replace").lower()
    return txid, DNSQuestion(name=name, qtype=qtype, qclass=qclass)


def build_response(txid: int, question: DNSQuestion, *, rcode: int,
                   answers: list[tuple[int, bytes]] | None = None,
                   soa_name: str = "") -> bytes:
    """Build a DNS response packet for one question.

    ``answers`` is a list of (rtype, rdata-wire-bytes). NXDOMAIN responses
    carry an SOA record in the authority section so resolvers treat the
    refusal as authoritative.
    """
    answers = answers or []
    flags = 0x8180 | rcode  # QR, RD, RA
    ancount = len(answers) if rcode == RCODE_OK else 0
    nscount = 1 if rcode == RCODE_NXDOMAIN else 0
    header = struct.pack(">HHHHHH", txid, flags, 1, ancount, nscount, 0)
    qname = encode_name(question.name)
    qsection = qname + struct.pack(">HH", question.qtype, question.qclass)
    body = b""
    if rcode == RCODE_OK:
        for rtype, rdata in answers:
            # name pointer to offset 12 (the question name)
            body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata))
            body += rdata
    elif rcode == RCODE_NXDOMAIN:
        soa = soa_name or question.name
        rdata = (encode_name(soa) + encode_name(f"admin.{soa}") +
                 struct.pack(">IIIII", 1, 3600, 900, 604800, 86400))
        body += b"\xc0\x0c" + struct.pack(">HHIH", 6, 1, 300, len(rdata))
        body += rdata
    return header + qsection + body


def rdata_for(qtype: int, value: str) -> bytes:
    """Encode a zone value into rdata wire bytes for its type."""
    if qtype == TYPE_A:
        try:
            return bytes(int(x) for x in value.split("."))
        except ValueError:
            return b"\x7f\x00\x00\x01"
    if qtype == TYPE_TXT:
        raw = value.encode("utf-8", "replace")[:255]
        return bytes([len(raw)]) + raw
    if qtype == TYPE_MX:
        parts = value.split(None, 1)
        pref = int(parts[0]) if parts[0].isdigit() else 10
        host = parts[1] if len(parts) > 1 else parts[0]
        return struct.pack(">H", pref) + encode_name(host)
    return b""


class DNSHandler(UDPProtocolHandler):
    """UDP DNS decoy: log the question, answer from the fake zone."""

    service = "dns"

    def handle(self) -> None:
        data, _sock = self.request
        zone: DNSZone = getattr(self.server, "dns_zone", None) or DNSZone(
            persona=self.persona)
        parsed = parse_question(data)
        if parsed is None:
            self.emit("malformed_query", severity="notice",
                      data=data[:64].hex())
            return
        txid, question = parsed
        self.emit("query", data=question.name, qtype=question.qtype)
        value = zone.lookup(question.name, question.qtype)
        if value is not None:
            rdata = rdata_for(question.qtype, value)
            response = build_response(txid, question, rcode=RCODE_OK,
                                      answers=[(question.qtype, rdata)])
            self.emit("answer", data=question.name, value=value)
        else:
            response = build_response(txid, question, rcode=RCODE_NXDOMAIN,
                                      soa_name=self.persona.domain)
            self.emit("nxdomain", data=question.name)
        self.reply(response)
