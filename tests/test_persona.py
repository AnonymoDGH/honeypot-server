"""Tests for the persona engine and tarpit pacing."""

import random

from honeypot_server.core.persona import (
    FakeUser,
    Persona,
    persona_from_seed,
)
from honeypot_server.core.tarpit import (
    MAX_SAFE_DELAY,
    Tarpit,
    TarpitConfig,
    default_configs,
    get_tarpit,
    set_tarpit,
)


class TestPersona:
    def test_generate_is_deterministic(self):
        a = Persona.generate(42)
        b = Persona.generate(42)
        assert a.hostname == b.hostname
        assert a.fqdn == b.fqdn
        assert a.versions == b.versions
        assert a.usernames() == b.usernames()

    def test_different_seeds_differ(self):
        a = Persona.generate(1)
        b = Persona.generate(2)
        assert (a.hostname, a.fqdn, a.os) != (b.hostname, b.fqdn, b.os)

    def test_fqdn_contains_hostname_and_domain(self):
        p = Persona.generate(7)
        assert p.fqdn == f"{p.hostname}.{p.domain}"
        assert "." in p.domain

    def test_banners_are_consistent_with_story(self):
        p = Persona.generate(3)
        assert p.ssh_banner().startswith("SSH-2.0-")
        assert p.versions["ssh"] in p.ssh_banner()
        assert p.ftp_banner().startswith("220 ")
        assert p.hostname in p.ftp_banner()
        assert p.smtp_banner().startswith("220 ")
        assert p.fqdn in p.smtp_banner()
        assert p.http_server_header() == p.versions["http"]
        assert p.hostname in p.telnet_banner()

    def test_users_roster(self):
        p = Persona.generate(5, user_count=4)
        assert len(p.users) == 4
        assert p.admin().role == "admin"
        assert len(set(p.usernames())) == 4  # unique
        for u in p.users:
            assert u.password  # every fake account has a fake password
            assert u.home.startswith("/home/")

    def test_user_count_clamped(self):
        assert len(Persona.generate(1, user_count=0).users) == 1
        assert len(Persona.generate(1, user_count=99).users) == 12

    def test_find_user(self):
        p = Persona.generate(9)
        name = p.usernames()[2]
        assert p.find_user(name).username == name
        assert p.find_user("ghost") is None

    def test_fake_user_matches(self):
        u = FakeUser(username="a", password="b", role="admin")
        assert u.matches("a", "b")
        assert not u.matches("a", "c")
        assert not u.matches("A", "b")

    def test_fingerprint_covers_all_surfaces(self):
        fp = Persona.generate(11).fingerprint()
        for key in ("hostname", "fqdn", "os", "ssh", "ftp", "smtp",
                    "http", "telnet", "redis", "mysql"):
            assert fp[key]

    def test_redis_info_line(self):
        p = Persona.generate(4)
        assert p.redis_info_line("redis_version") == p.versions["redis"]
        assert p.os in p.redis_info_line("os")
        assert len(p.redis_info_line("run_id")) == 40
        assert p.redis_info_line("unknown_key") == ""

    def test_persona_from_seed_variants(self):
        assert persona_from_seed(None).seed == 0
        assert persona_from_seed(3).seed == 3
        s1 = persona_from_seed("acme-dc1")
        s2 = persona_from_seed("acme-dc1")
        assert s1.hostname == s2.hostname  # string seeds stable
        assert s1.hostname != persona_from_seed("other").hostname

    def test_default_persona(self):
        assert Persona.default().fqdn == Persona.generate(0).fqdn


class TestTarpit:
    def test_disabled_by_default(self):
        t = Tarpit()
        assert t.delay_for("http") == 0.0
        assert t.wait("http") == 0.0
        assert t.waits == 0

    def test_enable_and_delay_deterministic(self):
        t = Tarpit(seed=1)
        t.enable("http", base=0.5, jitter=0.1)
        d1 = t.delay_for("http")
        t2 = Tarpit(seed=1)
        t2.enable("http", base=0.5, jitter=0.1)
        assert d1 == t2.delay_for("http")
        assert 0.4 <= d1 <= 0.6

    def test_wait_records_sleeps(self):
        slept = []
        t = Tarpit(seed=2, sleep=slept.append)
        t.enable("ftp", base=0.3, jitter=0.0)
        waited = t.wait("ftp")
        assert waited == 0.3 and slept == [0.3]
        assert t.stats() == {"waits": 1, "total_waited": 0.3}

    def test_cap_and_safety_bound(self):
        cfg = TarpitConfig(True, base=100.0, jitter=0.0, cap=2.0)
        t = Tarpit({"http": cfg}, sleep=lambda s: None)
        assert t.delay_for("http") == 2.0
        cfg2 = TarpitConfig(True, base=100.0, jitter=0.0, cap=10_000.0)
        t2 = Tarpit({"http": cfg2}, sleep=lambda s: None)
        assert t2.delay_for("http") == MAX_SAFE_DELAY

    def test_negative_jitter_clamped_to_zero(self):
        cfg = TarpitConfig(True, base=0.05, jitter=1.0, cap=5.0)
        t = Tarpit({"http": cfg}, seed=3, sleep=lambda s: None)
        for _ in range(20):
            assert t.delay_for("http") >= 0.0

    def test_enable_all_and_disable(self):
        t = Tarpit(seed=4, sleep=lambda s: None)
        t.enable(base=0.1, jitter=0.0)
        for svc in ("http", "ftp", "ssh", "telnet"):
            assert t.delay_for(svc) == 0.1
        t.disable("http")
        assert t.delay_for("http") == 0.0
        assert t.delay_for("ftp") == 0.1
        t.disable()
        assert t.delay_for("ftp") == 0.0

    def test_unknown_service_is_disabled(self):
        t = Tarpit()
        assert t.delay_for("gopher") == 0.0
        assert t.wait("gopher") == 0.0

    def test_drip_disabled_sends_one_chunk(self):
        sent = []
        t = Tarpit()
        n = t.drip(sent.append, b"x" * 200, "http", chunk_size=10)
        assert n == 1 and sent == [b"x" * 200]

    def test_drip_enabled_chunks_with_pauses(self):
        sent, slept = [], []
        t = Tarpit(seed=5, sleep=slept.append)
        t.enable("ftp", base=0.2, jitter=0.0)
        payload = b"y" * 100
        n = t.drip(sent.append, payload, "ftp", chunk_size=25)
        assert n == 4
        assert b"".join(sent) == payload
        assert len(slept) == 3  # pause between chunks, not after last
        assert all(s == 0.2 for s in slept)

    def test_drip_empty_payload(self):
        t = Tarpit()
        assert t.drip(lambda b: None, b"", "http") == 0

    def test_default_configs_shape(self):
        cfgs = default_configs()
        assert set(cfgs) == {"http", "ftp", "ssh", "smtp", "dns",
                             "telnet", "redis", "mysql"}
        assert all(not c.enabled for c in cfgs.values())
        assert cfgs["telnet"].base > cfgs["dns"].base

    def test_global_tarpit_accessors(self):
        original = get_tarpit()
        try:
            custom = Tarpit(seed=9)
            set_tarpit(custom)
            assert get_tarpit() is custom
            set_tarpit(None)
            assert get_tarpit() is not custom
        finally:
            set_tarpit(original)
