"""Tests for the deception score checks and grading."""

from honeypot_server.core.persona import Persona
from honeypot_server.intel.deception import (
    CheckResult,
    check_identity_consistency,
    check_os_consistency,
    check_revealing_words,
    check_roster_realism,
    check_timing_plausibility,
    check_version_plausibility,
    grade_label,
    score_deployment,
)


class TestGradeLabel:
    def test_boundaries(self):
        assert grade_label(100) == "A"
        assert grade_label(90) == "A"
        assert grade_label(89) == "B"
        assert grade_label(75) == "B"
        assert grade_label(74) == "C"
        assert grade_label(60) == "C"
        assert grade_label(59) == "D"
        assert grade_label(40) == "D"
        assert grade_label(39) == "F"
        assert grade_label(0) == "F"


class TestChecks:
    def test_revealing_words_clean(self):
        result = check_revealing_words(Persona.generate(1))
        assert result.passed and result.earned == 20

    def test_revealing_words_caught(self):
        persona = Persona.generate(1)
        persona.versions["http"] = "honeypot-server/1.0"
        result = check_revealing_words(persona)
        assert not result.passed
        assert "http:honeypot" in result.reason

    def test_version_plausibility_passes_for_all_stories(self):
        for seed in range(6):
            persona = Persona.generate(seed)
            result = check_version_plausibility(persona)
            assert result.passed, f"seed {seed}: {result.reason}"

    def test_version_plausibility_flags_odd_versions(self):
        persona = Persona.generate(2)
        persona.versions["redis"] = "2.4.0"
        result = check_version_plausibility(persona)
        assert not result.passed and "redis=2.4.0" in result.reason

    def test_os_consistency_passes_for_all_stories(self):
        for seed in range(6):
            assert check_os_consistency(Persona.generate(seed)).passed

    def test_os_consistency_flags_mismatch(self):
        persona = Persona.generate(3)
        persona.versions["http"] = "Microsoft-IIS/10.0"
        result = check_os_consistency(persona)
        assert not result.passed

    def test_identity_consistency_passes(self):
        assert check_identity_consistency(Persona.generate(4)).passed

    def test_identity_consistency_flags_missing_hostname(self):
        persona = Persona.generate(5)
        original = persona.ftp_banner
        persona.ftp_banner = lambda: "220 ready."
        result = check_identity_consistency(persona)
        assert not result.passed
        persona.ftp_banner = original

    def test_roster_realism_passes(self):
        assert check_roster_realism(Persona.generate(6)).passed

    def test_roster_realism_flags_username_password(self):
        persona = Persona.generate(7)
        persona.users[0].password = persona.users[0].username
        result = check_roster_realism(persona)
        assert not result.passed

    def test_roster_realism_flags_single_user(self):
        persona = Persona.generate(8, user_count=1)
        result = check_roster_realism(persona)
        assert not result.passed

    def test_timing_plausibility(self):
        assert check_timing_plausibility({}).passed
        assert check_timing_plausibility({"http": 0.5}).passed
        mid = check_timing_plausibility({"http": 2.0})
        assert mid.earned == 6 and not mid.passed  # partial credit
        bad = check_timing_plausibility({"http": 5.0})
        assert not bad.passed and "scream tarpit" in bad.reason


class TestScoreDeployment:
    def test_default_persona_scores_high(self):
        report = score_deployment(Persona.default())
        assert report.score >= 90
        assert report.grade == "A"
        assert all(c.passed for c in report.checks)

    def test_tarpit_penalty(self):
        good = score_deployment(Persona.default(), {"http": 0.5})
        bad = score_deployment(Persona.default(), {"http": 8.0})
        assert good.score > bad.score

    def test_observed_banners_extra_check(self):
        report = score_deployment(
            Persona.default(),
            observed_banners={"http": "Server: totally-real/nginx"})
        names = [c.name for c in report.checks]
        assert "observed_banners" in names
        assert report.score <= 100

    def test_observed_banners_reveal_deception(self):
        report = score_deployment(
            Persona.default(),
            observed_banners={"ssh": "SSH-2.0-cowrie honeypot"})
        observed = [c for c in report.checks if c.name == "observed_banners"][0]
        assert observed.earned == 0
        assert report.score < 100

    def test_report_render_and_dict(self):
        report = score_deployment(Persona.default())
        text = report.render()
        assert "Deception score:" in text
        assert "[PASS]" in text
        d = report.to_dict()
        assert d["score"] == report.score
        assert len(d["checks"]) == len(report.checks)

    def test_check_result_to_dict(self):
        c = CheckResult(name="x", weight=10, earned=5, reason="half")
        d = c.to_dict()
        assert d == {"name": "x", "weight": 10, "earned": 5,
                     "passed": False, "reason": "half"}

    def test_all_seeded_personas_pass_identity(self):
        # the persona engine must never produce self-inconsistent stories
        for seed in range(12):
            report = score_deployment(Persona.generate(seed))
            assert report.score >= 75, f"seed {seed} scored {report.score}"
