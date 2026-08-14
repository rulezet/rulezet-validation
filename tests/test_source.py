"""Tag production: the half that runs with no network and no yara."""

import re

import pytest

from rulezet_validation.source import platform_tags, vulns

CFGS = [
    (re.compile(r"\bupx\b", re.I), 'runtime-packer:pe="upx"'),
    (
        re.compile(r"\bransom(ware)?\b", re.I),
        'ms-caro-malware-full:malware-type="Ransom"',
    ),
]


def test_vulns_accepts_every_shape_the_column_arrives_in():
    assert vulns({"cve_id": '["CVE-2021-44228", "GHSA-j8v8-6h6r-m6pq"]'}) == [
        "CVE-2021-44228",
        "GHSA-J8V8-6H6R-M6PQ",
    ]
    assert vulns({"cve_id": "CVE-2025-53521"}) == ["CVE-2025-53521"]
    assert vulns({"cve_id": None}) == []
    assert vulns({}) == []


def test_en_dash_is_normalised():
    # Some imports carry a typographic dash, which would otherwise produce a
    # tag no consumer can match on.
    assert vulns({"cve_id": "CVE–2021–44228"}) == ["CVE-2021-44228"]


def test_platform_tags_from_description_and_title():
    tags = platform_tags(
        {
            "title": "Win32_Ransomware_LockBit",
            "description": "packed with UPX",
            "cve_id": "CVE-2021-44228",
        },
        CFGS,
    )
    assert 'runtime-packer:pe="upx"' in tags
    assert "cve:CVE-2021-44228" in tags
    # From the title alone, which only works because `_` is normalised away.
    # This is the assert that fails if that ever gets "simplified" out.
    assert 'ms-caro-malware-full:malware-type="Ransom"' in tags


def test_tags_stay_in_rulezet_vocabulary():
    """No routing, no prefixing, no local taxonomy. Whatever Rulezet would say."""
    tags = platform_tags({"title": "ransomware", "description": ""}, CFGS)
    assert tags == ['ms-caro-malware-full:malware-type="Ransom"']


def test_a_rule_matching_nothing_gets_no_tags():
    assert platform_tags({"title": "x", "description": "y"}, CFGS) == []


def test_keyless_rows_cannot_produce_vulnerability_tags():
    """The public endpoint omits cve_id entirely, so there is nothing to read.

    Not a defect to fix here -- a fact to surface. `sync` says so out loud.
    """
    keyless_row = {
        "uuid": "u1",
        "title": "Log4Shell_Detector",
        "description": "detects exploitation attempts",
        "content": "rule x { condition: true }",
        "author": "someone",
        "creation_date": "2024-01-01",
        "format": "yara",
    }
    assert vulns(keyless_row) == []


# --- .env -------------------------------------------------------------------


def _env_file(tmp_path, body):
    (tmp_path / ".env").write_text(body)
    return tmp_path


def test_dotenv_is_read_without_being_exported(tmp_path, monkeypatch):
    """`source .env` sets a shell variable no child inherits. Reading the file
    is the whole point of having one."""
    from rulezet_validation import config

    monkeypatch.chdir(_env_file(tmp_path, 'RULEZET_API_KEY="secret123"\n'))
    monkeypatch.delenv("RULEZET_API_KEY", raising=False)
    assert config.load()["api_key"] == "secret123"


def test_the_real_environment_beats_dotenv(tmp_path, monkeypatch):
    """So a one-shot override on the command line wins over a stale file."""
    from rulezet_validation import config

    monkeypatch.chdir(_env_file(tmp_path, "RULEZET_API_KEY=from_file\n"))
    monkeypatch.setenv("RULEZET_API_KEY", "from_env")
    assert config.load()["api_key"] == "from_env"


def test_dotenv_handles_what_dotenvs_actually_contain(tmp_path, monkeypatch):
    from rulezet_validation import config

    monkeypatch.chdir(
        _env_file(
            tmp_path,
            "# a comment\n\n"
            "export RULEZET_API_KEY='single'\n"
            "RULEZET_BASELINE_MAX_FILES=7\n"
            "malformed line without equals\n",
        )
    )
    monkeypatch.delenv("RULEZET_API_KEY", raising=False)
    monkeypatch.delenv("RULEZET_BASELINE_MAX_FILES", raising=False)
    s = config.load()
    assert s["api_key"] == "single"
    assert s["baseline_max_files"] == 7


def test_an_inline_hash_is_not_a_comment(tmp_path, monkeypatch):
    """Truncating a credential is worse than not supporting trailing comments."""
    from rulezet_validation import config

    monkeypatch.chdir(_env_file(tmp_path, "RULEZET_API_KEY=abc#def\n"))
    monkeypatch.delenv("RULEZET_API_KEY", raising=False)
    assert config.load()["api_key"] == "abc#def"


def test_no_dotenv_is_not_an_error(tmp_path, monkeypatch):
    from rulezet_validation import config

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("RULEZET_API_KEY", raising=False)
    assert config.load()["api_key"] == ""


def test_a_rejected_key_is_reported_not_traced(monkeypatch):
    """A typo'd credential is a user error; a stack trace buries the one fact
    that matters."""
    import urllib.error

    from rulezet_validation import source

    def forbidden(*a, **k):
        raise urllib.error.HTTPError("u", 403, "FORBIDDEN", {}, None)

    monkeypatch.setattr(source, "_post", forbidden)
    with pytest.raises(ValueError, match="rejected the API key"):
        source.fetch_rules({"api_key": "bad"}, log=lambda *_: None)


def test_nothing_new_is_not_an_error(monkeypatch):
    """An incremental sync with no updates answers 404."""
    import urllib.error

    from rulezet_validation import source

    def not_found(*a, **k):
        raise urllib.error.HTTPError("u", 404, "No rules found to dump.", {}, None)

    monkeypatch.setattr(source, "_post", not_found)
    assert source.fetch_rules({"api_key": "ok"}, log=lambda *_: None) == []


def test_every_setting_has_an_environment_equivalent():
    """The README claims this. Keep it true."""
    from rulezet_validation import config

    assert set(config.DEFAULTS) == set(config.ENV.values())


def test_boolean_and_list_settings_coerce_from_the_environment(monkeypatch):
    from rulezet_validation import config

    monkeypatch.setenv("RULEZET_BASELINE_PROBES", "false")
    monkeypatch.setenv("RULEZET_ALLOW_LICENSES", "cc0 1.0:cc by 4.0")
    s = config.load()
    assert s["baseline_probes"] is False
    assert s["allow_licenses"] == ["cc0 1.0", "cc by 4.0"]
