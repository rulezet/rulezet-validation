"""Writing the mirror to disk: rule files, tag sidecar, state."""

import json

import pytest

from rulezet_validation import config, mirror

RULE_TEXT = 'rule fixture_ok { strings: $a = "CANARY_9271" condition: $a }'


def _settings(tmp_path, **over):
    s = dict(config.DEFAULTS)
    s["mirror_dir"] = str(tmp_path / "mirror")
    s.update(over)
    return s


def _paths(tmp_path, **over):
    return config.paths(_settings(tmp_path, **over))


def _rule(uuid="u1", **over):
    row = {
        "uuid": uuid,
        "to_string": RULE_TEXT,
        "title": "Win32_Ransomware_LockBit",
        "description": "packed with UPX",
        "license": "CC0 1.0",
    }
    row.update(over)
    return row


def test_write_rules_uses_the_uuid_as_the_filename(tmp_path):
    p = _paths(tmp_path)
    p["quarantine"].mkdir(parents=True, exist_ok=True)
    _tags, rows = mirror.write_rules(
        [_rule()], [], p, _settings(tmp_path), log=lambda *_: None
    )
    assert (p["rules"] / "u1.yara").read_text() == RULE_TEXT
    assert rows["u1"]["name"] == "Win32_Ransomware_LockBit"


def test_license_filter_skips_disallowed_rules(tmp_path):
    s = _settings(tmp_path, allow_licenses=["cc by 4.0"])
    p = config.paths(s)
    p["quarantine"].mkdir(parents=True, exist_ok=True)
    tags, rows = mirror.write_rules([_rule()], [], p, s, log=lambda *_: None)
    assert rows == {}
    assert not (p["rules"] / "u1.yara").exists()


def test_a_quarantined_rule_is_updated_in_place_not_readmitted(tmp_path):
    """New text lands in quarantine/, never back in rules/.

    Readmitting it would silently undo the gate. Skipping it entirely -- the
    other obvious option -- would pin the rule at the version that was
    quarantined, so an upstream fix could never arrive and the recorded verdict
    would describe bytes that no longer exist.
    """
    p = _paths(tmp_path)
    p["quarantine"].mkdir(parents=True, exist_ok=True)
    (p["quarantine"] / "u1.yara").write_text("rule old_version { condition: false }")
    mirror.write_rules([_rule()], [], p, _settings(tmp_path), log=lambda *_: None)
    assert not (p["rules"] / "u1.yara").exists()
    assert (p["quarantine"] / "u1.yara").read_text() == RULE_TEXT


def test_merge_tags_only_ever_adds(tmp_path):
    p = _paths(tmp_path)
    p["root"].mkdir(parents=True, exist_ok=True)
    mirror.merge_tags({"u1": ["cve:CVE-2021-44228"]}, p)
    merged = mirror.merge_tags({"u1": ['runtime-packer:pe="upx"']}, p)
    assert merged["u1"] == ['cve:CVE-2021-44228', 'runtime-packer:pe="upx"']


def test_state_is_merged_not_replaced(tmp_path):
    p = _paths(tmp_path)
    p["root"].mkdir(parents=True, exist_ok=True)
    mirror.write_state(p, last_sync="2026-08-13 10:00")
    state = mirror.write_state(p, baseline={"files": 12})
    assert state["last_sync"] == "2026-08-13 10:00"
    assert json.loads(p["state"].read_text())["baseline"]["files"] == 12


def test_compile_drops_unparseable_rules_instead_of_failing(tmp_path):
    """One bad rule in 130k must not cost the whole compile."""
    pytest.importorskip("yara")
    p = _paths(tmp_path)
    p["rules"].mkdir(parents=True, exist_ok=True)
    (p["rules"] / "good.yara").write_text(RULE_TEXT)
    (p["rules"] / "bad.yara").write_text("rule broken { condition: ")
    rules = mirror.compile_mirror(p, log=lambda *_: None)
    assert rules is not None
    assert not (p["rules"] / "bad.yara").exists()
    assert p["compiled"].exists()


def test_license_filter_refuses_to_run_keyless(tmp_path, monkeypatch):
    """Otherwise it silently skips all 130k rules and reports an empty mirror."""
    monkeypatch.delenv("RULEZET_API_KEY", raising=False)
    from rulezet_validation.sync import sync

    s = _settings(tmp_path, allow_licenses=["cc0 1.0"], api_key="")
    with pytest.raises(ValueError, match="allow_licenses"):
        sync(s, config.paths(s), log=lambda *_: None)
