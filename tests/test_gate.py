"""The gate: what gets quarantined, what does not, and what is recorded."""

import json

import pytest

from rulezet_validation import config, gate, mirror

yara = pytest.importorskip("yara")

NOISY = 'rule noisy { strings: $a = "ELF" condition: $a }'
QUIET = 'rule quiet { strings: $a = "NOTHING_LIKE_THIS_EXISTS_9271" condition: $a }'


def _setup(tmp_path, **over):
    """A mirror with one rule that fires on the baseline and one that does not."""
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "benign.bin").write_bytes(b"\x7fELF and nothing else\n")

    s = dict(config.DEFAULTS)
    s["mirror_dir"] = str(tmp_path / "mirror")
    s["baseline_dirs"] = [str(clean)]
    s["baseline_probes"] = False  # deterministic corpus for the test
    s.update(over)

    p = config.paths(s)
    p["rules"].mkdir(parents=True, exist_ok=True)
    p["quarantine"].mkdir(parents=True, exist_ok=True)
    (p["rules"] / "noisy-uuid.yara").write_text(NOISY)
    (p["rules"] / "quiet-uuid.yara").write_text(QUIET)
    return s, p


def _compiled(p):
    return mirror.compile_mirror(p, log=lambda *_: None)


def test_only_rules_that_fired_are_quarantined(tmp_path):
    s, p = _setup(tmp_path)
    hits = gate.gate(_compiled(p), p, s, log=lambda *_: None)
    assert set(hits) == {"noisy-uuid"}
    assert (p["quarantine"] / "noisy-uuid.yara").exists()
    assert (p["rules"] / "quiet-uuid.yara").exists()
    assert not (p["rules"] / "noisy-uuid.yara").exists()


def test_released_uuids_are_never_quarantined(tmp_path):
    s, p = _setup(tmp_path)
    p["released"].write_text(
        "# reviewed: capability rule, hit is correct\nnoisy-uuid\n"
    )
    hits = gate.gate(_compiled(p), p, s, log=lambda *_: None)
    assert hits == {}
    assert (p["rules"] / "noisy-uuid.yara").exists()


def test_quarantine_json_and_txt_describe_the_same_rules(tmp_path):
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    doc = json.loads(p["quarantine_json"].read_text())
    assert doc["quarantined"]["noisy-uuid"]["rule"] == "noisy"
    assert doc["quarantined"]["noisy-uuid"]["reason"] == "baseline_hit"
    assert doc["baseline"]["files"] == 1
    txt = p["quarantine_log"].read_text()
    assert "noisy-uuid\tnoisy" in txt


def test_history_survives_a_later_run(tmp_path):
    """A quarantined rule leaves the compiled set, so a second run cannot
    re-observe it. Rewriting from scratch would erase the first decision."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    first = json.loads(p["quarantine_json"].read_text())
    first_seen = first["quarantined"]["noisy-uuid"]["first_seen"]

    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    second = json.loads(p["quarantine_json"].read_text())
    assert "noisy-uuid" in second["quarantined"]
    assert second["quarantined"]["noisy-uuid"]["first_seen"] == first_seen


def test_hand_moved_rules_still_get_listed(tmp_path):
    s, p = _setup(tmp_path)
    (p["quarantine"] / "by-hand.yara").write_text(QUIET)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    doc = json.loads(p["quarantine_json"].read_text())
    assert doc["quarantined"]["by-hand"]["reason"] == "unrecorded"


def test_scan_baseline_moves_nothing(tmp_path):
    s, p = _setup(tmp_path)
    hits = gate.scan_baseline(_compiled(p), gate.baseline_files(s), log=lambda *_: None)
    assert set(hits) == {"noisy-uuid"}
    assert (p["rules"] / "noisy-uuid.yara").exists()


def test_bundled_probes_are_part_of_the_default_baseline(tmp_path):
    """The blind spot this whole tool exists to close: a baseline of /usr/bin
    alone cannot judge a rule that fingerprints static embedded libc."""
    s, _ = _setup(tmp_path, baseline_probes=True)
    names = {f.name for f in gate.baseline_files(s)}
    assert "clean_uclibc_fcntl.elf" in names
    assert "clean_uclibc_printf.elf" in names
