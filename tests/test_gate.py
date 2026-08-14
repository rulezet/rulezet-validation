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
    # released_file defaults to a cwd-relative path, which across a suite means
    # one test's decision leaks into the next. Pin it per-test.
    s["released_file"] = str(tmp_path / "released.txt")
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


# --- Revisiting a decision --------------------------------------------------


def test_a_fresh_verdict_is_not_stale(tmp_path):
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    assert gate.stale(p, s) == {}


def test_an_upstream_fix_makes_the_verdict_stale(tmp_path):
    """The whole point: a quarantine must not outlive the rule it judged."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    (p["quarantine"] / "noisy-uuid.yara").write_text(QUIET)  # author fixed it
    assert gate.stale(p, s) == {"noisy-uuid": "rule_changed"}


def test_changing_the_baseline_makes_every_verdict_stale(tmp_path):
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    (tmp_path / "clean" / "another.bin").write_bytes(b"more clean bytes\n")
    assert gate.stale(p, s) == {"noisy-uuid": "baseline_changed"}


def test_verdicts_without_a_hash_cannot_claim_to_still_hold(tmp_path):
    """A mirror gated before hashes existed has nothing to compare against."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    doc = json.loads(p["quarantine_json"].read_text())
    del doc["quarantined"]["noisy-uuid"]["rule_sha256"]
    p["quarantine_json"].write_text(json.dumps(doc))
    assert gate.stale(p, s) == {"noisy-uuid": "unverifiable"}


def test_recheck_clears_a_rule_that_no_longer_fires(tmp_path):
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    (p["quarantine"] / "noisy-uuid.yara").write_text(QUIET)

    result = gate.recheck(p, s, log=lambda *_: None)
    assert result["cleared"] == ["noisy-uuid"]
    assert (p["rules"] / "noisy-uuid.yara").exists()
    assert not (p["quarantine"] / "noisy-uuid.yara").exists()


def test_recheck_re_quarantines_a_rule_that_still_fires(tmp_path):
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    result = gate.recheck(p, s, log=lambda *_: None)
    assert result["cleared"] == []
    assert (p["quarantine"] / "noisy-uuid.yara").exists()


def test_recheck_preserves_first_seen(tmp_path):
    """Re-trying a rule is not the same as meeting it for the first time."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    first = json.loads(p["quarantine_json"].read_text())
    gate.recheck(p, s, log=lambda *_: None)
    second = json.loads(p["quarantine_json"].read_text())
    assert (
        second["quarantined"]["noisy-uuid"]["first_seen"]
        == first["quarantined"]["noisy-uuid"]["first_seen"]
    )


def test_recheck_honours_released(tmp_path):
    """A human decision is not something a re-run gets to overturn."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    p["released"].write_text("noisy-uuid\n")
    gate.recheck(p, s, log=lambda *_: None)
    assert (p["rules"] / "noisy-uuid.yara").exists()


def test_recheck_can_be_scoped_to_specific_uuids(tmp_path):
    s, p = _setup(tmp_path)
    (p["quarantine"] / "unrelated.yara").write_text(QUIET)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    result = gate.recheck(p, s, uuids=["noisy-uuid"], log=lambda *_: None)
    assert result["rechecked"] == ["noisy-uuid"]
    assert (p["quarantine"] / "unrelated.yara").exists()


def test_a_cleared_rule_is_marked_not_erased(tmp_path):
    """History is kept, but a past verdict must not read as a current one."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    assert json.loads(p["quarantine_json"].read_text())["quarantined"]["noisy-uuid"][
        "status"
    ] == "quarantined"

    (p["quarantine"] / "noisy-uuid.yara").write_text(QUIET)
    gate.recheck(p, s, log=lambda *_: None)

    entry = json.loads(p["quarantine_json"].read_text())["quarantined"]["noisy-uuid"]
    assert entry["status"] == "cleared"
    assert entry["first_seen"]
    assert "noisy-uuid\tnoisy" in p["quarantine_log"].read_text()


CONSOLE_RULE = """
import "console"
rule chatty {
    condition:
        console.log("The Magic Header : ", uint16(0)) and uint16(0) == 0x457f
}
"""


def test_rules_do_not_get_to_write_to_our_stdout(tmp_path, capsys):
    """`console.log()` prints straight from the C library, and because it
    returns true it is chained with `and` -- so it fires while the condition is
    being evaluated, not only on a match. Across a real baseline that buries
    the result."""
    s, p = _setup(tmp_path)
    (tmp_path / "clean" / "elfish.bin").write_bytes(b"\x7fELF padding\n")
    (p["rules"] / "chatty-uuid.yara").write_text(CONSOLE_RULE)

    logged = []
    gate.scan_baseline(_compiled(p), gate.baseline_files(s), log=logged.append)

    assert "The Magic Header" not in capsys.readouterr().out
    assert any("console messages from rules suppressed" in line for line in logged)


def test_released_lives_outside_the_mirror(tmp_path):
    """It is a hand-written record meant to be committed; the mirror is
    gitignored build output that gets wiped."""
    s, p = _setup(tmp_path)
    assert p["root"] not in p["released"].parents


def test_the_old_in_mirror_location_is_still_honoured(tmp_path):
    """Upgrading must not silently drop decisions someone already reviewed."""
    s, p = _setup(tmp_path)
    p["released_legacy"].parent.mkdir(parents=True, exist_ok=True)
    p["released_legacy"].write_text("noisy-uuid\n")
    assert gate.gate(_compiled(p), p, s, log=lambda *_: None) == {}
    assert (p["rules"] / "noisy-uuid.yara").exists()
