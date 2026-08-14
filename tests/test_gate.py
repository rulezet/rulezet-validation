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
    # Shipped defaults are real patterns; tests assert on their own.
    s["baseline_exclude_defaults"] = False
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
    assert doc["baseline"]["count"] == 1
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


# --- evidence ---------------------------------------------------------------


def test_the_record_names_every_file_not_a_sample(tmp_path):
    """"and 297 others" is not something a reviewer can check."""
    s, p = _setup(tmp_path)
    for i in range(6):
        (tmp_path / "clean" / f"more{i}.bin").write_bytes(b"\x7fELF filler\n")
    gate.gate(_compiled(p), p, s, log=lambda *_: None)

    e = json.loads(p["quarantine_json"].read_text())["quarantined"]["noisy-uuid"]
    assert e["hits"] == 7
    assert len(e["matched"]) == 7
    assert {m["file"] for m in e["matched"]} == {"benign.bin"} | {
        f"more{i}.bin" for i in range(6)
    }


def test_every_match_carries_a_sha256_and_offsets(tmp_path):
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    m = json.loads(p["quarantine_json"].read_text())["quarantined"]["noisy-uuid"][
        "matched"
    ][0]
    assert len(m["sha256"]) == 64
    assert m["offsets"] == ["0x1"]  # "ELF" at offset 1, after the 0x7f
    assert m["strings"] == ["$a"]


def test_hashes_are_full_length(tmp_path):
    """A field called sha256 holding 16 characters is a lie."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    doc = json.loads(p["quarantine_json"].read_text())
    assert len(doc["quarantined"]["noisy-uuid"]["rule_sha256"]) == 64
    assert len(doc["baseline"]["signature"]) == 64
    assert all(len(f["sha256"]) == 64 for f in doc["baseline"]["files"])


def test_the_baseline_is_recorded_file_by_file(tmp_path):
    """"fired on 300 clean binaries" is not a reproducible claim."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    baseline = json.loads(p["quarantine_json"].read_text())["baseline"]
    assert baseline["count"] == 1
    assert baseline["files"][0]["name"] == "benign.bin"
    assert baseline["files"][0]["size"] == 22


def test_editing_a_baseline_file_in_place_is_now_detected(tmp_path):
    """The old name+size signature could not see this."""
    s, p = _setup(tmp_path)
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    assert gate.stale(p, s) == {}
    same_length = (tmp_path / "clean" / "benign.bin").read_bytes().replace(b"a", b"b")
    (tmp_path / "clean" / "benign.bin").write_bytes(same_length)
    assert gate.stale(p, s) == {"noisy-uuid": "baseline_changed"}


# --- exclusions -------------------------------------------------------------


def test_re_tools_can_be_kept_out_of_the_clean_corpus(tmp_path):
    """DIE and capa ship malware signatures on purpose. A rule firing on them
    is working, not failing, and leaving them in would quarantine good rules."""
    s, p = _setup(tmp_path, baseline_exclude=["capa*", "die"])
    (tmp_path / "clean" / "capa").write_bytes(b"\x7fELF signature database\n")
    (tmp_path / "clean" / "die").write_bytes(b"\x7fELF detect it easy\n")

    names = {f.name for f in gate.baseline_files(s)}
    assert "capa" not in names and "die" not in names
    assert "benign.bin" in names


def test_exclusions_match_full_paths_too(tmp_path):
    s, p = _setup(tmp_path, baseline_exclude=[str(tmp_path / "clean" / "tools") + "/*"])
    tools = tmp_path / "clean" / "tools"
    tools.mkdir()
    (tools / "capa").write_bytes(b"\x7fELF\n")
    assert all("tools" not in str(f) for f in gate.baseline_files(s))


def test_the_exclusion_list_is_recorded_with_the_verdict(tmp_path):
    """A verdict reached by ignoring half the corpus must say so."""
    s, p = _setup(tmp_path, baseline_exclude=["notreal*"])
    (tmp_path / "clean" / "notreal.bin").write_bytes(b"\x7fELF\n")
    gate.gate(_compiled(p), p, s, log=lambda *_: None)
    baseline = json.loads(p["quarantine_json"].read_text())["baseline"]
    assert "notreal*" in baseline["exclude_patterns"]
    assert baseline["excluded_files"] == ["notreal.bin"]


def test_the_shipped_exclusions_are_real_and_justified(tmp_path):
    """The list ships because the reasoning is universal, not per-machine."""
    patterns = gate.default_excludes()
    assert "capa*" in patterns
    assert "upx" in patterns
    assert any(p.startswith("msf") for p in patterns)
    # binutils must never be in here: excluding it would have hidden ELF_Mirai
    # firing on 21 clean binaries.
    assert not {"objdump", "nm", "ld", "readelf", "strings"} & set(patterns)


def test_shipped_defaults_apply_on_top_of_local_config(tmp_path):
    s, p = _setup(tmp_path, baseline_exclude_defaults=True, baseline_exclude=["mine*"])
    (tmp_path / "clean" / "capa").write_bytes(b"\x7fELF\n")
    (tmp_path / "clean" / "mine.bin").write_bytes(b"\x7fELF\n")
    kept, excluded = gate.collect_baseline(s)
    assert {f.name for f in excluded} == {"capa", "mine.bin"}
    assert "benign.bin" in {f.name for f in kept}


def test_defaults_can_be_turned_off(tmp_path):
    s, p = _setup(tmp_path, baseline_exclude_defaults=False)
    (tmp_path / "clean" / "capa").write_bytes(b"\x7fELF\n")
    assert "capa" in {f.name for f in gate.baseline_files(s)}


def test_excluding_a_file_does_not_cost_a_slot_in_the_corpus(tmp_path):
    """Otherwise turning on an exclusion silently shrinks what gets scanned."""
    s, p = _setup(tmp_path, baseline_exclude=["skip*"], baseline_max_files=2)
    for i in range(2):
        (tmp_path / "clean" / f"skip{i}.bin").write_bytes(b"\x7fELF\n")
    (tmp_path / "clean" / "zz.bin").write_bytes(b"\x7fELF\n")
    kept, _ = gate.collect_baseline(s)
    assert {f.name for f in kept} == {"benign.bin", "zz.bin"}


def test_the_baseline_samples_the_whole_directory(tmp_path):
    """A prefix of a sorted /usr/bin is everything from `[` to `cmp`. A rule
    that only fires on `zsh` would pass a gate that never looks past `c`."""
    d = tmp_path / "many"
    d.mkdir()
    for i in range(100):
        (d / f"{i:03d}.bin").write_bytes(b"\x7fELF\n")
    s, _ = _setup(tmp_path, baseline_dirs=[str(d)], baseline_max_files=10)

    names = sorted(f.name for f in gate.baseline_files(s))
    assert len(names) == 10
    assert names[0] == "000.bin"
    assert names[-1] == "090.bin"  # spread, not 000-009


def test_sampling_is_deterministic(tmp_path):
    d = tmp_path / "many"
    d.mkdir()
    for i in range(50):
        (d / f"{i:03d}.bin").write_bytes(b"\x7fELF\n")
    s, _ = _setup(tmp_path, baseline_dirs=[str(d)], baseline_max_files=7)
    assert gate.baseline_files(s) == gate.baseline_files(s)
