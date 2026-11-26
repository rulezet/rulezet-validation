import pytest

from rulezet_validation import cli

pytest.importorskip("yara")

NOISY = 'rule noisy { strings: $a = "ELF" condition: $a }'
QUIET = 'rule quiet { strings: $a = "never-present-xyz" condition: $a }'


def _cfg(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "benign.bin").write_bytes(b"\x7fELF and nothing else\n")
    cfg = tmp_path / "c.toml"
    cfg.write_text(
        f'baseline_dirs = ["{clean}"]\nbaseline_probes = false\n'
        "baseline_exclude_defaults = false\n"
    )
    return str(cfg)


def test_check_reports_firing_and_clean_rules(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "noisy.yar").write_text(NOISY)
    (rules / "quiet.yara").write_text(QUIET)
    (rules / "broken.yar").write_text("rule {")
    assert cli.main(["--config", _cfg(tmp_path), "check", str(rules)]) == 1
    out = capsys.readouterr().out
    assert f"FIRES\t{rules / 'noisy.yar'}" in out
    assert f"CLEAN\t{rules / 'quiet.yara'}" in out
    assert f"BROKEN\t{rules / 'broken.yar'}" in out


def test_bare_path_means_check(tmp_path, capsys):
    rule = tmp_path / "quiet.yar"
    rule.write_text(QUIET)
    assert cli.main(["--config", _cfg(tmp_path), str(rule)]) == 0
    assert "CLEAN" in capsys.readouterr().out


def test_check_scans_past_the_gate_cap(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    (tmp_path / "clean" / "second.bin").write_bytes(b"\x7fELF again\n")
    with open(cfg, "a") as f:
        f.write("baseline_max_files = 1\n")
    rule = tmp_path / "noisy.yar"
    rule.write_text(NOISY)
    assert cli.main(["--config", cfg, "check", str(rule)]) == 1
    assert f"FIRES\t{rule}\t2 files" in capsys.readouterr().out
