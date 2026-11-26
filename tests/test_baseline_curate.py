"""The curated lock is deterministic and rejects altered package members."""

import hashlib
import json
import lzma

import pytest

from rulezet_validation import baseline_curate


def test_ubuntu_selection_filters_sections_and_size():
    index = lzma.compress(
        b"Package: tool\nSection: utils\nSize: 100\n"
        b"Filename: pool/tool.deb\nSHA256: abc\n\n"
        b"Package: doc\nSection: doc\nSize: 100\n"
        b"Filename: pool/doc.deb\nSHA256: def\n\n"
        b"Package: huge\nSection: utils\nSize: 9999999\n"
        b"Filename: pool/huge.deb\nSHA256: ghi\n\n"
    )
    packages = list(baseline_curate._ubuntu(index))
    assert [package["name"] for package in packages] == ["tool"]
    assert packages[0]["sha256"] == "abc"


def test_locked_sync_rejects_changed_file(tmp_path, monkeypatch):
    content = b"\x7fELF original"
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "tool",
                        "source": "ubuntu-noble-main",
                        "url": "https://example.test/tool.deb",
                        "sha256": "0" * 64,
                    }
                ],
                "files": [
                    {
                        "package": "tool",
                        "member": "usr/bin/tool",
                        "output": "ubuntu-noble-main/tool/tool",
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                ],
            }
        )
    )
    monkeypatch.setattr(baseline_curate, "_download", lambda *_: tmp_path / "tool.deb")
    monkeypatch.setattr(
        baseline_curate,
        "_members",
        lambda *_: iter([("usr/bin/tool", b"\x7fELF changed")]),
    )
    with pytest.raises(ValueError, match="file SHA-256 mismatch"):
        baseline_curate.sync_locked(lock, tmp_path / "output", tmp_path / "cache")
    assert not (tmp_path / "output").exists()
