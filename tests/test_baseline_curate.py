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
        b"Package: huge\nSection: utils\nSize: 99999999\n"
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


def test_ports_download_from_mirror_first_then_snapshot(tmp_path, monkeypatch):
    calls = []

    def fake(entry, cache, verify, attempts=3):
        calls.append(entry["url"])
        if entry["url"].startswith(baseline_curate.MIRROR):
            raise OSError("404")
        return tmp_path / entry["name"]

    monkeypatch.setattr(baseline_curate, "_download", fake)
    url = baseline_curate.SNAPSHOT + "pool/main/x/x/x_1_arm64.deb"
    baseline_curate._package({"url": url, "sha256": "0"}, tmp_path, True)
    assert calls == [baseline_curate.MIRROR + "pool/main/x/x/x_1_arm64.deb", url]


def test_openwrt_ipk_members_yield_only_elf_under_binary_dirs(tmp_path):
    import io
    import tarfile

    def tar_gz(entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    data = tar_gz([
        ("./usr/sbin/tool", b"\x7fELF arm"),
        ("./etc/config/tool", b"\x7fELF not a binary dir"),
        ("./usr/bin/script", b"#!/bin/sh"),
    ])
    ipk = tmp_path / "tool.ipk"
    ipk.write_bytes(tar_gz([("./debian-binary", b"2.0\n"), ("./data.tar.gz", data)]))
    found = list(baseline_curate._members({"source": "openwrt-arm_xscale-base"}, ipk))
    assert [n for n, _ in found] == ["usr/sbin/tool"]
