"""Assemblage selection keeps licenses and pinned bytes explicit."""

import json

from rulezet_validation import baseline_assemblage


def test_rust_candidates_exclude_unreviewed_licenses():
    rows = []
    for name, license_name in (("safe", "MIT License"), ("unsafe", "GPL-3.0")):
        rows.append(
            {
                "tar": f"repos/{name}.tar",
                "stored_bytes": 1000,
                "binaries": 4,
                "license": license_name,
            }
        )
    index = "\n".join(json.dumps(row) for row in rows)
    assert [name for name, _ in baseline_assemblage._rust_candidates(index)] == [
        "repos/safe.tar"
    ]


def test_take_stream_caps_files_per_repository(tmp_path):
    class Stream:
        consumed = 0

    def members(_):
        for n in range(10):
            yield f"m{n}", b"x"

    files = baseline_assemblage._take_stream(
        Stream(),
        members,
        lambda member, c: (
            c,
            {
                "member": member,
                "output": member,
                "repo_url": "same" if member < "m5" else member,
            },
        ),
        6,
        lambda *_: None,
        "test",
        tmp_path,
    )
    assert sorted(x.name for x in tmp_path.iterdir()) == sorted(
        f["member"] for f in files
    )
    repos = [f["repo_url"] for f in files]
    assert repos.count("same") == baseline_assemblage.PER_REPO
    assert len(files) == 6


def test_elf_filter_skips_cmake_probes():
    import tarfile

    class Stream:
        def members(self):
            for name in (
                "binaries/1/CMakeDetermineCompilerABI_C.bin",
                "binaries/1/a.out",
                "binaries/1/tool",
            ):
                info = tarfile.TarInfo(name)
                info.size = 8
                yield info, b"\x7fELFxxxx"

    names = [n for n, _ in baseline_assemblage._elf_members(Stream())]
    assert names == ["binaries/1/tool"]
