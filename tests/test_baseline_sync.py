"""Pinned downloads and local baseline discovery."""

import hashlib
import io

import pytest

from rulezet_validation import baseline_sync, config, gate


class Response(io.BytesIO):
    def geturl(self):
        return "https://example.test/file"


def test_sync_verifies_hashes_and_keeps_opt_in_files_out_of_default_gate(
    tmp_path, monkeypatch
):
    manifest = tmp_path / "manifest.toml"
    good = hashlib.sha256(b"\x7fELF safe").hexdigest()
    extra = hashlib.sha256(b"MZ extra").hexdigest()
    manifest.write_text(
        f'''[[files]]
name = "safe"
url = "https://example.test/file"
sha256 = "{good}"
file_sha256 = "{good}"
output = "safe.elf"
license = "MIT"
default = true

[[files]]
name = "extra"
url = "https://example.test/file"
sha256 = "{extra}"
file_sha256 = "{extra}"
output = "extra.exe"
license = "GPL"
default = false
'''
    )
    content = iter([b"\x7fELF safe", b"MZ extra"])
    monkeypatch.setattr(
        baseline_sync.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(next(content)),
    )
    root = tmp_path / "baseline"
    baseline_sync.sync(root=root, manifest=manifest, log=lambda *_: None)
    assert (root / "default/safe.elf").read_bytes() == b"\x7fELF safe"
    assert not (tmp_path / "baseline-all-licenses").exists()
    baseline_sync.sync(
        all_licenses=True, root=root, manifest=manifest, log=lambda *_: None
    )
    assert (tmp_path / "baseline-all-licenses/extra.exe").read_bytes() == b"MZ extra"
    custom = root / "my_custom_dir"
    custom.mkdir()
    (custom / "own.elf").write_bytes(b"\x7fELF own")
    settings = dict(config.DEFAULTS, baseline_dirs=[str(root)], baseline_probes=False)
    assert {p.name for p in gate.baseline_files(settings)} == {"safe.elf", "own.elf"}


def test_hash_mismatch_fails_closed_unless_explicitly_skipped(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.toml"
    manifest.write_text("""[[files]]
name = "file"
url = "https://example.test/file"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
file_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
output = "file.elf"
license = "MIT"
default = true
""")
    monkeypatch.setattr(
        baseline_sync.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(b"\x7fELF actual"),
    )
    root = tmp_path / "baseline"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        baseline_sync.sync(root=root, manifest=manifest, log=lambda *_: None)
    assert not (root / "default/file.elf").exists()
    baseline_sync.sync(
        skip_hash_verification=True, root=root, manifest=manifest, log=lambda *_: None
    )
    assert (root / "default/file.elf").read_bytes() == b"\x7fELF actual"
