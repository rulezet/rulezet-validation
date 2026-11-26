"""Fetch the pinned, locally scanned baseline artifacts."""

import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent / "baseline" / "manifest.toml"
ROOT = Path("data/baseline")
MAX_DOWNLOAD = 100 * 1024 * 1024


def _digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(entry, cache, verify):
    url = entry["url"]
    if not url.startswith("https://"):
        raise ValueError(f"baseline source must use HTTPS: {url}")
    target = cache / entry["name"]
    if target.exists() and (not verify or _digest(target) == entry["sha256"]):
        return target
    cache.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as out:
            tmp = Path(out.name)
            with urllib.request.urlopen(url, timeout=30) as source:
                if not source.geturl().startswith("https://"):
                    raise ValueError(
                        f"baseline source redirected away from HTTPS: {url}"
                    )
                size = 0
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD:
                        raise ValueError(
                            f"baseline source exceeds {MAX_DOWNLOAD} bytes: {url}"
                        )
                    out.write(chunk)
        if verify and _digest(tmp) != entry["sha256"]:
            raise ValueError(f"SHA-256 mismatch for {url}")
        os.replace(tmp, target)
        return target
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def _content(archive, member):
    if not member:
        return archive.read_bytes()
    try:
        result = subprocess.run(
            ["dpkg-deb", "--fsys-tarfile", str(archive)],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as e:
        raise ValueError("dpkg-deb is required to unpack Ubuntu packages") from e
    except subprocess.CalledProcessError as e:
        raise ValueError(
            f"cannot unpack {archive}: {e.stderr.decode(errors='replace')}"
        ) from e
    try:
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as tar:
            found = tar.extractfile("./" + member)
            if found is None:
                raise ValueError(f"{member} is not a file in {archive}")
            return found.read()
    except (KeyError, tarfile.TarError) as e:
        raise ValueError(f"{member} missing or unreadable in {archive}") from e


def sync(
    *,
    all_licenses=False,
    skip_hash_verification=False,
    root=ROOT,
    manifest=MANIFEST,
    log=print,
):
    """Download selected files; publish only after both archive and file checks."""
    if all_licenses:
        log(
            "warning: --all-licenses includes files outside the reviewed "
            "default corpus; check their licenses before use"
        )
    if skip_hash_verification:
        log(
            "warning: SHA-256 verification disabled; downloaded bytes may "
            "differ from the manifest"
        )
    data = tomllib.loads(Path(manifest).read_text())
    root = Path(root)
    for entry in data["files"]:
        if not entry["default"] and not all_licenses:
            continue
        archive = _download(
            entry, root.parent / "baseline-cache", not skip_hash_verification
        )
        content = _content(archive, entry.get("member"))
        if (
            not skip_hash_verification
            and hashlib.sha256(content).hexdigest() != entry["file_sha256"]
        ):
            raise ValueError(
                f"SHA-256 mismatch for {entry['name']}:{entry.get('member', '')}"
            )
        destination = (
            root / "default"
            if entry["default"]
            else root.parent / "baseline-all-licenses"
        ) / entry["output"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as out:
            temp = Path(out.name)
            out.write(content)
        os.replace(temp, destination)
        log(f"{destination}  {entry['license']}")
    if Path(manifest) == MANIFEST and Path(root) == ROOT:
        from .baseline_curate import sync_locked

        sync_locked(verify=not skip_hash_verification, log=log)
