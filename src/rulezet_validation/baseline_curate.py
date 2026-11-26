"""Select a small ELF/PE corpus from official package indexes and pin its bytes."""

import argparse
import hashlib
import io
import json
import lzma
import subprocess
import tarfile
import urllib.request
from pathlib import Path

from .baseline_sync import _download

LOCK = Path(__file__).resolve().parent / "baseline" / "curated.json"
ROOT = Path("data/baseline/default/curated")
CACHE = Path("data/baseline-cache")
UBUNTU_INDEX = (
    "https://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.xz"
)
MSYS_INDEX = "https://repo.msys2.org/mingw/mingw64/mingw64.db"
SECTIONS = {
    "admin",
    "devel",
    "editors",
    "libs",
    "mail",
    "net",
    "shells",
    "text",
    "utils",
    "web",
    "x11",
}
LICENSES = {
    "MIT",
    "MIT-0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "ISC",
    "0BSD",
    "Zlib",
    "BSL-1.0",
    "CC0-1.0",
}
MAX_PACKAGE = 5_000_000
MAX_FILE = 3_000_000


def _fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError(f"index redirected away from HTTPS: {url}")
        return response.read()


def _ubuntu(index):
    for block in lzma.decompress(index).decode().split("\n\n"):
        fields = dict(
            line.split(": ", 1) for line in block.splitlines() if ": " in line
        )
        if not fields or fields.get("Section") not in SECTIONS:
            continue
        if int(fields.get("Size", 0)) > MAX_PACKAGE:
            continue
        yield {
            "source": "ubuntu-noble-main",
            "name": fields["Package"],
            "url": "https://archive.ubuntu.com/ubuntu/" + fields["Filename"],
            "sha256": fields["SHA256"],
            "size": int(fields["Size"]),
            "license": "Ubuntu main (see package copyright)",
        }


def _msys(index):
    with tarfile.open(
        fileobj=io.BytesIO(
            subprocess.run(
                ["zstd", "-dc"], input=index, capture_output=True, check=True
            ).stdout
        )
    ) as tar:
        for member in tar:
            if not member.name.endswith("/desc"):
                continue
            chunks = tar.extractfile(member).read().decode().split("\n\n")
            fields = {
                part.split("\n", 1)[0].strip("% "): part.split("\n", 1)[1].strip()
                for part in chunks
                if "\n" in part
            }
            license_text = fields.get("LICENSE", "").removeprefix("spdx:")
            if (
                license_text not in LICENSES
                or int(fields.get("CSIZE", 0)) > MAX_PACKAGE
            ):
                continue
            yield {
                "source": "msys2-mingw64",
                "name": fields["NAME"],
                "url": "https://repo.msys2.org/mingw/mingw64/" + fields["FILENAME"],
                "sha256": fields["SHA256SUM"],
                "size": int(fields["CSIZE"]),
                "license": license_text,
            }


def _members(package, archive):
    command = (
        ["dpkg-deb", "--fsys-tarfile", str(archive)]
        if package["source"].startswith("ubuntu")
        else ["zstd", "-dc", str(archive)]
    )
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|*") as tar:
            for member in tar:
                if not member.isfile() or member.size > MAX_FILE:
                    continue
                name = member.name.removeprefix("./")
                if not (
                    name.startswith(
                        ("usr/bin/", "usr/sbin/", "usr/lib/", "mingw64/bin/")
                    )
                ):
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                head = stream.read(4)
                magic = b"\x7fELF" if package["source"].startswith("ubuntu") else b"MZ"
                if head != magic and not (magic == b"MZ" and head.startswith(b"MZ")):
                    continue
                content = head + stream.read()
                yield name, content
        if process.wait() != 0:
            detail = process.stderr.read().decode(errors="replace")
            raise ValueError(f"cannot unpack {archive}: {detail}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def _rank(package):
    return hashlib.sha256(package["name"].encode()).hexdigest()


def curate(count=2000, lock=LOCK, root=ROOT, cache=CACHE, log=print):
    """Pull candidate packages, select bounded binary files, and write an exact lock."""
    if count < 2:
        raise ValueError("count must be at least 2")
    targets = (
        ("ubuntu-noble-main", count * 4 // 5, UBUNTU_INDEX, _ubuntu),
        ("msys2-mingw64", count - count * 4 // 5, MSYS_INDEX, _msys),
    )
    selected, sources = [], []
    for source, target, url, parser in targets:
        index = _fetch(url)
        sources.append(
            {"source": source, "url": url, "sha256": hashlib.sha256(index).hexdigest()}
        )
        group = []
        for package in sorted(parser(index), key=_rank):
            if len(group) >= target:
                break
            archive = _download(
                {**package, "name": package["url"].rsplit("/", 1)[1]}, Path(cache), True
            )
            files = list(_members(package, archive))
            # Cap a package's contribution so one library cannot dominate the corpus.
            for name, content in sorted(
                files, key=lambda f: hashlib.sha256(f[0].encode()).digest()
            )[:10]:
                if len(group) >= target:
                    break
                digest = hashlib.sha256(content).hexdigest()
                member_id = hashlib.sha256(name.encode()).hexdigest()[:12]
                output = f"{source}/{package['name']}/{member_id}-{Path(name).name}"
                destination = Path(root) / output
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                group.append(
                    {
                        "package": package["name"],
                        "member": name,
                        "output": output,
                        "sha256": digest,
                        "size": len(content),
                    }
                )
            if files:
                selected.append(package)
                if len(group) % 100 < 10:
                    log(f"{source}: {len(group)}/{target} binaries")
        if len(group) < target:
            raise ValueError(f"only found {len(group)} of {target} {source} binaries")
        selected.extend(group)
    document = {
        "version": 1,
        "count": count,
        "selection": (
            "80% Ubuntu noble main amd64 ELF, 20% MSYS2 mingw64 PE; "
            "SHA-256 package-name order, up to 10 files per package, "
            "names SHA-256 ordered; package <=5 MB, file <=3 MB"
        ),
        "indexes": sources,
        "packages": [x for x in selected if "url" in x],
        "files": [x for x in selected if "member" in x],
    }
    Path(lock).write_text(json.dumps(document, indent=2) + "\n")
    log(f"wrote {lock}: {len(document['files'])} files")


def sync_locked(lock=LOCK, root=ROOT, cache=CACHE, verify=True, log=print):
    if not Path(lock).exists():
        return
    document = json.loads(Path(lock).read_text())
    by_package = {}
    for item in document["files"]:
        by_package.setdefault(item["package"], []).append(item)
    for package in document["packages"]:
        archive = _download(
            {**package, "name": package["url"].rsplit("/", 1)[1]}, Path(cache), verify
        )
        needed = {item["member"]: item for item in by_package[package["name"]]}
        for name, content in _members(package, archive):
            if name not in needed:
                continue
            item = needed.pop(name)
            if verify and hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise ValueError(f"file SHA-256 mismatch: {package['name']}:{name}")
            destination = Path(root) / item["output"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        if needed:
            raise ValueError(f"missing members in {package['name']}: {list(needed)}")
    log(f"synced {len(document['files'])} locked binaries")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=2000)
    args = parser.parse_args()
    curate(args.count)
