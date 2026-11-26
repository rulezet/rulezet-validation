"""Select a small ELF/PE corpus from official package indexes and pin its bytes."""

import argparse
import gzip
import hashlib
import http.client
import io
import json
import lzma
import subprocess
import tarfile
import time
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
# Non-x86 coverage. A fixed snapshot, not deb.debian.org: point releases drop
# superseded .debs from the live pool, which would break every pinned URL.
SNAPSHOT = "https://snapshot.debian.org/archive/debian/20261101T000000Z/"
PORTS = (
    ("bookworm", "arm64"), ("bookworm", "armhf"), ("bookworm", "armel"),
    ("bookworm", "mipsel"), ("bookworm", "mips64el"), ("bookworm", "ppc64el"),
    ("bookworm", "s390x"), ("bookworm", "i386"), ("trixie", "riscv64"),
)
MIRROR = "https://deb.debian.org/debian/"
# Embedded ARM coverage. OpenWrt builds 32-bit ARM targets in ARM (not Thumb)
# encoding against musl, unlike Debian armhf. Release directories never change.
OPENWRT = "https://downloads.openwrt.org/releases/23.05.5/packages/"
OPENWRT_ARCHES = (
    "arm_arm926ej-s", "arm_xscale", "arm_fa526", "arm_mpcore",
    "arm_cortex-a5_vfpv4", "arm_cortex-a7_neon-vfpv4", "arm_cortex-a9",
    "arm_cortex-a15_neon-vfpv4",
)
OPENWRT_FEEDS = ("base", "packages")
OPENWRT_LOCK = LOCK.parent / "openwrt.json"
OPENWRT_ROOT = Path("data/baseline/default/openwrt")
PORTS_LOCK = LOCK.parent / "ports.json"
PORTS_ROOT = Path("data/baseline/default/ports")
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
# curated.json was built with 5 MB / 3 MB limits; later locks use these.
MAX_PACKAGE = 50_000_000
MAX_FILE = 20_000_000


def _fetch(url, attempts=3):
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError(f"index redirected away from HTTPS: {url}")
                return response.read()
        except (OSError, http.client.HTTPException):
            if attempt == attempts - 1:
                raise
            time.sleep(5 * (attempt + 1))


def _ubuntu(index):
    yield from _debian(
        index, "ubuntu-noble-main", "https://archive.ubuntu.com/ubuntu/",
        "Ubuntu main (see package copyright)",
    )


def _port(suite, arch):
    def parse(index):
        yield from _debian(
            index, f"debian-{suite}-{arch}", SNAPSHOT,
            "Debian main, DFSG-free (see package copyright)",
        )
    return parse


def _openwrt(arch, feed):
    def parse(index):
        for block in gzip.decompress(index).decode().split("\n\n"):
            fields = dict(
                line.split(": ", 1) for line in block.splitlines() if ": " in line
            )
            if "Filename" not in fields or int(fields.get("Size", 0)) > MAX_PACKAGE:
                continue
            yield {
                "source": f"openwrt-{arch}-{feed}",
                "name": fields["Package"],
                "url": f"{OPENWRT}{arch}/{feed}/{fields['Filename']}",
                "sha256": fields["SHA256sum"],
                "size": int(fields["Size"]),
                "license": fields.get("License", "unspecified in OpenWrt index"),
            }
    return parse


def _debian(index, source, base, license_text):
    for block in lzma.decompress(index).decode().split("\n\n"):
        fields = dict(
            line.split(": ", 1) for line in block.splitlines() if ": " in line
        )
        if not fields or fields.get("Section") not in SECTIONS:
            continue
        if int(fields.get("Size", 0)) > MAX_PACKAGE:
            continue
        yield {
            "source": source,
            "name": fields["Package"],
            "url": base + fields["Filename"],
            "sha256": fields["SHA256"],
            "size": int(fields["Size"]),
            "license": license_text,
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


def _openwrt_members(archive):
    """An .ipk is a gzip tar holding data.tar.gz; yield its ELF files."""
    with tarfile.open(archive, "r:gz") as outer:
        member = next(m for m in outer if m.name.removeprefix("./") == "data.tar.gz")
        data = outer.extractfile(member).read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile() or member.size > MAX_FILE:
                continue
            name = member.name.removeprefix("./")
            if not name.startswith(OPENWRT_DIRS):
                continue
            content = tar.extractfile(member).read()
            if content.startswith(b"\x7fELF"):
                yield name, content


OPENWRT_DIRS = ("bin/", "sbin/", "lib/", "usr/bin/", "usr/sbin/", "usr/lib/")


def _members(package, archive):
    if package["source"].startswith("openwrt"):
        yield from _openwrt_members(archive)
        return
    command = (
        ["dpkg-deb", "--fsys-tarfile", str(archive)]
        if package["source"].startswith(("ubuntu", "debian"))
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
                debian = package["source"].startswith(("ubuntu", "debian"))
                magic = b"\x7fELF" if debian else b"MZ"
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


def _package(package, cache, verify):
    """Download a locked package, Debian mirror first.

    The lock pins snapshot.debian.org URLs because the live pool drops
    superseded files at point releases. Snapshot is slow, though, so the same
    pool path is tried on deb.debian.org first; the pinned SHA-256 makes the
    source irrelevant. Snapshot is the fallback once the mirror lost the file.
    """
    entry = {**package, "name": package["url"].rsplit("/", 1)[1]}
    if package["url"].startswith(SNAPSHOT):
        mirror = {**entry, "url": MIRROR + package["url"].removeprefix(SNAPSHOT)}
        try:
            return _download(mirror, cache, verify, attempts=1)
        except (ValueError, OSError, http.client.HTTPException):
            pass
    return _download(entry, cache, verify)


def _rank(package):
    # Ports salt the rank with the source so each architecture draws a
    # different set of packages; the original two sources keep their order.
    key = package["name"]
    if package["source"].startswith(("debian", "openwrt")):
        key = package["source"] + "/" + key
    return hashlib.sha256(key.encode()).hexdigest()


def default_targets(count):
    return (
        ("ubuntu-noble-main", count * 4 // 5, UBUNTU_INDEX, _ubuntu),
        ("msys2-mingw64", count - count * 4 // 5, MSYS_INDEX, _msys),
    )


def port_targets(count):
    each = count // len(PORTS)
    return tuple(
        (
            f"debian-{suite}-{arch}",
            each + (i < count - each * len(PORTS)),
            f"{SNAPSHOT}dists/{suite}/main/binary-{arch}/Packages.xz",
            _port(suite, arch),
        )
        for i, (suite, arch) in enumerate(PORTS)
    )


def openwrt_targets(count):
    pairs = [(a, f) for a in OPENWRT_ARCHES for f in OPENWRT_FEEDS]
    each = count // len(pairs)
    return tuple(
        (
            f"openwrt-{arch}-{feed}",
            each + (i < count - each * len(pairs)),
            f"{OPENWRT}{arch}/{feed}/Packages.gz",
            _openwrt(arch, feed),
        )
        for i, (arch, feed) in enumerate(pairs)
    )


def curate(count=2000, lock=LOCK, root=ROOT, cache=CACHE, log=print, targets=None,
           selection=None):
    """Pull candidate packages, select bounded binary files, and write an exact lock."""
    if count < 2:
        raise ValueError("count must be at least 2")
    targets = targets or default_targets(count)
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
            try:
                archive = _package(package, Path(cache), True)
            except ValueError as e:
                # snapshot.debian.org resolves pool paths by file name; a few
                # names were reused for different bytes, and it serves the
                # wrong one every time. Skipping keeps the lock syncable.
                if "SHA-256 mismatch" not in str(e):
                    raise
                log(f"skip {package['name']}: {e}")
                continue
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
                        "source": source,
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
        "selection": selection or (
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
        # Ports repeat package names across architectures; older locks have
        # no per-file source and unique names.
        by_package.setdefault((item.get("source"), item["package"]), []).append(item)
    for package in document["packages"]:
        archive = _package(package, Path(cache), verify)
        key = (package["source"], package["name"])
        items = by_package.get(key) or by_package[(None, package["name"])]
        needed = {item["member"]: item for item in items}
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
    which = parser.add_mutually_exclusive_group()
    which.add_argument("--ports", action="store_true",
                       help="build the non-x86 Debian ports lock instead")
    which.add_argument("--openwrt", action="store_true",
                       help="build the OpenWrt ARM lock instead")
    args = parser.parse_args()
    if args.openwrt:
        curate(
            args.count, OPENWRT_LOCK, OPENWRT_ROOT,
            targets=openwrt_targets(args.count),
            selection=(
                f"OpenWrt 23.05.5 ELF from the {' and '.join(OPENWRT_FEEDS)} feeds "
                "of " + ", ".join(OPENWRT_ARCHES) + "; equal share per "
                "architecture and feed, source-salted SHA-256 package order, "
                f"up to 10 files per package; package <={MAX_PACKAGE // 10**6} "
                f"MB, file <={MAX_FILE // 10**6} MB"
            ),
        )
    elif args.ports:
        curate(
            args.count, PORTS_LOCK, PORTS_ROOT, targets=port_targets(args.count),
            selection=(
                "Debian main ELF across " + ", ".join(a for _, a in PORTS)
                + f" from snapshot {SNAPSHOT}; equal share per architecture, "
                "source-salted SHA-256 package order, up to 10 files per "
                f"package; package <={MAX_PACKAGE // 10**6} MB, "
                f"file <={MAX_FILE // 10**6} MB"
            ),
        )
    else:
        curate(args.count)
