"""Pin an Assemblage Windows PE and Linux ELF subset without its full archives."""

import argparse
import csv
import hashlib
import io
import json
import subprocess
import tarfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

from .baseline_sync import _download

LOCK = Path(__file__).resolve().parent / "baseline" / "assemblage.json"
ROOT = Path("data/baseline/default/assemblage")
CACHE = Path("data/assemblage-cache")
RUST_REV = "0d6f0c57891f09ca21c4840f420ec450959ff7e0"
PE_REV = "19a8f947f5a04d03edea78e61790226b55f92ac2"
PE_INDEX_REV = "12803410d3a61e5c99443d2b50f84ab8a70117f5"
RUST_BASE = (
    f"https://huggingface.co/datasets/changliu8541/assemblage-rust/resolve/{RUST_REV}/"
)
PE_BASE = (
    f"https://huggingface.co/datasets/changliu8541/Assemblage_PE/resolve/{PE_REV}/"
)
PE_INDEX_URL = f"https://huggingface.co/datasets/changliu8541/Assemblage_PE/resolve/{PE_INDEX_REV}/binaries.csv"
# June 2024 LinuxELF revision: the archive part and the SQLite index that
# describes it (SHA-256, license, compiler) come from the same commit. The
# current 2026 archive interleaves builds this index does not cover.
ELF_REV = "efbaa11cd2cc1d5e72293d3cac89ff3af8cbcb36"
ELF_BASE = f"https://huggingface.co/datasets/changliu8541/Assemblage_LinuxELF/resolve/{ELF_REV}/"
ELF_ARCHIVE_URL = ELF_BASE + "binaries.tar.xz.partaa"
ELF_INDEX_URL = ELF_BASE + "linux.sqlite.tar.xz"
MAX_FILE = 20_000_000
PER_REPO = 3
CHUNK = 1 << 20
PERMISSIVE = {
    "mit",
    "apache-2.0",
    "bsd-2-clause",
    "bsd-3-clause",
    "isc",
    "zlib",
    "bsl-1.0",
    "cc0-1.0",
    "unlicense",
}
RUST_LICENSES = {
    "MIT License",
    "Apache License 2.0",
    'BSD 3-Clause "New" or "Revised" License',
}


def _get(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError(f"Assemblage source redirected away from HTTPS: {url}")
        return response.read()


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _archive_digest(url):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, new_url):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(
            urllib.request.Request(url, method="HEAD"), timeout=30
        ) as response:
            headers = response.headers
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        headers = error.headers
    digest = headers.get("X-Linked-ETag", "").strip('"')
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError(f"no archive SHA-256 in Assemblage response: {url}")
    return digest


class _Stream:
    """The first `limit` compressed bytes of a zstd or xz tar, read over HTTPS.

    Assemblage ships each platform as one tens-of-GB archive with no per-file
    access, so a subset is a prefix: read until enough members are selected,
    record how many compressed bytes that took, and replay exactly that many
    on sync. `consumed` and `sha256` describe the bytes fed so far.
    """

    def __init__(self, url, limit=None, codec="zstd"):
        self.url, self.limit, self.codec = url, limit, codec
        self.consumed, self._hash = 0, hashlib.sha256()

    @property
    def sha256(self):
        return self._hash.hexdigest()

    def members(self):
        response = urllib.request.urlopen(self.url, timeout=60)
        if not response.geturl().startswith("https://"):
            raise ValueError(
                f"Assemblage source redirected away from HTTPS: {self.url}"
            )
        zstd = subprocess.Popen(
            [self.codec, "-dc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        stop = threading.Event()

        def feed():
            try:
                while not stop.is_set():
                    want = CHUNK
                    if self.limit is not None:
                        want = min(want, self.limit - self.consumed)
                    chunk = response.read(want) if want > 0 else b""
                    if not chunk:
                        break
                    self._hash.update(chunk)
                    self.consumed += len(chunk)
                    zstd.stdin.write(chunk)
            except (BrokenPipeError, ValueError, OSError):
                pass
            finally:
                try:
                    zstd.stdin.close()
                except OSError:
                    pass

        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
        try:
            with tarfile.open(fileobj=zstd.stdout, mode="r|") as tar:
                try:
                    for member in tar:
                        if member.isfile():
                            yield member, tar.extractfile(member).read()
                except (tarfile.ReadError, EOFError):
                    pass  # the prefix ends mid-member: expected
        finally:
            stop.set()
            zstd.kill()
            zstd.wait()
            feeder.join(timeout=30)
            response.close()


def _pe_members(stream):
    for member, content in stream.members():
        if member.size > MAX_FILE or not member.name.lower().endswith((".exe", ".dll")):
            continue
        if content.startswith(b"MZ"):
            yield member.name, content


def _elf_members(stream):
    for member, content in stream.members():
        name = Path(member.name).name
        if member.size > MAX_FILE:
            continue
        # CMake feature probes and bare a.out test programs are thousands of
        # near-identical stubs; they would crowd out real programs.
        if name == "a.out" or name.startswith("CMake") or name.endswith(".bin"):
            continue
        if content.startswith(b"\x7fELF"):
            yield member.name, content


def _rust_members(archive):
    with tarfile.open(archive) as tar:
        for member in tar:
            if not member.isfile() or "/binaries/" not in member.name:
                continue
            if not member.name.endswith(".zst") or member.size > MAX_FILE:
                continue
            encoded = tar.extractfile(member).read()
            content = subprocess.run(
                ["zstd", "-dc"], input=encoded, capture_output=True, check=True
            ).stdout
            if len(content) <= MAX_FILE and content.startswith(b"\x7fELF"):
                yield member.name, content


def _rust_candidates(index):
    grouped = {}
    for line in index.splitlines():
        row = json.loads(line)
        group = grouped.setdefault(row["tar"], {"rows": [], "bytes": 0, "binaries": 0})
        group["rows"].append(row)
        group["bytes"] += row["stored_bytes"]
        group["binaries"] += row["binaries"]
    for name, group in sorted(
        grouped.items(), key=lambda item: hashlib.sha256(item[0].encode()).digest()
    ):
        if 4 <= group["binaries"] <= 15 and group["bytes"] < 30_000_000:
            if all(row["license"] in RUST_LICENSES for row in group["rows"]):
                yield name, group


def _write(root, output, content):
    destination = Path(root) / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)


def _pe_index():
    """{sha256: row} from the PE per-binary CSV index."""
    content = _get(PE_INDEX_URL)
    rows = {
        row["hash"].lower(): row
        for row in csv.DictReader(io.StringIO(content.decode()))
    }
    return content, rows


def _elf_index(cache):
    """{sha256: row} from the LinuxELF SQLite index (zstd tar, despite .xz)."""
    import sqlite3

    content = _get(ELF_INDEX_URL)
    cache.mkdir(parents=True, exist_ok=True)
    tar_bytes = subprocess.run(
        ["zstd", "-dc"], input=content, capture_output=True, check=True
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        member = next(m for m in tar if m.name.endswith(".sqlite"))
        db = cache / "linux_licensed.sqlite"
        db.write_bytes(tar.extractfile(member).read())
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = {
        r["hash"].lower(): dict(r)
        for r in con.execute(
            "select hash, license, github_url, toolset_version, optimization"
            " from binaries"
        )
    }
    con.close()
    return content, rows


def _take_stream(stream, members, pick, target, log, label, root):
    """Select up to `target` files from a stream; return them with the bytes read."""
    files, per_repo = [], {}
    for member, content in members(stream):
        picked = pick(member, content)
        if picked is None:
            continue
        content, item = picked
        if per_repo.get(item["repo_url"], 0) >= PER_REPO:
            continue
        _write(root, item["output"], content)
        per_repo[item["repo_url"]] = per_repo.get(item["repo_url"], 0) + 1
        files.append(item)
        if len(files) % 250 == 0:
            log(f"{label}: {len(files)}/{target} ({stream.consumed / 1e6:.0f} MB read)")
        if len(files) == target:
            break
    if len(files) != target:
        raise ValueError(f"only found {len(files)} of {target} {label} files")
    return files


def curate(pe=2500, elf=1500, rust=200, lock=LOCK, root=ROOT, cache=CACHE, log=print):
    root, cache = Path(root), Path(cache)
    seen = set()

    pe_index, pe_rows = _pe_index()

    def pick_pe(member, content):
        digest = _sha(content)
        row = pe_rows.get(digest)
        if digest in seen or not row or row["license"].lower() not in PERMISSIVE:
            return None
        seen.add(digest)
        output = f"pe/{digest[:16]}-{Path(member).name}"
        return content, {
            "source": "assemblage-pe",
            "member": member,
            "output": output,
            "sha256": digest,
            "size": len(content),
            "license": row["license"],
            "repo_url": row["github_url"],
            "commit": row["github_commit_hash"],
            "toolset": row["toolset_version"],
            "optimization": row["optimization"],
        }

    pe_stream = _Stream(PE_BASE + "binaries.tar.xz")
    pe_files = _take_stream(
        pe_stream, _pe_members, pick_pe, pe, log, "Assemblage PE", root
    )

    elf_index, elf_rows = _elf_index(cache)

    def pick_elf(member, content):
        digest = _sha(content)
        row = elf_rows.get(digest)
        if digest in seen or not row or row["license"].lower() not in PERMISSIVE:
            return None
        seen.add(digest)
        output = f"elf/{digest[:16]}-{Path(member).name}"
        return content, {
            "source": "assemblage-elf",
            "member": member,
            "output": output,
            "sha256": digest,
            "size": len(content),
            "license": row["license"],
            "repo_url": row["github_url"],
            "toolset": row["toolset_version"],
            "optimization": row["optimization"],
        }

    elf_stream = _Stream(ELF_ARCHIVE_URL, codec="xz")
    elf_files = _take_stream(
        elf_stream, _elf_members, pick_elf, elf, log, "Assemblage ELF", root
    )

    rust_index = _get(RUST_BASE + "index.jsonl")
    rust_files, rust_archives = [], []
    for name, group in _rust_candidates(rust_index):
        if len(rust_files) == rust:
            break
        url = RUST_BASE + name
        archive_hash = _archive_digest(url)
        archive = _download(
            {"url": url, "name": Path(name).name, "sha256": archive_hash}, cache, True
        )
        picked = 0
        for member, content in _rust_members(archive):
            digest = _sha(content)
            if digest in seen:
                continue
            seen.add(digest)
            output = f"rust/{digest[:16]}-{Path(member).name.removesuffix('.zst')}"
            _write(root, output, content)
            rust_files.append(
                {
                    "source": "assemblage-rust",
                    "archive": name,
                    "member": member,
                    "output": output,
                    "sha256": digest,
                    "size": len(content),
                    "license": group["rows"][0]["license"],
                    "repo_url": group["rows"][0]["repo_url"],
                }
            )
            picked += 1
            if picked == PER_REPO or len(rust_files) == rust:
                break
        if picked:
            rust_archives.append(
                {
                    "name": Path(name).name,
                    "path": name,
                    "url": url,
                    "sha256": archive_hash,
                }
            )
            log(f"Assemblage Rust: {len(rust_files)}/{rust}")
    if len(rust_files) != rust:
        raise ValueError(f"only found {len(rust_files)} Assemblage Rust files")

    document = {
        "version": 2,
        "count": pe + elf + rust,
        "selection": (
            f"{pe} Windows PE (MSVC), {elf} Linux ELF (gcc/clang C/C++), {rust} "
            f"Linux ELF (Rust: llvm/gcc/cranelift); permissive licenses only; at "
            f"most {PER_REPO} files per repository; files <= {MAX_FILE} bytes; "
            "PE and C/C++ ELF are archive prefixes, not uniform samples"
        ),
        "pe": {
            "url": pe_stream.url,
            "prefix_bytes": pe_stream.consumed,
            "prefix_sha256": pe_stream.sha256,
            "license_index_url": PE_INDEX_URL,
            "license_index_sha256": _sha(pe_index),
        },
        "elf": {
            "url": elf_stream.url,
            "codec": "xz",
            "prefix_bytes": elf_stream.consumed,
            "prefix_sha256": elf_stream.sha256,
            "license_index_url": ELF_INDEX_URL,
            "license_index_sha256": _sha(elf_index),
        },
        "rust": {
            "index_url": RUST_BASE + "index.jsonl",
            "index_sha256": _sha(rust_index),
            "archives": rust_archives,
        },
        "files": pe_files + elf_files + rust_files,
    }
    Path(lock).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    log(f"wrote {lock}: {len(document['files'])} files")


def _sync_stream(section, members, source, document, root, verify):
    needed = {i["member"]: i for i in document["files"] if i["source"] == source}
    stream = _Stream(
        section["url"], section["prefix_bytes"], section.get("codec", "zstd")
    )
    for member, content in members(stream):
        item = needed.pop(member, None)
        if item is None:
            continue
        if verify and _sha(content) != item["sha256"]:
            raise ValueError(f"{source} file SHA-256 mismatch: {member}")
        _write(root, item["output"], content)
        if not needed:
            break
    if needed:
        raise ValueError(f"{source} members missing: {list(needed)[:5]}")


def sync_locked(lock=LOCK, root=ROOT, cache=CACHE, verify=True, log=print):
    if not Path(lock).exists():
        return
    document = json.loads(Path(lock).read_text())
    root, cache = Path(root), Path(cache)
    # Per-file SHA-256 is the check that matters; the prefix hash pins which
    # archive revision the selection came from.
    _sync_stream(document["pe"], _pe_members, "assemblage-pe", document, root, verify)
    _sync_stream(
        document["elf"], _elf_members, "assemblage-elf", document, root, verify
    )
    for archive in document["rust"]["archives"]:
        path = _download(archive, cache, verify)
        needed = {
            item["member"]: item
            for item in document["files"]
            if item.get("archive") == archive["path"]
        }
        for member, content in _rust_members(path):
            item = needed.pop(member, None)
            if item is None:
                continue
            if verify and _sha(content) != item["sha256"]:
                raise ValueError(f"Assemblage Rust file SHA-256 mismatch: {member}")
            _write(root, item["output"], content)
        if needed:
            raise ValueError(f"Assemblage Rust members missing: {list(needed)}")
    log(f"synced {len(document['files'])} Assemblage binaries")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", type=int, default=2500)
    parser.add_argument("--elf", type=int, default=1500)
    parser.add_argument("--rust", type=int, default=200)
    args = parser.parse_args()
    curate(args.pe, args.elf, args.rust)
