"""The false-positive gate.

**A rule is quarantined if and only if it matched at least one file in the
baseline corpus, and its uuid is not in `released.txt`.**

That is the entire criterion. It is an observation, not a judgement: nothing
here inspects a rule's quality, its metadata, or its author's intent. Lint
findings never move a file, and neither does a risk score.

The reason is that a hit on a clean binary is not automatically a defect. A
capability rule ("this binary speaks SMTP") firing on busybox is *correct* --
busybox has a sendmail applet. A malware rule firing on the same file is not.
The difference lives in what the author meant, and every heuristic for guessing
that is wrong often enough to be worse than nothing. So the tool observes and
the human judges: review the quarantine, and put the uuid in `released.txt` if
the hit was legitimate. That file is honoured on every later run, so a decision
is never re-litigated.

Quarantined rules are moved, not deleted. `rules/` and `quarantine/` are both
real directories you can compile, copy, or hand to another project.

A quarantine is a measurement, not a sentence. Each verdict records the hash of
the rule text it was made about and a signature of the baseline it was made
against, so `stale()` can say when a decision has stopped describing reality --
upstream fixed the rule, or the corpus changed underneath it. `recheck()` puts
those rules back on trial. Neither is automatic: a sync reports staleness and
stops there, because silently reopening a reviewed decision is its own kind of
wrong.
"""

import hashlib
import json
import shutil
import time
from pathlib import Path

PROBES = Path(__file__).resolve().parent / "baseline" / "probes"


class Counter:
    """Swallows output from YARA's `console` module, counting it.

    A rule may call `console.log()`, which writes straight to stdout from the C
    library. Eleven rules in the mirror do, and because `console.log()` returns
    true they are chained into conditions with `and` -- so they print while the
    condition is being *evaluated*, not only when it matches. Across a 300-file
    baseline that buries the actual result in lines like

        The SHA256 Hash : e0d411325b7035b8ea6e9cdb4c3edf523e7a12fd4c7e450...

    A ruleset does not get to own this tool's stdout, so the output is captured
    and reduced to a count. Passing any callback is what stops yara printing.
    """

    def __init__(self):
        self.n = 0

    def hit(self, message):
        self.n += 1

    def report(self, log):
        if self.n:
            log(f"  {self.n} console messages from rules suppressed")


def rule_digest(path):
    """Hash of a rule file, so a verdict can name the bytes it was about."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def baseline_signature(files):
    """Cheap identity for a corpus: which files, and how big.

    Deliberately not a content hash of every binary -- this is checked on every
    status call, and name+size already catches the changes that matter (a probe
    added, a corpus swapped, a distro upgraded). It will not notice a file
    edited in place at identical length; `recheck --all` is the answer there.
    """
    h = hashlib.sha256()
    for f in sorted(files, key=lambda p: p.name):
        try:
            h.update(f"{f.name}:{f.stat().st_size}\n".encode())
        except OSError:
            continue
    return h.hexdigest()[:16]


def baseline_files(settings):
    """Known-clean binaries every mirrored rule has to stay silent on.

    The bundled probes come first and are never displaced by the cap. They are
    small statically linked uClibc binaries, and they exist because a baseline
    of `/usr/bin` alone is x86-64 dynamic glibc -- which is structurally unable
    to judge a rule that fingerprints statically linked embedded libc. Such a
    rule passes a `/usr/bin` gate while matching every uClibc binary in the
    world, malware and `ldconfig` alike.
    """
    out = []
    if settings.get("baseline_probes", True) and PROBES.is_dir():
        out.extend(sorted(f for f in PROBES.glob("*") if f.is_file()))
    cap = int(settings.get("baseline_max_files") or 300)
    for d in settings.get("baseline_dirs") or []:
        for f in sorted(Path(d).expanduser().glob("*")):
            if len(out) >= cap:
                return out
            if f.is_file() and not f.is_symlink():
                out.append(f)
    return out


def read_released(paths):
    """Uuids a human has cleared, one per line. `#` starts a comment.

    Deliberately a plain text file and not JSON: the cheapest possible
    contributor action is appending a line, and the reason for the decision
    belongs in the commit message that added it -- which is also why it lives
    outside `mirror_dir`, where it would be gitignored build output that a
    `rm -rf` throws away.

    The old in-mirror location is still read, so upgrading does not silently
    drop decisions someone already made.
    """
    out = set()
    for key in ("released", "released_legacy"):
        p = paths.get(key)
        if not p or not p.exists():
            continue
        out |= {
            line.strip()
            for line in p.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
    return out


def scan_baseline(rules, files, log=print):
    """`{namespace: {"rule": name, "n": hits, "where": [file, ...]}}`.

    Pure observation -- moves nothing, writes nothing. `mirror check` uses this
    against an already-gated mirror, and any external ruleset can be passed in
    the same way.
    """
    hits = {}
    noise = Counter()
    for f in files:
        try:
            matches = rules.match(str(f), timeout=300, console_callback=noise.hit)
        except Exception:
            # A single unreadable or pathological file is not a reason to lose
            # the rest of the run.
            continue
        for m in matches:
            e = hits.setdefault(m.namespace, {"rule": m.rule, "n": 0, "where": []})
            e["n"] += 1
            if len(e["where"]) < 3:
                e["where"].append(f.name)
    log(f"  {len(files)} clean binaries scanned, {len(hits)} rules fired")
    noise.report(log)
    return hits


def write_quarantine_files(hits, paths, baseline, log=print):
    """`quarantine.json` and `quarantine.txt` -- same data, two audiences.

    Merged rather than overwritten. Once a rule is quarantined it leaves
    `rules/` and therefore leaves the compiled ruleset, so a later run cannot
    re-observe it; rewriting from scratch would quietly erase the history of
    every earlier decision.
    """
    p = paths["quarantine_json"]
    doc = {}
    if p.exists():
        try:
            doc = json.loads(p.read_text())
        except (ValueError, OSError):
            doc = {}
    entries = doc.get("quarantined") or {}
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for uuid, info in hits.items():
        entries[uuid] = {
            "rule": info["rule"],
            "hits": info["n"],
            "examples": info["where"],
            "first_seen": entries.get(uuid, {}).get("first_seen", now),
            "last_checked": now,
            "reason": "baseline_hit",
            # What the verdict was actually about. Both are what make a
            # quarantine revisitable instead of permanent: if either has moved
            # on, the decision no longer describes reality.
            "rule_sha256": rule_digest(paths["quarantine"] / f"{uuid}.yara"),
            "baseline_sig": baseline.get("signature", ""),
        }
    # Anything sitting in quarantine/ without a record -- a hand-moved file, or
    # a mirror from before this file existed -- still gets listed, so the JSON
    # always describes the directory rather than only the last run.
    for f in sorted(paths["quarantine"].glob("*.yara")):
        entries.setdefault(
            f.stem,
            {
                "rule": "",
                "hits": 0,
                "examples": [],
                "first_seen": now,
                "reason": "unrecorded",
            },
        )

    # History is kept, but a record of a past verdict must not read as a
    # current one: a rule cleared by `recheck` stays in the file with
    # status "cleared", and the directory remains the source of truth for
    # what is quarantined right now.
    present = {f.stem for f in paths["quarantine"].glob("*.yara")}
    for uuid, e in entries.items():
        e["status"] = "quarantined" if uuid in present else "cleared"

    doc = {"generated": now, "baseline": baseline, "quarantined": entries}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2, sort_keys=True))

    lines = [
        f"# quarantined -- fired on {baseline.get('files', 0)} known-clean binaries",
        "# uuid\trule\thits\tstatus\texamples",
    ]
    for uuid, e in sorted(entries.items(), key=lambda kv: -kv[1].get("hits", 0)):
        lines.append(
            f"{uuid}\t{e.get('rule', '')}\t{e.get('hits', 0)} hits"
            f"\t{e['status']}\t{','.join(e.get('examples') or [])}"
        )
    paths["quarantine_log"].write_text("\n".join(lines) + "\n")
    log(f"  quarantine now holds {len(present)} rules")
    return doc


def gate(rules, paths, settings, log=print):
    """Scan the baseline, move every rule that fired, record the decision."""
    if rules is None:
        return {}
    files = baseline_files(settings)
    hits = scan_baseline(rules, files, log=log)

    for uuid in read_released(paths):
        hits.pop(uuid, None)

    paths["quarantine"].mkdir(parents=True, exist_ok=True)
    moved = 0
    for uuid in hits:
        src = paths["rules"] / f"{uuid}.yara"
        if src.exists():
            shutil.move(str(src), str(paths["quarantine"] / f"{uuid}.yara"))
            moved += 1

    write_quarantine_files(hits, paths, describe_baseline(files, settings), log=log)
    log(f"  gate: {moved} rules quarantined this run")
    return hits


def describe_baseline(files, settings):
    return {
        "files": len(files),
        "dirs": list(settings.get("baseline_dirs") or []),
        "probes": bool(settings.get("baseline_probes", True)),
        "signature": baseline_signature(files),
    }


# --- Revisiting a decision --------------------------------------------------


def stale(paths, settings):
    """Quarantined rules whose verdict no longer describes reality.

    A quarantine is a measurement, not a sentence, and a measurement expires
    when its inputs change. Two ways that happens:

    * **the rule changed** -- upstream fixed it, and the recorded hash is of
      text that no longer exists.
    * **the baseline changed** -- a probe was added, a corpus swapped. The rule
      was cleared against a different world.

    Returns `{uuid: reason}`. Reporting only; nothing here moves a file.
    """
    p = paths["quarantine_json"]
    if not p.exists():
        return {}
    try:
        entries = (json.loads(p.read_text()) or {}).get("quarantined") or {}
    except (ValueError, OSError):
        return {}

    sig = baseline_signature(baseline_files(settings))
    out = {}
    for uuid, e in entries.items():
        f = paths["quarantine"] / f"{uuid}.yara"
        if not f.exists():
            # Cleared by an earlier recheck, or moved by hand. The record is
            # history; only what is in the directory can be stale.
            continue
        if e.get("rule_sha256") and e["rule_sha256"] != rule_digest(f):
            out[uuid] = "rule_changed"
        elif e.get("baseline_sig") and e["baseline_sig"] != sig:
            out[uuid] = "baseline_changed"
        elif not e.get("rule_sha256"):
            # Quarantined before hashes were recorded, so there is nothing to
            # compare against and no way to claim the verdict still holds.
            out[uuid] = "unverifiable"
    return out


def recheck(paths, settings, uuids=None, log=print):
    """Put quarantined rules back on trial.

    Moves the selected rules back into `rules/`, recompiles, and re-runs the
    gate. Whatever still fires returns to quarantine with a fresh verdict;
    whatever no longer fires simply stays. `released.txt` is untouched -- a
    human decision is not something a re-run gets to overturn.

    `uuids=None` means everything currently quarantined. This is never
    automatic: a sync must not silently reopen decisions someone reviewed.
    """
    from . import mirror as mirror_mod

    quarantined = {f.stem for f in paths["quarantine"].glob("*.yara")}
    targets = quarantined if uuids is None else (set(uuids) & quarantined)
    if not targets:
        log("  nothing to recheck")
        return {}

    paths["rules"].mkdir(parents=True, exist_ok=True)
    for uuid in targets:
        shutil.move(
            str(paths["quarantine"] / f"{uuid}.yara"),
            str(paths["rules"] / f"{uuid}.yara"),
        )
    log(f"  {len(targets)} rules returned to the ruleset for re-evaluation")

    # Validating: the text may have changed since it was last compiled.
    compiled = mirror_mod.compile_mirror(paths, log=log, validate=True)
    hits = gate(compiled, paths, settings, log=log)

    cleared = sorted(
        t
        for t in targets
        if t not in hits and (paths["rules"] / f"{t}.yara").exists()
    )
    for uuid in cleared:
        log(f"  cleared: {uuid}")
    log(f"  recheck: {len(cleared)} of {len(targets)} no longer fire")
    return {
        "rechecked": sorted(targets),
        "cleared": cleared,
        "still_firing": sorted(hits),
    }
