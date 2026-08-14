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
"""

import json
import shutil
import time
from pathlib import Path

PROBES = Path(__file__).resolve().parent / "baseline" / "probes"


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
    belongs in the commit message that added it.
    """
    p = paths["released"]
    if not p.exists():
        return set()
    return {
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def scan_baseline(rules, files, log=print):
    """`{namespace: {"rule": name, "n": hits, "where": [file, ...]}}`.

    Pure observation -- moves nothing, writes nothing. `mirror check` uses this
    against an already-gated mirror, and any external ruleset can be passed in
    the same way.
    """
    hits = {}
    for f in files:
        try:
            matches = rules.match(str(f), timeout=300)
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
            "reason": "baseline_hit",
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

    doc = {"generated": now, "baseline": baseline, "quarantined": entries}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2, sort_keys=True))

    lines = [
        f"# quarantined -- fired on {baseline.get('files', 0)} known-clean binaries",
        "# uuid\trule\thits\texamples",
    ]
    for uuid, e in sorted(entries.items(), key=lambda kv: -kv[1].get("hits", 0)):
        lines.append(
            f"{uuid}\t{e.get('rule', '')}\t{e.get('hits', 0)} hits"
            f"\t{','.join(e.get('examples') or [])}"
        )
    paths["quarantine_log"].write_text("\n".join(lines) + "\n")
    log(f"  quarantine now holds {len(entries)} rules")
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

    baseline = {
        "files": len(files),
        "dirs": list(settings.get("baseline_dirs") or []),
        "probes": bool(settings.get("baseline_probes", True)),
    }
    write_quarantine_files(hits, paths, baseline, log=log)
    log(f"  gate: {moved} rules quarantined this run")
    return hits
