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

import fnmatch
import hashlib
import json
import shutil
import time
from pathlib import Path

PROBES = Path(__file__).resolve().parent / "baseline" / "probes"

# Per file, per rule. Enough to see the pattern; short of letting one
# pathological rule write a megabyte into quarantine.json.
OFFSET_CAP = 64

# Shipped, versioned, PR-able. See the file for why this is not left to each
# user's local config.
DEFAULT_EXCLUDE = Path(__file__).resolve().parent / "baseline" / "exclude.txt"

# Hits -> proposed risk. Absolute counts, not a fraction of the baseline: the
# corpus is small enough that a percentage reads as more precision than there
# is, and "fired on twenty clean binaries" is the sentence a reviewer actually
# reasons with.
# ponytail: flat thresholds, revisit if the baseline grows past a few thousand
# files, at which point a fraction starts meaning more than a count.
RISK_THRESHOLDS = ((20, "high"), (5, "medium"), (1, "low"))
RISK_PREFIX = "false-positive:risk:"


def propose_risk(hits):
    """The risk level suggested by how much clean material a rule fired on.

    A proposal, never a verdict: it is written next to the evidence and moves
    nothing. Zero hits is `cannot-be-judged` rather than `low` -- a rule with no
    observation behind it (a hand-moved file, a record from before the evidence
    existed) has not been exercised, and saying "low" there would be inventing
    a measurement that was never taken.
    """
    for floor, level in RISK_THRESHOLDS:
        if hits >= floor:
            return RISK_PREFIX + level
    return RISK_PREFIX + "cannot-be-judged"


def sidecar_tags(paths):
    """`{uuid: [tag]}` from the tags sidecar, or `{}` if there is none yet."""
    try:
        return json.loads(paths["tags"].read_text())
    except (ValueError, OSError, KeyError):
        return {}


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


def display_path(path):
    """A path fit to be published in a verdict.

    Quarantine records are evidence meant to be shared -- pasted into an issue,
    attached to a pull request arguing a rule is wrong. Two kinds of path in
    them are worse than useless to the reader:

    * **Bundled probes.** Their absolute location is wherever pip happened to
      install the package. Rendered as `<probes>/name`, which identifies the
      file for everyone.
    * **Anything under $HOME.** Leaks a username into a public record for no
      analytical gain. Rendered with a `~` prefix.

    System paths are kept verbatim: `/usr/bin/zsh` means the same thing on the
    reader's machine as it did on yours, which is the whole point.
    """
    path = Path(path)
    try:
        return f"<probes>/{path.relative_to(PROBES)}"
    except ValueError:
        pass
    try:
        return f"~/{path.relative_to(Path.home())}"
    except ValueError:
        return str(path)


def hash_files(files):
    """`{real path: sha256}`. One pass, so nothing is hashed twice."""
    return {str(f): sha256(f) for f in files}


def sha256(path):
    """Full hex sha256 of a file, or "" if it cannot be read.

    Full, not truncated. A field called `sha256` holding sixteen characters is
    a lie, and these hashes exist so a verdict can be re-verified later.
    """
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def baseline_manifest(files, digests=None):
    """`[{name, path, sha256, size}]` -- exactly what a verdict was measured on.

    Recorded in full rather than as a count, because "fired on 300 clean
    binaries" is not a reproducible claim. With this, anyone can fetch the same
    files, check the hashes, and re-run the gate.
    """
    digests = hash_files(files) if digests is None else digests
    out = []
    for f in sorted(files, key=lambda p: (p.name, str(p))):
        try:
            size = f.stat().st_size
        except OSError:
            continue
        out.append(
            {
                "name": f.name,
                "path": display_path(f),
                "sha256": digests.get(str(f), ""),
                "size": size,
            }
        )
    return out


def baseline_signature(manifest):
    """One id for a whole corpus: sha256 over its files' names and hashes.

    Content-based, so a binary edited in place at the same length still changes
    it. That costs a hash of every baseline file per call, which is a fraction
    of the yara scan it accompanies.
    """
    h = hashlib.sha256()
    for entry in manifest:
        h.update(f"{entry['name']}:{entry['sha256']}\n".encode())
    return h.hexdigest()


def baseline_files(settings):
    """Known-clean binaries every mirrored rule has to stay silent on.

    The bundled probes come first and are never displaced by the cap. They are
    small statically linked uClibc binaries, and they exist because a baseline
    of `/usr/bin` alone is x86-64 dynamic glibc -- which is structurally unable
    to judge a rule that fingerprints statically linked embedded libc. Such a
    rule passes a `/usr/bin` gate while matching every uClibc binary in the
    world, malware and `ldconfig` alike.
    """
    return collect_baseline(settings)[0]


def collect_baseline(settings):
    """`(kept, excluded)`.

    The cap counts kept files only. Excluding `capa` should not cost you a slot
    in the corpus -- otherwise turning on an exclusion silently shrinks what
    gets scanned.
    """
    excluded_by = excludes(settings)
    out, dropped = [], []
    if settings.get("baseline_probes", True) and PROBES.is_dir():
        out.extend(sorted(f for f in PROBES.glob("*") if f.is_file()))

    candidates = []
    for d in settings.get("baseline_dirs") or []:
        for f in sorted(Path(d).expanduser().glob("*")):
            # Symlinks are skipped rather than followed: /usr/bin is full of
            # them (msfvenom, upx, r2 all point at /etc/alternatives), and
            # following them scans the same binary twice under two names.
            if not f.is_file() or f.is_symlink():
                continue
            (dropped if excluded_by(f) else candidates).append(f)

    cap = int(settings.get("baseline_max_files") or 300)
    out.extend(sample(candidates, cap))
    return out, dropped


def sample(files, cap):
    """`cap` files spread across the whole list, not its first `cap` entries.

    Taking a prefix of a sorted directory means a `/usr/bin` baseline is
    everything from `[` to `cmp` and nothing else -- 300 files that share a
    first letter are not a sample of 3300, and a rule firing only on `zsh`
    passes the gate. An even stride is still fully deterministic, so a verdict
    stays reproducible, and the exact file list is recorded anyway.
    """
    if cap <= 0 or len(files) <= cap:
        return list(files)
    stride = len(files) / cap
    return [files[int(i * stride)] for i in range(cap)]


def default_excludes():
    """Patterns from the shipped `exclude.txt`, comments and blanks stripped.

    Entries may carry a trailing `# reason` comment, which is the point of the
    file -- an exclusion without a justification is indistinguishable from
    hiding a false positive.
    """
    if not DEFAULT_EXCLUDE.exists():
        return []
    out = []
    for line in DEFAULT_EXCLUDE.read_text().splitlines():
        pattern = line.split("#", 1)[0].strip()
        if pattern:
            out.append(pattern)
    return out


def exclude_patterns(settings):
    """Shipped defaults plus this machine's additions, in that order."""
    use_defaults = settings.get("baseline_exclude_defaults", True)
    out = default_excludes() if use_defaults else []
    return out + [str(x) for x in (settings.get("baseline_exclude") or [])]


def partition(settings, files):
    """`(kept, excluded)` -- what counts as clean, and what was set aside."""
    excluded_by = excludes(settings)
    kept, dropped = [], []
    for f in files:
        (dropped if excluded_by(f) else kept).append(f)
    return kept, dropped


def excludes(settings):
    """A predicate for files that must not count as known-clean.

    Some perfectly legitimate software carries malicious content on purpose:
    reverse-engineering tools ship malware signatures and sample strings, and
    a scanner firing on `die` or `capa` is the rule working, not failing.
    Leaving them in the corpus would quarantine good rules.

    Patterns are fnmatch, tested against both the bare filename and the full
    path, so `capa*` and `/opt/die/*` both work. They come from two places: the
    shipped `baseline/exclude.txt`, because "capa embeds its own rules" is true
    on every machine, and `baseline_exclude` in the local config for anything
    site-specific. Every exclusion is logged and recorded in the verdict, so
    shipping defaults does not make them invisible.
    """
    patterns = exclude_patterns(settings)
    if not patterns:
        return lambda f: False

    def excluded(f):
        name, full = f.name, str(f)
        return any(
            fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(full, pat)
            for pat in patterns
        )

    return excluded


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


def scan_baseline(rules, files, log=print, digests=None):
    """`{namespace: {"rule": name, "matched": {path: {...}}}}`.

    Every matching file is recorded in full -- name, sha256 and the offsets
    it matched at -- not a sample of three. A quarantine record whose
    evidence is "and 297 others" cannot be checked by the person who has to
    decide whether the rule was right.

    Pure observation -- moves nothing, writes nothing. `mirror check` uses this
    against an already-gated mirror, and any external ruleset can be passed in
    the same way.
    """
    hits = {}
    noise = Counter()
    digests = dict(digests or {})
    for f in files:
        try:
            matches = rules.match(str(f), timeout=300, console_callback=noise.hit)
        except Exception:
            # A single unreadable or pathological file is not a reason to lose
            # the rest of the run.
            continue
        if not matches:
            continue
        if str(f) not in digests:
            digests[str(f)] = sha256(f)
        for m in matches:
            e = hits.setdefault(m.namespace, {"rule": m.rule, "matched": {}})
            offsets, strings = [], set()
            for s in m.strings or []:
                strings.add(s.identifier)
                for i in s.instances or []:
                    offsets.append(i.offset)
            e["matched"][str(f)] = {
                "file": f.name,
                "path": display_path(f),
                "sha256": digests[str(f)],
                "strings": sorted(strings),
                # A pathological rule can match a short string thousands of
                # times in one binary. The addresses are the point, so they are
                # kept -- but not without bound, and the truncation is stated
                # rather than silent.
                "offsets": [hex(o) for o in sorted(offsets)[:OFFSET_CAP]],
                "offsets_total": len(offsets),
                "offsets_truncated": len(offsets) > OFFSET_CAP,
            }
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
        matched = [info["matched"][k] for k in sorted(info["matched"])]
        entries[uuid] = {
            "rule": info["rule"],
            "hits": len(matched),
            "matched": matched,
            "first_seen": entries.get(uuid, {}).get("first_seen", now),
            "last_checked": now,
            "reason": "baseline_hit",
            # What the verdict was actually about. Both are what make a
            # quarantine revisitable instead of permanent: if either has moved
            # on, the decision no longer describes reality.
            "rule_sha256": sha256(paths["quarantine"] / f"{uuid}.yara"),
            "baseline_signature": baseline.get("signature", ""),
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
                "matched": [],
                "first_seen": now,
                "reason": "unrecorded",
            },
        )

    # History is kept, but a record of a past verdict must not read as a
    # current one: a rule cleared by `recheck` stays in the file with
    # status "cleared", and the directory remains the source of truth for
    # what is quarantined right now.
    present = {f.stem for f in paths["quarantine"].glob("*.yara")}
    upstream = sidecar_tags(paths)
    for uuid, e in entries.items():
        e["status"] = "quarantined" if uuid in present else "cleared"
        # A suggestion for whoever reviews the quarantine, derived from the
        # evidence in this same record. Where upstream already carries a risk
        # tag, the proposal is still made -- an observed hit count outranks a
        # tag derived from a rule's prose -- but the upstream value is kept
        # beside it, because a disagreement between the two is worth seeing.
        e["proposed_tag"] = propose_risk(e.get("hits", 0))
        prior = [t for t in upstream.get(uuid, []) if t.startswith(RISK_PREFIX)]
        if prior:
            e["upstream_tag"] = prior[0]

    doc = {"generated": now, "baseline": baseline, "quarantined": entries}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2, sort_keys=True))

    # A summary for eyes. The full evidence -- every file, its sha256, the
    # offsets -- is in quarantine.json; this is the index into it.
    n_baseline = len(baseline.get("files") or [])
    lines = [
        f"# quarantined -- fired on {n_baseline} known-clean binaries",
        f"# baseline {baseline.get('signature', '')[:16]}",
        "# uuid\trule\thits\tstatus\tproposed risk\tfiles",
    ]
    for uuid, e in sorted(entries.items(), key=lambda kv: -kv[1].get("hits", 0)):
        names = [m["file"] for m in (e.get("matched") or [])]
        shown = ",".join(names[:5]) + (f",+{len(names) - 5}" if len(names) > 5 else "")
        lines.append(
            f"{uuid}\t{e.get('rule', '')}\t{e.get('hits', 0)} hits"
            f"\t{e['status']}\t{e.get('proposed_tag', '')}\t{shown}"
        )
    paths["quarantine_log"].write_text("\n".join(lines) + "\n")
    log(f"  quarantine now holds {len(present)} rules")
    return doc


def gate(rules, paths, settings, log=print):
    """Scan the baseline, move every rule that fired, record the decision."""
    if rules is None:
        return {}
    files, excluded = collect_baseline(settings)
    if excluded:
        log(f"  {len(excluded)} files excluded from the baseline")
    digests = hash_files(files)
    manifest = baseline_manifest(files, digests)
    hits = scan_baseline(rules, files, log=log, digests=digests)

    for uuid in read_released(paths):
        hits.pop(uuid, None)

    paths["quarantine"].mkdir(parents=True, exist_ok=True)
    moved = 0
    for uuid in hits:
        src = paths["rules"] / f"{uuid}.yara"
        if src.exists():
            shutil.move(str(src), str(paths["quarantine"] / f"{uuid}.yara"))
            moved += 1

    write_quarantine_files(
        hits, paths, describe_baseline(files, settings, manifest, excluded), log=log
    )
    log(f"  gate: {moved} rules quarantined this run")
    return hits


def describe_baseline(files, settings, manifest=None, excluded=None):
    """The corpus a verdict was measured against, in full.

    Including what was left out. A verdict reached by ignoring part of the
    corpus has to say which part, or "fired on no clean binaries" means nothing.
    """
    manifest = baseline_manifest(files) if manifest is None else manifest
    return {
        "count": len(manifest),
        "files": manifest,
        "dirs": [display_path(d) for d in (settings.get("baseline_dirs") or [])],
        "exclude_patterns": exclude_patterns(settings),
        "excluded_files": sorted(f.name for f in (excluded or [])),
        "probes": bool(settings.get("baseline_probes", True)),
        "signature": baseline_signature(manifest),
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

    sig = baseline_signature(baseline_manifest(baseline_files(settings)))

    out = {}
    for uuid, e in entries.items():
        f = paths["quarantine"] / f"{uuid}.yara"
        if not f.exists():
            # Cleared by an earlier recheck, or moved by hand. The record is
            # history; only what is in the directory can be stale.
            continue
        if e.get("rule_sha256") and e["rule_sha256"] != sha256(f):
            out[uuid] = "rule_changed"
        elif e.get("baseline_signature") and e["baseline_signature"] != sig:
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
