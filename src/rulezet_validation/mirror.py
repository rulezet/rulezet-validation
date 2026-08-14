"""The mirror on disk: rule files, the tag sidecar, and the compiled ruleset.

Tags live in a `tags.json` sidecar keyed by rule uuid rather than being injected
into the rule text: `yara.compile(filepaths={uuid: path})` makes
`match.namespace` the uuid, which makes the join exact even though rule *names*
collide freely across 130k rules from different repos. It also means nothing
here has to parse or rewrite YARA source.
"""

import json
import time

from .source import platform_tags


def protect(paths):
    """Drop a `.gitignore` of `*` into the mirror root.

    The repo's own `.gitignore` covers the default `data/`, but `mirror_dir` is
    configurable and a mirror is 130k rule files plus a ~440 MB compiled blob
    with mixed upstream licensing. Pointing it anywhere else inside a checkout
    should not put that one `git add -A` away from being committed, so the
    directory ignores itself wherever it lands.

    Note this is the reason `released_file` lives outside: it is a hand-written
    record meant to be committed, and it cannot be both.
    """
    paths["root"].mkdir(parents=True, exist_ok=True)
    f = paths["root"] / ".gitignore"
    if not f.exists():
        f.write_text("# Build output: regenerate with `rulezet-validate sync`.\n*\n")
    return f


def write_rules(rules, tag_config, paths, settings, log=print, write_files=True):
    """Rule text to `rules/<uuid>.yara`, tags to the sidecar.

    Returns `(sidecar tags, metadata rows)`. The rows are everything a user
    needs to get back to a rule on rulezet.org, taken while the API response is
    still in hand: after a sync all that is left on disk is `<uuid>.yara`, and
    no read endpoint takes a uuid.

    `write_files=False` is the `--meta-only` backfill: the rule files are
    already on disk from an earlier sync, only the metadata is missing.
    """
    paths["rules"].mkdir(parents=True, exist_ok=True)
    quarantined = {f.stem for f in paths["quarantine"].glob("*.yara")}
    tags, rows, written, skipped = {}, {}, 0, 0

    allow = [x.lower() for x in (settings.get("allow_licenses") or [])]
    for rule in rules:
        uuid = rule.get("uuid") or str(rule.get("id") or "")
        text = rule.get("to_string") or rule.get("content") or ""
        if not uuid or not text.strip():
            skipped += 1
            continue
        if allow and str(rule.get("license") or "").strip().lower() not in allow:
            skipped += 1
            continue
        if write_files:
            # A quarantined rule still gets its new text, written to
            # `quarantine/` rather than `rules/`. Skipping it entirely (the
            # obvious thing) pins the rule at the version that was quarantined,
            # so an upstream fix can never arrive and the verdict describes
            # bytes that no longer exist anywhere. Keeping the text current is
            # also what makes staleness detectable: `gate.stale()` compares the
            # file against the hash recorded when the verdict was made.
            target = "quarantine" if uuid in quarantined else "rules"
            (paths[target] / f"{uuid}.yara").write_text(text)
            written += 1

        rule_tags = platform_tags(rule, tag_config)
        if rule_tags:
            tags[uuid] = rule_tags
        rows[uuid] = {
            "uuid": uuid,
            "name": rule.get("title") or "",
            "description": rule.get("description") or "",
            "license": rule.get("license") or "",
            "author": rule.get("author") or "",
            "updated_at": rule.get("updated_at") or "",
            "tags": rule_tags,
        }

    log(
        f"  {written} rule files written, {skipped} skipped "
        f"(license/empty), {len(tags)} carry tags"
    )
    return tags, rows


def merge_tags(new_tags, paths):
    """Fold newly produced tags into the sidecar, preserving what is there.

    A sync can only add to the sidecar, never wipe it: tags obtained by other
    means (a curated per-rule lookup, a hand edit) must survive the next sync.
    """
    p = paths["tags"]
    old = {}
    if p.exists():
        try:
            old = json.loads(p.read_text())
        except (ValueError, OSError):
            old = {}
    for uuid, tags in new_tags.items():
        old[uuid] = sorted(set(old.get(uuid, [])) | set(tags))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(old))
    return old


def compile_mirror(paths, log=print, validate=True):
    """Validate every rule file, compile the survivors, save the ruleset.

    Per-file validation first: one bad rule fails the whole bulk compile, and at
    this scale there is always a bad rule. Measured ~7ms a file, so ~15 min at
    130k -- the price of not having a single syntax error cost you the sync.

    `validate=False` skips it, for the rebuild after the gate: those same files
    were just validated, and quarantining moves files out rather than changing
    any, so a second pass can only reach the same verdict at full price.
    """
    import yara

    files, bad = {}, []
    t0 = time.time()
    for f in sorted(paths["rules"].glob("*.yara")):
        if validate:
            try:
                yara.compile(filepath=str(f))
            except yara.Error:
                bad.append(f)
                continue
        # The uuid *is* the namespace, which is what makes the tag sidecar join
        # exact -- rule names collide across 130k rules from different repos.
        files[f.stem] = str(f)
    for f in bad:
        f.unlink()
    if validate:
        log(
            f"  validated {len(files)} rules, dropped {len(bad)} unparseable "
            f"({time.time() - t0:.0f}s)"
        )

    if not files:
        return None
    t0 = time.time()
    rules = yara.compile(filepaths=files)
    rules.save(str(paths["compiled"]))
    log(
        f"  compiled + saved in {time.time() - t0:.0f}s "
        f"({paths['compiled'].stat().st_size / 1e6:.0f} MB)"
    )
    return rules


def load_compiled(paths):
    """The saved ruleset, or None when no mirror has been compiled yet."""
    import yara

    if not paths["compiled"].exists():
        return None
    try:
        return yara.load(str(paths["compiled"]))
    except yara.Error:
        return None


def read_state(paths):
    if not paths["state"].exists():
        return {}
    try:
        return json.loads(paths["state"].read_text())
    except (ValueError, OSError):
        return {}


def write_state(paths, **fields):
    """Merge `fields` into `state.json`.

    The baseline block matters as much as `last_sync`: a quarantine decision is
    only reproducible if you know what corpus produced it, and a re-run against
    a different baseline silently means something else.
    """
    state = read_state(paths)
    state.update(fields)
    paths["state"].parent.mkdir(parents=True, exist_ok=True)
    paths["state"].write_text(json.dumps(state, indent=2, sort_keys=True))
    return state
