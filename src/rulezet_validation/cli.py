"""Command line entry point.

Wiring only -- every command is a few lines that resolve config and call into a
module. Logic lives in `source`, `mirror`, `gate`, `sync`.

    rulezet-validate sync                   # shortcut for `mirror sync`
    rulezet-validate mirror sync            # fetch, tag, compile, gate
    rulezet-validate mirror check           # re-scan the baseline, move nothing
    rulezet-validate mirror compile
    rulezet-validate mirror status
    rulezet-validate mirror recheck         # put quarantined rules back on trial
    rulezet-validate scan BINARY            # what fires on one file
    rulezet-validate baseline list

`check RULE.yar`, the single-rule linter that needs no mirror at all, lands
next; the bare-path form (`rulezet-validate my_rule.yar`) is reserved for it.
"""

import argparse
import sys

from . import config
from . import mirror as mirror_mod
from .gate import (
    Counter,
    baseline_files,
    read_released,
    recheck,
    scan_baseline,
    stale,
)
from .source import KEYLESS_MISSING, api_key
from .sync import sync as run_sync


def _resolved(args):
    settings = config.load(getattr(args, "config", None))
    if getattr(args, "mirror_dir", None):
        settings["mirror_dir"] = args.mirror_dir
    return settings, config.paths(settings)


def cmd_mirror_sync(args):
    settings, paths = _resolved(args)
    run_sync(
        settings,
        paths,
        full=args.full,
        limit=args.limit,
        meta_only=args.meta_only,
        dump=args.dump,
    )
    return 0


def cmd_mirror_compile(args):
    settings, paths = _resolved(args)
    rules = mirror_mod.compile_mirror(paths, validate=not args.no_validate)
    return 0 if rules is not None else 1


def cmd_mirror_check(args):
    """Re-scan the baseline and report. Never moves a file."""
    settings, paths = _resolved(args)
    rules = mirror_mod.load_compiled(paths)
    if rules is None:
        print("no compiled mirror; run `rulezet-validate mirror sync` first")
        return 1
    hits = scan_baseline(rules, baseline_files(settings))
    released = read_released(paths)
    for uuid, info in sorted(hits.items(), key=lambda kv: -kv[1]["n"]):
        flag = " (released)" if uuid in released else ""
        where = ",".join(info["where"])
        print(f"{uuid}\t{info['rule']}\t{info['n']} hits\t{where}{flag}")
    return 1 if any(u not in released for u in hits) else 0


def cmd_mirror_status(args):
    settings, paths = _resolved(args)
    state = mirror_mod.read_state(paths)
    key = api_key(settings)
    n_rules = len(list(paths["rules"].glob("*.yara")))
    n_quar = len(list(paths["quarantine"].glob("*.yara")))
    # Worth a line of its own: `source .env` without `export` sets a shell
    # variable, not an environment one, so the key looks set to the user and is
    # invisible to this process. Silently falling back to the public endpoint
    # then costs them the fields in KEYLESS_MISSING with no hint why.
    if key:
        print(f"api key     set ({len(key)} chars)")
    else:
        print("api key     not set  " + "; ".join(sorted(KEYLESS_MISSING.values())))
    print(f"mirror      {paths['root']}")
    print(f"rules       {n_rules}")
    print(f"quarantine  {n_quar}")
    print(f"released    {len(read_released(paths))}")
    print(f"compiled    {'yes' if paths['compiled'].exists() else 'no'}")
    stale_now = stale(paths, settings)
    print(f"last sync   {state.get('last_sync', 'never')}")
    if stale_now:
        reasons = {}
        for reason in stale_now.values():
            reasons[reason] = reasons.get(reason, 0) + 1
        detail = ", ".join(f"{n} {r}" for r, n in sorted(reasons.items()))
        print(f"stale       {len(stale_now)} quarantined ({detail})")
        print("            `rulezet-validate mirror recheck` to re-evaluate")
    return 0


def cmd_mirror_recheck(args):
    """Re-evaluate quarantined rules. Stale ones by default, --all for every one."""
    settings, paths = _resolved(args)
    if args.all:
        uuids = None
    else:
        stale_now = stale(paths, settings)
        if not stale_now:
            print("nothing stale; --all to recheck every quarantined rule")
            return 0
        for uuid, reason in sorted(stale_now.items()):
            print(f"  {uuid}\t{reason}")
        uuids = list(stale_now)
    result = recheck(paths, settings, uuids=uuids)
    return 0 if result else 1


def cmd_scan(args):
    settings, paths = _resolved(args)
    rules = mirror_mod.load_compiled(paths)
    if rules is None:
        print("no compiled mirror; run `rulezet-validate mirror sync` first")
        return 1
    noise = Counter()
    matches = rules.match(args.binary, timeout=300, console_callback=noise.hit)
    for m in matches:
        offsets = [
            hex(i.offset) for s in (m.strings or []) for i in (s.instances or [])
        ]
        print(f"{m.rule}\tns={m.namespace}\t{','.join(offsets[:8])}")
    noise.report(lambda s: print(s, file=sys.stderr))
    return 0


def cmd_baseline_list(args):
    settings, _ = _resolved(args)
    files = baseline_files(settings)
    for f in files:
        print(f)
    print(f"\n{len(files)} baseline files", file=sys.stderr)
    return 0


def _add_sync(sub, name, help_text):
    """`sync` exists twice: under `mirror`, and at the top level.

    One canonical place for the flags, registered twice. `mirror sync` is the
    honest name -- it acts on the mirror -- but it is also the command people
    run every day, and making the common case the short one is worth an alias.
    """
    p = sub.add_parser(name, help=help_text)
    p.add_argument("--full", action="store_true", help="ignore the last-sync date")
    p.add_argument("--limit", type=int, help="stop after N rules (trial runs)")
    p.add_argument("--meta-only", action="store_true", help="metadata backfill")
    p.add_argument(
        "--dump",
        action="store_true",
        help="use the API key even with --limit; downloads everything, "
        "then truncates. Slow, but the sample keeps cve/license/updated_at.",
    )
    p.set_defaults(func=cmd_mirror_sync)
    return p


def build_parser():
    p = argparse.ArgumentParser(prog="rulezet-validate", description=__doc__)
    p.add_argument("--config", help="path to a config TOML")
    p.add_argument("--mirror-dir", help="override the mirror directory")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mirror", help="manage the rulezet mirror")
    msub = m.add_subparsers(dest="mirror_cmd", required=True)

    _add_sync(msub, "sync", "fetch, tag, compile, gate")

    c = msub.add_parser("compile", help="recompile the mirror")
    c.add_argument("--no-validate", action="store_true")
    c.set_defaults(func=cmd_mirror_compile)

    k = msub.add_parser("check", help="re-scan the baseline, report only")
    k.set_defaults(func=cmd_mirror_check)

    rc = msub.add_parser("recheck", help="put quarantined rules back on trial")
    rc.add_argument(
        "--all",
        action="store_true",
        help="re-evaluate every quarantined rule, not only the stale ones",
    )
    rc.set_defaults(func=cmd_mirror_recheck)

    st = msub.add_parser("status", help="what is on disk")
    st.set_defaults(func=cmd_mirror_status)

    _add_sync(sub, "sync", "shortcut for `mirror sync`")

    sc = sub.add_parser("scan", help="what fires on one binary")
    sc.add_argument("binary")
    sc.set_defaults(func=cmd_scan)

    b = sub.add_parser("baseline", help="the known-clean corpus")
    bsub = b.add_subparsers(dest="baseline_cmd", required=True)
    bl = bsub.add_parser("list", help="files the gate will scan")
    bl.set_defaults(func=cmd_baseline_list)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:
        # Configuration problems -- a rejected key, allow_licenses without one.
        # The user can act on the sentence; the traceback only hides it.
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
