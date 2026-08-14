# rulezet-validation

Mirror [rulezet.org](https://rulezet.org)'s YARA rules and validate them against
known-clean binaries.

Two halves that share a directory layout and nothing else:

- **mirror** — fetch ~130k rules, tag them in Rulezet's own MISP-style
  vocabulary, compile them, and gate them against a clean-binary baseline.
- **validate** — judge a rule on its own merits, with no mirror involved.
  *(landing next; see [Status](#status))*

## Why

A ruleset of 130k unreviewed bulk imports contains rules that fire on ordinary
software. Some of those hits are correct — a capability rule saying "this binary
speaks SMTP" is *right* about busybox, which ships a sendmail applet. Others are
not: Elastic's `Linux_Generic_Threat_d94e1020` matches uClibc's `fcntl` syscall
wrapper, so it fires on any binary statically linked against that libc.

Telling those apart needs a baseline corpus that actually covers what the rules
target. A baseline of `/usr/bin` is x86-64 dynamic glibc, and it cannot judge a
rule that fingerprints statically linked embedded libc — the rule passes the
gate and then matches every uClibc binary in the world. So this ships small
uClibc probes as part of the default baseline, and treats the corpus itself as
something to be declared and versioned rather than assumed.

## Install

```sh
pip install rulezet-validation      # or: uv tool install rulezet-validation
```

One dependency (`yara-python`). No database, no services. State is files.

## Quickstart

```sh
rulezet-validate sync --limit 500          # trial run, no API key needed
rulezet-validate mirror status
rulezet-validate scan ./suspicious.elf
```

`sync` is a shortcut for `mirror sync`; every other mirror command lives under
`mirror`.

Rules are mirrored byte-for-byte and never rewritten. Some of them call YARA's
`console` module, which prints straight to stdout from the C library — and
because `console.log()` returns true, it is chained into conditions with `and`,
so it fires while the condition is *evaluated*, not only when it matches. Across
a 300-file baseline that buries the result under lines like `The SHA256 Hash :
e0d411...`. Those are captured and reduced to a count. The rules themselves are
untouched; only where their output goes changes.

Every request this tool makes is a read; nothing is written back to
rulezet.org.

### What an API key changes

More than speed. The public and private endpoints **do not return the same
fields**, and the difference is silent — nothing errors, the columns are simply
absent from the response:

| | keyless (`searchPage`) | with `RULEZET_API_KEY` (`dumpRules`) |
|---|---|---|
| rule text, title, description, author | yes | yes |
| `cve_id` → `cve:` / `ghsa:` / `pysec:` tags | **no** | yes |
| `license` → `allow_licenses` filtering | **no** | yes |
| `updated_at` → incremental sync | **no** | yes |
| cost of a full mirror | ~1300 paged requests | one POST |

So a keyless mirror gets tags from the title/description regex table only. `sync`
says this out loud on every keyless run rather than leaving you to notice the
missing tags months later, and it refuses to start if `allow_licenses` is set
without a key — that combination would skip all 130k rules and report an empty
mirror as success.

The key is read from the environment, not from a `.env` file — no dependency is
worth it for one variable. If you keep one, source it yourself:

```sh
set -a; . ./.env; set +a
```

`.env` is gitignored.

### Backfilling an existing mirror

Already synced without a key? Add one, then:

```sh
export RULEZET_API_KEY=...
rulezet-validate mirror sync --meta-only
```

`--meta-only` refetches every rule, updates the tag sidecar and metadata, and
touches neither the rule files nor any quarantine decision. It ignores the
last-sync date by definition — the rules it is describing are the old ones.

Two limits:

- Tags are only ever **added**, never removed. Delete `tags.json` first if you
  want a clean rebuild.
- It cannot enforce a newly set `allow_licenses`: disallowed rules drop out of
  the sidecar, but their `.yara` files stay on disk. Use `mirror sync --full`
  when the licence policy itself changes.

Running it keyless is close to pointless — the fields it exists to backfill are
the ones a public response omits — so it says so and gets on with it. The one
real use is re-deriving tags after deleting the cached
`platform_tag_configs.json` to pick up a newer upstream table.

## Configuration

Optional. First hit wins: `$RULEZET_CONFIG`, `./rulezet-validation.toml`,
`~/.config/rulezet-validation/config.toml`. Environment always beats the file.

```toml
mirror_dir = "data/rulezet"
baseline_dirs = ["/usr/bin"]
baseline_max_files = 300
baseline_probes = true
baseline_exclude = ["capa*", "die", "yara*"]   # see below
released_file = "released.txt"
allow_licenses = []          # e.g. ["cc0 1.0", "cc by 4.0"]; empty keeps all
```

### Excluding files from the corpus

Some perfectly legitimate software carries malicious content on purpose.
Reverse-engineering tools — DIE, capa, yara itself — ship malware signatures and
sample strings, so a rule firing on them is the rule *working*. Leaving them in
the baseline quarantines good rules.

`baseline_exclude` takes fnmatch patterns, tested against both the bare filename
and the full path:

```toml
baseline_exclude = ["capa*", "die", "/opt/ghidra/*"]
```

The list is recorded in every verdict, because a decision reached by ignoring
part of the corpus has to say so.

## The evidence a verdict carries

`quarantine.json` records what was measured, not a summary of it:

```json
"matched": [
  {
    "file": "a.bin",
    "path": "/usr/bin/a.bin",
    "sha256": "76b81057ba9e752c8faa4eb7fa873cc7094007259a8730eab78ca5f3853bb537",
    "strings": ["$mz", "$w"],
    "offsets": ["0x0", "0x3"],
    "offsets_total": 2,
    "offsets_truncated": false
  }
]
```

Every matching file, with its hash and the addresses it matched at — not three
examples. "and 297 others" is not something a reviewer can check.

The `baseline` block lists every file in the corpus with its sha256 and size,
so "fired on 300 clean binaries" becomes a reproducible claim: fetch the same
files, verify the hashes, re-run the gate. `baseline.signature` is a sha256 over
those hashes, which means a binary edited in place — same name, same length — is
detected as `baseline_changed`.

Offsets are capped at 64 per file per rule, with `offsets_truncated` saying so;
one pathological rule matching a two-byte string should not write a megabyte
into the record.

## The quarantine criterion

> A rule is quarantined **if and only if** it matched at least one file in the
> baseline corpus, and its uuid is not in `released.txt`.

That is the whole rule. It is an observation, not a judgement — nothing inspects
a rule's quality, metadata, or author's intent, and no lint finding or risk
score ever moves a file.

Because a clean-binary hit is not automatically a defect, review is expected.
Put the uuid in `released.txt` when the hit was legitimate; it is honoured on
every later run, so a decision is never re-litigated. Explain the decision in
the commit message that adds the line — that is the audit trail.

Quarantined rules are **moved, not deleted**. `rules/` and `quarantine/` are
both real directories you can compile, copy, or hand to another project.

### A quarantine is a measurement, not a sentence

A verdict is only true of the rule text it judged and the corpus it judged
against. Both move. So each entry in `quarantine.json` records a hash of the
rule and a signature of the baseline, and a decision goes **stale** when either
changes:

- `rule_changed` — upstream fixed it; the verdict describes bytes that no
  longer exist.
- `baseline_changed` — a probe was added, a corpus swapped. The rule was judged
  against a different world.
- `unverifiable` — quarantined before hashes were recorded, so nothing can
  claim the verdict still holds.

```sh
rulezet-validate mirror status     # reports how many are stale, and why
rulezet-validate mirror recheck    # put the stale ones back on trial
rulezet-validate mirror recheck --all
```

`recheck` returns the selected rules to `rules/`, recompiles, and re-runs the
gate: whatever still fires goes back to quarantine with a fresh verdict,
whatever doesn't simply stays. `first_seen` survives, so history isn't rewritten
by a retry, and `released.txt` is untouched — a human decision is not something
a re-run gets to overturn.

This is never automatic. A sync reports staleness and stops, because silently
reopening a reviewed decision is its own kind of wrong.

Sync keeps quarantined rules' text current, writing updates into `quarantine/`
rather than readmitting them. Skipping them instead — the obvious option — would
pin each rule at the version that got it quarantined, so an upstream fix could
never arrive and staleness could never be detected.

## Mirror layout

```
data/rulezet/
  rules/<uuid>.yara       one file per rule; the uuid is the yara namespace
  quarantine/<uuid>.yara  fired on the baseline
  rules.compiled          saved yara ruleset
  tags.json               {uuid: [misp-style tag, ...]}
  quarantine.json         machine-readable record, merged across runs
  quarantine.txt          same data, for eyes
  state.json              last_sync + the baseline the decisions were made with
  .gitignore              written on sync: the mirror ignores itself
```

`released.txt` deliberately lives **outside** the mirror, next to your config
(`released_file`, default `./released.txt`). Everything under `mirror_dir` is
regenerable build output — gitignored, safe to `rm -rf`. `released.txt` is
neither: it is hand-written, it is the only durable record of a human decision,
and its history belongs in version control. It cannot be both ignored and
committed, so it is not stored with the things that are ignored. The old
in-mirror location is still read, so upgrading loses nothing.

### What is and is not gitignored

| | |
|---|---|
| `data/` (default `mirror_dir`) | ignored by the repo's `.gitignore` |
| any other `mirror_dir` | ignores itself — `sync` writes a `.gitignore` of `*` into it |
| `released.txt` | **not** ignored. Commit it; that is the audit trail |
| `.env`, `rulezet-validation.toml` | ignored |

One thing to know before wiping a mirror: `quarantine.json` holds `first_seen`
for every verdict, and that history is not regenerable. The rules and the
compiled ruleset are.

Tags stay in Rulezet's vocabulary (`ms-caro-malware-full:malware-type="Ransom"`,
`cve:CVE-2021-44228`). Mapping them into some other taxonomy is the consumer's
job, not this library's.

Nothing under `data/` is source. Regenerate it; never commit it.

## Embedding

```python
from rulezet_validation import load_config, paths
from rulezet_validation.sync import sync

settings = load_config()
sync(settings, paths(settings), on_rules=my_indexer)
```

`on_rules` receives `{uuid: metadata row}` for everything fetched — the seam for
indexing rule provenance into a host application's own store.

## Status

Working: mirror sync, tagging, compile, gate, quarantine records, CLI, tests.

Next, in order:

1. `rulezet-validate check RULE.yar` — single-rule linter, no mirror required.
   Static checks (glob collisions like `4 of ($arch*)` silently covering
   `$archx*`; strings that alone satisfy a condition; weak strings) plus
   empirical ones against the baseline.
2. `baseline sync` — fetch the larger corpora declared in `baseline/manifest.toml`.
3. `false-positive:risk` tags — emitted only where the baseline actually
   exercises the rule, `cannot-be-judged` otherwise (which is most of a 130k
   ruleset). `false-positive:confirmed` needs labelled malware analysis and is
   deliberately not attempted yet.

## Licence

AGPL-3.0. See [NOTICE](NOTICE) for the licensing of fetched and bundled
artifacts, which is not the same thing.
