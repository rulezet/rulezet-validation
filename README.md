# rulezet-validation

Mirror [rulezet.org](https://rulezet.org)'s YARA rules and scan them against
known-clean binaries. Any rule that fires on clean software is quarantined, with
the evidence recorded.

## Install

```sh
pip install git+https://github.com/rulezet/rulezet-validation

# or from a clone
git clone https://github.com/rulezet/rulezet-validation
cd rulezet-validation && pip install .      # uv pip install . works the same

# development
pip install -e ".[dev]" && pytest
```

One dependency: `yara-python`. No database, no services. State is files.

## CLI

| command | does |
|---|---|
| `sync` | shortcut for `mirror sync` |
| `mirror sync` | fetch rules, compile, run the gate |
| `mirror gate` | re-run the gate on the mirror on disk, no fetch |
| `mirror check` | re-scan the baseline, report only, move nothing |
| `mirror recheck` | put quarantined rules back on trial |
| `mirror compile` | recompile the mirror |
| `mirror status` | key, counts, last sync, stale verdicts |
| `scan BINARY` | what fires on one file |
| `check RULE.yar\|DIR ...` | scan your own rules against the baseline. No mirror, no key. Bare `rulezet-validate my.yar` works too. Exit 1 if any rule fires or fails to compile |
| `baseline list` | files the gate will scan |
| `baseline sync` | download and verify the pinned clean-binary corpus |

| flag | on | does |
|---|---|---|
| `--limit N` | `sync` | stop after N rules. Ignores the API key — the bulk endpoint cannot fetch a subset |
| `--dump` | `sync` | use the key anyway with `--limit`; downloads everything, then truncates |
| `--full` | `sync` | ignore the last-sync date |
| `--meta-only` | `sync` | refresh metadata only, leave rule files alone |
| `--all` | `mirror recheck` | re-evaluate every quarantined rule, not only stale ones |
| `--mirror-dir` | any | override the mirror location |
| `--config` | any | path to a config TOML |

Test a local rule without syncing rulezet:

```bash
rulezet-validate baseline sync
rulezet-validate check my_rule.yar rules_dir/
```

## Configuration

Optional. First hit wins: `$RULEZET_CONFIG`, `./rulezet-validation.toml`,
`~/.config/rulezet-validation/config.toml`.

Precedence, strongest first: environment, `.env`, config file, defaults.

```toml
mirror_dir = "data/rulezet"
released_file = "released.txt"
baseline_dirs = ["data/baseline"]
baseline_max_files = 300
baseline_probes = true
baseline_exclude = []
baseline_exclude_defaults = true
allow_licenses = []          # e.g. ["cc0 1.0"]; empty keeps all. Needs an API key
```

Every setting has an environment equivalent:

| setting | variable |
|---|---|
| `mirror_dir` | `RULEZET_DIR` |
| `released_file` | `RULEZET_RELEASED_FILE` |
| `baseline_dirs` | `RULEZET_BASELINE_DIRS` |
| `baseline_max_files` | `RULEZET_BASELINE_MAX_FILES` |
| `baseline_probes` | `RULEZET_BASELINE_PROBES` |
| `baseline_exclude` | `RULEZET_BASELINE_EXCLUDE` |
| `baseline_exclude_defaults` | `RULEZET_BASELINE_EXCLUDE_DEFAULTS` |
| `allow_licenses` | `RULEZET_ALLOW_LICENSES` |
| `url` | `RULEZET_URL` |
| `api_key` | `RULEZET_API_KEY` |

List values are separated like `PATH` (`:` on Linux); booleans accept
`1/true/yes/on`. `RULEZET_API_KEY` is also read from a `.env` in the working
directory; `mirror status` reports whether it reached the process.

## The baseline

What counts as known-clean: the bundled uClibc ARM probes, plus
`baseline_dirs`, minus the exclusions. After a one-time sync the default
directory holds about 10,200 pinned ELF and PE files across x86, x86-64, ARM,
AArch64, MIPS, PowerPC, s390x and RISC-V; it does not depend on this machine's
`/usr/bin`. A first sync downloads about 6 GB and needs about 13 GB free,
because the downloaded packages stay in `data/` caches for later syncs.

```sh
rulezet-validate baseline sync
rulezet-validate baseline list
```

The source URLs, licenses, package and file SHA-256 hashes are in
`src/rulezet_validation/baseline/manifest.toml` and
`src/rulezet_validation/baseline/curated.json`. Sync downloads to gitignored
`data/baseline/default/`; it verifies both the download and the scanned file before
using it. Extraction needs `dpkg-deb`, `zstd` and `xz` on the PATH.
The default gate
requires a sync first; use `baseline list` to see the exact files.

The curated lock contains 2,000 files: 1,600 amd64 ELF binaries from Ubuntu
24.04 `main`, and 400 amd64 PE binaries from MSYS2 MinGW packages whose SPDX
license is MIT, BSD, Apache, ISC, 0BSD, Zlib, BSL, or CC0. The process picks
packages in SHA-256 order of package name, takes at most ten executable files
from each package in SHA-256 order of member path, and rejects packages above
5 MB or files above 3 MB. It records the official index hashes, package URLs,
package hashes, member paths, and file hashes. Ubuntu `main` is a redistributable
archive component; the index does not provide individual SPDX tags, so each
Ubuntu package's copyright file remains the authoritative license record.
Ubuntu `main` includes copyleft packages; the default is a free-software
selection, not a permissive-only selection.
MSYS2 maintains package license metadata on a best-effort basis; check package
notices before redistributing binaries.
No downloaded package or binary is committed. To regenerate a selection with a
different size and update the lock:

```sh
PYTHONPATH=src python3 -m rulezet_validation.baseline_curate --count 2000
```

Three more locks bring the default corpus to about 10,200 files:

| lock | files | what |
|---|---|---|
| `baseline/ports.json` | 3,000 | Debian `main` ELF for arm64, armhf, armel, mipsel, mips64el, ppc64el, s390x, i386 (bookworm) and riscv64 (trixie), equal share each, from a fixed snapshot.debian.org timestamp |
| `baseline/openwrt.json` | 1,000 | OpenWrt 23.05.5 `base` and `packages` feeds for eight 32-bit ARM CPU targets (ARMv5 to Cortex-A15). ARM encoding and musl libc, closer to embedded malware builds than Debian armhf (Thumb-2) |
| `baseline/assemblage.json` | 4,200 | [Assemblage](https://assemblage-dataset.net/): 2,500 MSVC Windows PE, 1,500 gcc/clang C/C++ Linux ELF, 200 Rust Linux ELF (llvm, gcc, cranelift). Permissive licenses only, at most 3 files per repository |

Sync downloads each ports package from `deb.debian.org` first and falls back
to the pinned snapshot.debian.org URL only when the live mirror has dropped
the file; the pinned SHA-256 is checked either way.

Assemblage is x86 and x86-64 only, so architecture coverage comes from the
Debian ports and OpenWrt. See `docs/assemblage-subset.md` for how the Assemblage subset is
read from its multi-GB archives.

```sh
PYTHONPATH=src python3 -m rulezet_validation.baseline_curate --ports --count 3000
PYTHONPATH=src python3 -m rulezet_validation.baseline_curate --openwrt --count 1000
PYTHONPATH=src python3 -m rulezet_validation.baseline_assemblage --pe 2500 --elf 1500 --rust 200
```

Regeneration uses the current upstream indexes, so it can change the selection.
The committed lock makes ordinary `baseline sync` reproducible.

To add your own clean files, copy a directory into `data/baseline/`, for example
`data/baseline/my_custom_dir/`. The gate scans nested files automatically.
Only put files there that you want treated as known-clean. The existing
`baseline_max_files` cap still applies across all added directories.

`baseline sync --all-licenses` additionally downloads the opt-in GPL sample to
`data/baseline-all-licenses/` and prints a license warning. That directory is
not in the default gate. Add it to `baseline_dirs` locally to scan it. The
independent `--skip-hash-verification` flag bypasses checks with a warning; it
does not change license selection.

| behaviour | |
|---|---|
| sampling | even stride across the sorted directory if files exceed `baseline_max_files` (default 2100; `check` scans every file) |
| symlinks | skipped, not followed |
| exclusions | do not consume a slot in `baseline_max_files` |
| probes | always included, never displaced by the cap |

```sh
rulezet-validate baseline list      # exactly what will be scanned
```

### Excluding files

| layer | where | note |
|---|---|---|
| shipped | `src/rulezet_validation/baseline/exclude.txt` | capa, DIE, yara, ClamAV, radare2, metasploit, UPX, binwalk. One reason per entry, open to pull requests |
| local | `baseline_exclude` | additive; fnmatch against both the bare filename and the full path |

```toml
baseline_dirs = ["/usr/bin", "/usr/sbin", "/opt/vendor-firmware/bin"]
baseline_max_files = 1500
baseline_exclude = ["/opt/ghidra/*", "our-internal-scanner"]
baseline_exclude_defaults = false    # ignore the shipped list entirely
```

| the test | |
|---|---|
| excluded | carries attack content or detection signatures as part of its job — `capa` embeds its own rules |
| not excluded | merely matches a rule — `objdump` lists every architecture it supports, and a rule reading that as a malware indicator is the rule's bug |

## Mirror layout

Default `data/rulezet/`, set by `mirror_dir`. Disposable: it writes its own
`.gitignore`, and `sync` rebuilds it.

```
data/rulezet/
  rules/<uuid>.yara       one file per rule; the uuid is the yara namespace
  quarantine/<uuid>.yara  fired on the baseline
  rules.compiled          saved yara ruleset
  tags.json               {uuid: [tag, ...]}
  quarantine.json         the verdicts and their evidence   <-- what you want
  quarantine.txt          same, as a TSV index
  state.json              last sync + the baseline in use
  .gitignore              written on sync
```

| file | gitignored | |
|---|---|---|
| `data/`, and any other `mirror_dir` | yes | disposable, regenerated by `sync` |
| `released.txt` | no | hand-written, lives outside the mirror, commit it |
| `.env`, `rulezet-validation.toml` | yes | |

## quarantine.json

A rule is quarantined **if and only if** it fired on the baseline and its uuid
is not in `released.txt`. Nothing else moves a file.

```json
{
  "baseline": {
    "count": 2102,
    "signature": "742ff72ca0128ad4cfbe700e300b1cc55dd7bc17f82944d966ca41b37e34377b",
    "dirs": ["data/baseline"],
    "exclude_patterns": ["capa*", "die"],
    "excluded_files": [],
    "files": [
      {
        "name": "9a9c61e49958-bzip2",
        "path": "data/baseline/default/openwrt/openwrt-arm_cortex-a9-base/bzip2/9a9c61e49958-bzip2",
        "sha256": "…",
        "size": 28707
      }
    ]
  },
  "quarantined": {
    "adca4692-e22e-4952-a6b1-0baaa1e91ede": {
      "rule": "Linux_Generic_Threat_d94e1020",
      "status": "quarantined",
      "reason": "baseline_hit",
      "hits": 2,
      "first_seen": "2026-08-14T08:57:05Z",
      "last_checked": "2026-08-14T08:57:05Z",
      "rule_sha256": "a5b92da6a313f57d4e425da01f8f1d483f5d1181af7fbd06ebb1bff3b5c63c4f",
      "baseline_signature": "742ff72ca0128ad4…",
      "matched": [
        {
          "file": "clean_uclibc_fcntl.elf",
          "path": "<probes>/clean_uclibc_fcntl.elf",
          "sha256": "1794c4ad1d5872cfd2c1b3e81bb4d444df5b7c443f8310d6016fc2fe00e15d0c",
          "strings": ["$a1"],
          "offsets": ["0xd9d"],
          "offsets_total": 1,
          "offsets_truncated": false
        }
      ]
    }
  }
}
```

| field | note |
|---|---|
| `matched` | every matching file, not a sample. Offsets capped at 64/file, flagged when truncated |
| `path` | publish-safe: `$HOME` becomes `~/…`, bundled probes become `<probes>/…`, system paths kept verbatim |
| `baseline.files` | the whole corpus with hashes, so the verdict is reproducible |
| `status` | `quarantined` or `cleared` — history is kept, cleared entries stay |

## Releasing a rule

A clean-binary hit is not automatically a defect: `network_smtp_raw` firing on
busybox is correct, since busybox has a sendmail applet. A uuid in
`released.txt` is never quarantined again.

```
# reviewed: capability rule, MAIL FROM:/RCPT TO: on busybox is correct
ea0359a9-7798-410c-b9cf-3b9cfd72bbc0
```

## Rechecking

A verdict is only true of the rule text and the corpus it was measured on.

| stale reason | means |
|---|---|
| `rule_changed` | upstream edited the rule |
| `baseline_changed` | a probe, a corpus, or a binary changed |
| `unverifiable` | quarantined before hashes were recorded |

```sh
rulezet-validate mirror status      # how many are stale, and why
rulezet-validate mirror recheck     # stale ones
rulezet-validate mirror recheck --all
```

| recheck | |
|---|---|
| does | returns rules to `rules/`, recompiles, re-gates. Still fires → back to quarantine |
| never | automatic. A sync reports staleness and stops |
| leaves alone | `released.txt`, `first_seen` |

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

Working: sync, tagging, compile, gate, quarantine records, recheck, CLI.

Each quarantine record carries a `proposed_tag` — `false-positive:risk=high`
(20+ clean binaries hit), `medium` (5–19), `low` (1–4), or `cannot-be-judged`
when there is no observation behind the record at all. It is a suggestion for
the reviewer, not a verdict: nothing moves on it, and a risk tag already
present upstream is recorded next to it as `upstream_tag` rather than
overwriting or being overwritten.

Next:

1. `rulezet-validate check RULE.yar` — single-rule linter, no mirror needed.
2. Expand the pinned baseline with more architectures and packages.
3. Static checks feeding the risk proposal, so a rule can be judged on more
   than its hit count.

## Licence

AGPL-3.0. See [NOTICE](NOTICE) for fetched and bundled artifacts, which are
under their own terms.
