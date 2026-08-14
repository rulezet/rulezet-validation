# Contributing

## Setup

```sh
git clone https://github.com/rdmmf/rulezet-validation
cd rulezet-validation
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

The suite runs offline and takes under a second. Tests that need the network
are marked `network` and deselected in CI:

```sh
pytest -m "not network"
```

No mirror is needed to develop or test. If you want one, `mirror sync --limit
500` gives you a few hundred real rules without an API key.

## Where things live

```
src/rulezet_validation/
  config.py     settings + the mirror's file layout
  source.py     rulezet.org API, tag production
  mirror.py     rule files, tag sidecar, compile, state
  gate.py       the baseline scan and quarantine
  sync.py       orchestration
  cli.py        argparse wiring only, no logic
  baseline/     manifest + the bundled probes
```

## Things that will get a patch rejected

**Anything other than a baseline hit moving a rule into quarantine.** The
criterion is deliberately narrow and mechanical. Lint findings, risk scores,
and metadata heuristics inform a human; they never move a file. If you find
yourself wanting an exception, the answer is a `released.txt` entry or a new
finding type, not a new quarantine trigger.

**Tags in any vocabulary but Rulezet's.** This library emits MISP-style tags
exactly as Rulezet would. Mapping them into a consumer's own taxonomy happens
in the consumer. That separation is the reason this code exists as its own
repository.

**Committing anything under `data/`.** It is a build artifact: 130k rule files
with mixed licensing.

**Adding a dependency to do something a few lines of stdlib already do.**
`yara-python` is the only runtime dependency and it should stay that way unless
there is a real reason.

## Adding a check

Checks are the main contribution surface. A check is a function that takes a
rule context and returns findings — no base class, no plugin registry, no entry
points. Add the function, register it in `checks/__init__.py`, and add a
fixture rule under `tests/fixtures/` that the check fires on.

Every check needs a stable id (`RZ0xx`) and a severity:

- **error** — an observed false positive. The only severity that fails CI by
  default, and the only one tied to quarantine.
- **warn** — latent risk. Feeds the risk score, moves nothing.
- **info** — hygiene. No tag, no exit code.

A check that reports a rule as risky must be able to say *why*, with evidence a
reader can verify: the matched bytes, the file, the offset. "This rule looks
weak" is not a finding.

## Baseline artifacts

New baseline binaries need a manifest entry with a URL and a sha256, and a
`description` explaining what blind spot the artifact closes. "I built it
myself" is not sufficient provenance — a reviewer has to be able to reproduce
it. Prefer fetching over committing; commit only what is small and needed
offline.
