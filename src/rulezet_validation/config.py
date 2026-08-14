"""Configuration and the on-disk layout of a mirror.

One TOML file, environment overrides, defaults that work with no file at all.
There is no config framework here on purpose: the tool has eight settings and
a first run should need none of them.

Lookup order for the file, first hit wins:

    $RULEZET_CONFIG
    ./rulezet-validation.toml
    $XDG_CONFIG_HOME/rulezet-validation/config.toml  (or ~/.config/...)

Environment always beats the file, so CI can override without writing one.
"""

import os
from pathlib import Path

import tomllib

DEFAULT_URL = "https://rulezet.org"

DEFAULTS = {
    # rulezet.org instance to mirror. Every request this tool makes is a read.
    "url": DEFAULT_URL,
    # Optional. Unlocks `dumpRules` (one POST instead of ~1300 paged requests)
    # and incremental syncs. Prefer the RULEZET_API_KEY environment variable.
    "api_key": "",
    # Where the mirror lives. Build output, never source; keep it gitignored.
    "mirror_dir": "data/rulezet",
    # Rule licenses to keep, lowercased, e.g. ["cc0 1.0", "cc by 4.0"].
    # Empty means keep everything.
    "allow_licenses": [],
    # Directories of known-clean binaries the gate scans. The bundled probes
    # are always added on top of whatever is listed here.
    "baseline_dirs": ["/usr/bin"],
    # Cap on baseline files, so a gate run stays minutes rather than hours.
    "baseline_max_files": 300,
    # Include the bundled uClibc probes in the baseline. Turning this off
    # re-opens the static-embedded-libc blind spot; see README.
    "baseline_probes": True,
    # Reviewed uuids the gate must never quarantine. Deliberately *outside*
    # `mirror_dir`: everything in there is regenerable build output that gets
    # wiped and gitignored, and this file is neither. It is hand-written, it is
    # the only durable record of a human decision, and its history is meant to
    # live in version control.
    "released_file": "released.txt",
}

# Environment variable -> config key. Values arrive as strings and are coerced
# to the type of the default, so RULEZET_BASELINE_MAX_FILES=50 works.
ENV = {
    "RULEZET_URL": "url",
    "RULEZET_API_KEY": "api_key",
    "RULEZET_DIR": "mirror_dir",
    "RULEZET_BASELINE_DIRS": "baseline_dirs",
    "RULEZET_BASELINE_MAX_FILES": "baseline_max_files",
    "RULEZET_RELEASED_FILE": "released_file",
}


def _config_path():
    explicit = os.environ.get("RULEZET_CONFIG")
    if explicit:
        return Path(explicit)
    local = Path("rulezet-validation.toml")
    if local.exists():
        return local
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "rulezet-validation" / "config.toml"


def _coerce(value, default):
    if isinstance(default, bool):
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(value)
    if isinstance(default, list):
        # Colon-separated, like PATH, because these are directories.
        return [v for v in str(value).split(os.pathsep) if v]
    return value


def load(path=None):
    """The merged settings dict. Never raises on a missing or broken file."""
    out = dict(DEFAULTS)
    p = Path(path) if path else _config_path()
    if p.exists():
        try:
            data = tomllib.loads(p.read_text())
        except (tomllib.TOMLDecodeError, OSError):
            data = {}
        # A [rulezet] table is honoured so the file can live alongside other
        # tools' settings, but a flat file works too.
        data = data.get("rulezet", data)
        for key in out:
            if key in data:
                out[key] = data[key]
    for env_key, key in ENV.items():
        if os.environ.get(env_key):
            out[key] = _coerce(os.environ[env_key], DEFAULTS[key])
    return out


def paths(settings=None):
    """Every file the mirror owns, resolved from `mirror_dir`.

    `released.txt` is the only one a human edits; everything else is written by
    this tool. `quarantine.json` and `quarantine.txt` are the same data twice --
    JSON for machines, TSV for eyes -- and both are *merged* on each gate run
    rather than rewritten, because a quarantined rule leaves the compiled set
    and so cannot be re-observed later.
    """
    settings = settings if settings is not None else load()
    d = Path(settings["mirror_dir"]).expanduser()
    return {
        "root": d,
        "rules": d / "rules",
        "quarantine": d / "quarantine",
        "compiled": d / "rules.compiled",
        "tags": d / "tags.json",
        "quarantine_json": d / "quarantine.json",
        "quarantine_log": d / "quarantine.txt",
        "released": Path(settings["released_file"]).expanduser(),
        # Where it used to live, read as a fallback so an existing mirror
        # does not silently lose its reviewed decisions on upgrade.
        "released_legacy": d / "released.txt",
        "state": d / "state.json",
        "tag_config": d / "platform_tag_configs.json",
        "readme": d / "SYNCED_FROM.md",
    }
