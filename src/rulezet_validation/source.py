"""Reading rules and tags out of rulezet.org.

Three facts about the API shape this whole module:

  * **No endpoint ever returns a rule's tags.** `Rule.to_json()` has no tags
    field and every read path uses it -- public search, detail, CVE search,
    private search, `dumpRules`, the bundle zip. Tags exist server-side but are
    only readable through login-gated UI routes, one rule per call. So the
    MISP-style tags this module attaches are *produced locally* (see
    `platform_tags`), never received.
  * `per_page` caps at 100, so a keyless full mirror is ~1300 requests. With an
    API key `dumpRules` returns everything in one POST and takes an
    `updated_after` for incremental syncs. Both are reads -- nothing is ever
    written back to rulezet.org.
  * **The public and private paths do not return the same fields.** A
    `dumpRules` row carries `cve_id`, `license` and `updated_at`; a keyless
    `searchPage` row carries only author, content, creation_date, description,
    format, title, uuid. So without an API key there are no vulnerability tags
    to derive, no license to filter on, and no timestamp to sync incrementally
    against. See `KEYLESS_MISSING`, and note that this is a silent difference
    in the API -- nothing errors, the fields are simply absent.

Tags stay in Rulezet's own MISP-style form (`namespace:predicate="value"`).
Mapping them into some other vocabulary is the consumer's job, not this
library's -- that is the whole reason this code left BSimVis.
"""

import json
import os
import re
import urllib.error
import urllib.request

from .config import DEFAULT_URL

# Rulezet auto-tags its bulk imports by running regexes over each rule's title
# and description (`app/core/utils/default_platform_tag_configs.json`). Running
# the same table locally reproduces most of the tag set they hold with zero
# requests and no API key. It is *downloaded* into the mirror directory rather
# than vendored: rulezet-core is AGPL-3.0 and their file is treated exactly like
# their rules -- fetched at sync time, never committed.
TAG_CONFIG_URL = (
    "https://raw.githubusercontent.com/rulezet/rulezet-core/main/"
    "app/core/utils/default_platform_tag_configs.json"
)

# A vulnerability id in the `cve_id` column. Rulezet stores CVE, GHSA and PYSEC
# ids there, as a JSON list or a bare string depending on the import path.
#
# The en-dash is accepted in *both* separator positions, not just the first:
# ids scraped from prose sometimes arrive fully typographic ("CVE–2021–44228"),
# and matching only the leading dash truncates the id to "CVE-2021".
VULN_RE = re.compile(r"\b(CVE|GHSA|PYSEC)[-–][\w.–-]+", re.I)


# --- HTTP -------------------------------------------------------------------
# urllib rather than requests: three call sites, no session state, no retries
# worth the dependency. Every one of these is a read.


def api_key(settings):
    """The configured key, or "" -- environment beating the config file."""
    return settings.get("api_key") or os.environ.get("RULEZET_API_KEY") or ""


# Fields the public `searchPage` endpoint does not return, with what each one
# costs you. Measured against the live API, not assumed: a keyless row carries
# only author, content, creation_date, description, format, title, uuid.
KEYLESS_MISSING = {
    "cve_id": "no cve:/ghsa:/pysec: tags",
    "license": "no license filtering",
    "updated_at": "no incremental sync",
}


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _post(url, body, key, timeout=600):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-API-KEY": key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def fetch_rules(settings, since=None, limit=None, log=print, dump=False):
    """Every YARA rule on the instance, as the API's own dicts.

    With an API key this is one `dumpRules` POST (and `since` makes it
    incremental). Without one it pages `searchPage` at the API's 100/page cap,
    which costs ~1300 requests for a full mirror -- measured at ~25s with 8
    threads, but kept serial here because a sync is not the thing to be clever
    about.
    """
    base = (settings.get("url") or DEFAULT_URL).rstrip("/")
    key = api_key(settings)

    # `dumpRules` has no size parameter -- it is all-or-nothing, ~130k rules and
    # 128 MB before the first byte is usable. So a trial run pages the public
    # endpoint instead, which really does stop early. Otherwise `--limit 2000`
    # would still cost the full ~2 minute download to then throw 128k rules away.
    if key and limit and not dump:
        log(
            f"--limit {limit}: your API key is set, but dumpRules has no size "
            f"parameter -- it would download all ~130k rules (128 MB) to then "
            f"discard all but {limit}. Paging the public endpoint instead, "
            f"which really does stop early."
        )
        log(
            "  the sample will therefore lack: "
            + "; ".join(sorted(KEYLESS_MISSING.values()))
        )
        log("  pass --dump to use the key anyway and pay the full download.")
        key = ""

    if key:
        body = {"format_name": "yara"}
        if since:
            body["updated_after"] = since
        log(
            f"dumpRules (incremental since {since})"
            if since
            else "dumpRules (full): ~130k rules, 128 MB, ~2 min before "
            "anything is written"
        )
        try:
            doc = _post(f"{base}/api/rule/private/dumpRules", body, key)
        except urllib.error.HTTPError as e:
            # An incremental sync with nothing new answers 404 "No rules found
            # to dump." That is the ordinary quiet case, not a failure -- every
            # re-run between updates would otherwise raise.
            if e.code == 404:
                return []
            if e.code in (401, 403):
                # A rejected key is a typo or an expired credential, not a bug.
                # A stack trace here tells the user nothing they can act on, and
                # buries the one fact that matters.
                raise ValueError(
                    f"rulezet.org rejected the API key (HTTP {e.code}). "
                    f"Check RULEZET_API_KEY -- `rulezet-validate mirror status` "
                    f"shows whether the value reaching this process is the one "
                    f"you meant. Without a key, plain `sync` still works "
                    f"against the public endpoint."
                ) from None
            raise
        rules = (doc.get("data", {}).get("rules_by_format", {}) or {}).get("yara", [])
        return rules[:limit] if limit else rules

    out, page = [], 1
    while True:
        url = (
            f"{base}/api/rule/public/searchPage"
            f"?rule_type=yara&per_page=100&page={page}"
        )
        doc = _get(url)
        out.extend(doc.get("results") or [])
        if page == 1:
            log(
                f"{doc.get('total_rules_found', 0)} yara rules available, "
                f"paging at 100/request ({doc.get('total_pages', 0)} pages)"
            )
        if limit and len(out) >= limit:
            return out[:limit]
        if not (doc.get("pagination") or {}).get("next_page"):
            return out
        page += 1
        if page % 50 == 0:
            log(f"  page {page}, {len(out)} rules")


# --- Local tagging ----------------------------------------------------------


def load_tag_config(path, refresh=False, log=print):
    """Rulezet's own regex->MISP-tag table, cached at `path`."""
    if refresh or not path.exists():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(_get(TAG_CONFIG_URL)))
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"  tag config unavailable ({e}); rules get cve tags only")
            return []
    try:
        groups = json.loads(path.read_text())
    except (ValueError, OSError):
        return []
    out = []
    for entries in groups.values():
        for e in entries:
            if not e.get("enabled", True):
                continue
            try:
                out.append((re.compile(e["regex"], re.I), e["tag_name"]))
            except re.error:
                continue
    return out


def vulns(rule):
    """Vulnerability ids off the `cve_id` column, whatever shape it arrived in."""
    raw = rule.get("cve_id")
    if not raw:
        return []
    if isinstance(raw, list):
        text = " ".join(str(x) for x in raw)
    else:
        text = str(raw)
    return sorted(
        {m.group(0).upper().replace("–", "-") for m in VULN_RE.finditer(text)}
    )


def platform_tags(rule, tag_config):
    """The MISP-style source tags for one rule, in Rulezet's own vocabulary.

    Two producers, neither of which needs an API key: the vulnerability ids that
    ship in the rule row, and Rulezet's own title/description regex table.
    """
    tags = [f"{v.split('-')[0].lower()}:{v}" for v in vulns(rule)]
    # Rulezet does not tag false-positive risk yet, and no endpoint returns
    # tags at all -- but the column is coming, and a rule row that carries one
    # should not lose it on the way into the mirror. Only this one family is
    # taken: anything else arriving under `tags` belongs to a vocabulary this
    # module does not claim to understand.
    raw = rule.get("tags") or []
    tags += [
        t
        for t in (raw if isinstance(raw, list) else [raw])
        if isinstance(t, str) and t.startswith("false-positive:risk:")
    ]
    # Underscores become spaces first. Rulezet's regexes are `\b`-anchored and
    # written for prose descriptions, but a mirrored rule's *title* is almost
    # always underscore-joined (`Win32_Ransomware_LockBit`) -- and `_` is a word
    # character, so `\bransom(ware)?\b` matches none of them. Without this the
    # table scores against descriptions only and misses most of the bulk
    # imports, which are exactly the rules with nothing but a title to go on.
    hay = f"{rule.get('title') or ''} {rule.get('description') or ''}".replace("_", " ")
    for pattern, tag_name in tag_config:
        if pattern.search(hay):
            tags.append(tag_name)
    return sorted(set(tags))
