"""Tag production: the half that runs with no network and no yara."""

import re

from rulezet_validation.source import platform_tags, vulns

CFGS = [
    (re.compile(r"\bupx\b", re.I), 'runtime-packer:pe="upx"'),
    (
        re.compile(r"\bransom(ware)?\b", re.I),
        'ms-caro-malware-full:malware-type="Ransom"',
    ),
]


def test_vulns_accepts_every_shape_the_column_arrives_in():
    assert vulns({"cve_id": '["CVE-2021-44228", "GHSA-j8v8-6h6r-m6pq"]'}) == [
        "CVE-2021-44228",
        "GHSA-J8V8-6H6R-M6PQ",
    ]
    assert vulns({"cve_id": "CVE-2025-53521"}) == ["CVE-2025-53521"]
    assert vulns({"cve_id": None}) == []
    assert vulns({}) == []


def test_en_dash_is_normalised():
    # Some imports carry a typographic dash, which would otherwise produce a
    # tag no consumer can match on.
    assert vulns({"cve_id": "CVE–2021–44228"}) == ["CVE-2021-44228"]


def test_platform_tags_from_description_and_title():
    tags = platform_tags(
        {
            "title": "Win32_Ransomware_LockBit",
            "description": "packed with UPX",
            "cve_id": "CVE-2021-44228",
        },
        CFGS,
    )
    assert 'runtime-packer:pe="upx"' in tags
    assert "cve:CVE-2021-44228" in tags
    # From the title alone, which only works because `_` is normalised away.
    # This is the assert that fails if that ever gets "simplified" out.
    assert 'ms-caro-malware-full:malware-type="Ransom"' in tags


def test_tags_stay_in_rulezet_vocabulary():
    """No routing, no prefixing, no local taxonomy. Whatever Rulezet would say."""
    tags = platform_tags({"title": "ransomware", "description": ""}, CFGS)
    assert tags == ['ms-caro-malware-full:malware-type="Ransom"']


def test_a_rule_matching_nothing_gets_no_tags():
    assert platform_tags({"title": "x", "description": "y"}, CFGS) == []
