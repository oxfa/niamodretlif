"""Prepare source grammar and whole-file format selection."""

from pathlib import Path

import pytest

from domain_pipeline.prepare.manual_inputs import ManualInputLoader
from domain_pipeline.prepare.sources.parser import (
    AdblockFormatHandler,
    DomainEntry,
    DomainListParser,
    DomainSyntax,
    InputFileFormat,
    SourceItemSyntax,
)


def test_plain_and_surge_domain_set_use_literal_host_and_scope() -> None:
    parser = DomainListParser()
    plain = parser.parse_source_file(["  BÜCHER.Example.COM.  \v", "blogspot.com\r\n"])
    domain_set = parser.parse_source_file([".BÜCHER.Example.COM.\n", "blogspot.com\n"])

    assert plain.file_format is InputFileFormat.PLAIN
    assert [line.raw_line for line in plain.lines] == [
        "  BÜCHER.Example.COM.  ",
        "blogspot.com",
    ]
    assert list(parser.entries_from_parsed_source_file(plain)) == [
        DomainEntry("xn--bcher-kva.example.com", "example.com"),
        DomainEntry("blogspot.com", None),
    ]
    assert domain_set.file_format is InputFileFormat.SURGE_DOMAIN_SET
    assert [
        (target.host, target.role)
        for line in domain_set.lines
        if line.parsed_item is not None
        for target in line.parsed_item.targets
    ] == [
        ("xn--bcher-kva.example.com", "domain_suffix"),
        ("blogspot.com", "exact_host"),
    ]


def test_hosts_ignores_inline_and_cosmetic_looking_comments_and_checks_aliases() -> None:
    parser = DomainListParser()
    parsed = parser.parse_source_file([
        "  ::1 Alias.Blogspot.com. nope.invalid example.net\t# ## trailing comment\r\n",
        " ##.banner\r\n",
    ])

    assert parsed.file_format is InputFileFormat.HOSTS
    line, comment = parsed.lines
    assert line.raw_line == (
        "  ::1 Alias.Blogspot.com. nope.invalid example.net\t# ## trailing comment"
    )
    assert comment.line_number == 2
    assert comment.is_ignored
    assert comment.parsed_item is None
    assert line.parsed_item is not None
    assert [
        (target.host, target.registrable_domain, target.error_reason)
        for target in line.parsed_item.targets
    ] == [
        ("alias.blogspot.com", "alias.blogspot.com", None),
        ("nope.invalid", None, "no_strict_public_suffix_match"),
        ("example.net", "example.net", None),
    ]
    assert list(parser.entries_from_parsed_source_file(parsed)) == [
        DomainEntry("alias.blogspot.com", "alias.blogspot.com"),
        DomainEntry("example.net", "example.net"),
    ]


def test_hosts_rejects_malformed_alias_list_before_projecting() -> None:
    parser = DomainListParser()
    item = parser.parse_source_item(
        "0.0.0.0 example.com bad_name # comment", file_format=InputFileFormat.HOSTS
    )
    assert item is not None and item.error_reason is not None
    assert not item.targets


@pytest.mark.parametrize("upstream", ["1.1.1.1#5353", "#", "opaque@upstream"])
def test_dnsmasq_extracts_ordered_selectors_and_keeps_the_upstream(upstream: str) -> None:
    parser = DomainListParser()
    original = (
        "server=/One.Example.com/.Two.Example.net/*.Three.Example.org/"
        f"miss.invalid/{upstream}"
    )
    parsed = parser.parse_source_file([original])

    assert parsed.file_format is InputFileFormat.DNSMASQ
    line = parsed.lines[0]
    assert line.raw_line == original
    assert line.parsed_item is not None
    assert [
        (target.host, target.role, target.error_reason)
        for target in line.parsed_item.targets
    ] == [
        ("one.example.com", "dnsmasq_selector", None),
        ("two.example.net", "dnsmasq_dot_selector", None),
        ("three.example.org", "dnsmasq_wildcard_selector", None),
        ("miss.invalid", "dnsmasq_selector", "no_strict_public_suffix_match"),
    ]


def test_compact_surge_directives_and_ruleset_comments() -> None:
    parsed = DomainListParser().parse_source_file([
        "DOMAIN,Exact.Example.com\n",
        "// vendor comment\n",
        "; another vendor comment\n",
        "DOMAIN-SUFFIX,Suffix.Example.net\n",
    ])
    assert parsed.file_format is InputFileFormat.SURGE_RULESET
    assert [line.is_ignored for line in parsed.lines] == [False, True, True, False]
    assert [
        (target.host, target.role)
        for line in parsed.lines
        if line.parsed_item is not None
        for target in line.parsed_item.targets
    ] == [
        ("exact.example.com", "exact_host"),
        ("suffix.example.net", "domain_suffix"),
    ]


@pytest.mark.parametrize(
    ("line", "file_format"),
    [
        ("server=/example.com/", InputFileFormat.DNSMASQ),
        ("server=/example.com//1.1.1.1", InputFileFormat.DNSMASQ),
        ("server=/example.com/*example.net/1.1.1.1", InputFileFormat.DNSMASQ),
        ("server=/example.com/not*valid.net/1.1.1.1", InputFileFormat.DNSMASQ),
        ("server=/example.com/1.1.1.1 extra", InputFileFormat.DNSMASQ),
        ("server=1.1.1.1", InputFileFormat.DNSMASQ),
        ("address=/example.com/0.0.0.0", InputFileFormat.DNSMASQ),
        ("DOMAIN,", InputFileFormat.SURGE_RULESET),
        ("DOMAIN,example.com,DIRECT", InputFileFormat.SURGE_RULESET),
        ("IP-CIDR,192.0.2.0/24", InputFileFormat.SURGE_RULESET),
    ],
)
def test_auto_rejects_recognized_malformed_or_unsupported_directives(
    line: str, file_format: InputFileFormat
) -> None:
    parser = DomainListParser()
    assert parser.detect_file_format([line]) is InputFileFormat.UNKNOWN
    item = parser.parse_source_item(line, file_format=file_format)
    assert item is not None and item.error_reason is not None
    assert not item.targets


def test_scoped_cosmetic_filter_conflicts_with_hosts() -> None:
    raw = ["0.0.0.0 example.com\n", "! note\n", "example.com##.sponsored\r"]
    parser = DomainListParser()
    mixed = parser.parse_source_file(raw)
    assert mixed.file_format is InputFileFormat.MIXED
    assert [line.is_ignored for line in mixed.lines] == [False, True, False]
    assert [line.parsed_item for line in mixed.lines] == [None, None, None]

    forced = parser.parse_source_file(raw, forced_format="hosts")
    assert forced.file_format is InputFileFormat.HOSTS
    assert forced.lines[2].parsed_item is not None
    assert forced.lines[2].parsed_item.error_reason == "line_not_valid_for_source_format"


@pytest.mark.parametrize(
    ("adblock_line", "kind"),
    [
        ("[Adblock Plus 2.0]", "metadata"),
        ("||Req.Example.com^", "network_filter"),
        ("/ads?.js/", "regex_filter"),
        ("example.com##.ad", "cosmetic_filter"),
    ],
)
def test_adblock_evidence_makes_bare_names_targetless(
    adblock_line: str, kind: str
) -> None:
    parsed = DomainListParser().parse_source_file([adblock_line, "bare.example.net"])
    assert parsed.file_format is InputFileFormat.ADBLOCK
    specific, bare = [line.parsed_item for line in parsed.lines]
    assert specific is not None and specific.item_kind == kind
    assert bare is not None and bare.error_reason is None
    assert bare.targets == ()
    assert bare.no_target_reason == "network_filter_is_not_host_anchored"


def test_domain_set_requires_the_rest_of_the_file_to_fit() -> None:
    parsed = DomainListParser().parse_source_file(
        [".resource.example.com", "||req.example.net^"]
    )
    assert parsed.file_format is InputFileFormat.ADBLOCK
    unanchored = parsed.lines[0].parsed_item
    assert unanchored is not None and not unanchored.targets
    assert unanchored.no_target_reason == "network_filter_is_not_host_anchored"


def test_adblock_cosmetic_only_file_has_no_request_hosts() -> None:
    parsed = DomainListParser().parse_source_file(["##.sponsored", "#@#.sponsored"])
    assert parsed.file_format is InputFileFormat.ADBLOCK
    assert [
        item.item_kind for line in parsed.lines if (item := line.parsed_item) is not None
    ] == ["cosmetic_filter", "cosmetic_exception_filter"]
    assert list(DomainListParser().entries_from_parsed_source_file(parsed)) == []


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        (r"/foo##bar/", "regex_filter"),
        (r"@@/foo#@#bar/$third-party", "exception_regex_filter"),
        (r"/foo#?#bar/", "regex_filter"),
    ],
)
def test_adblock_regex_takes_precedence_over_cosmetic_operators(
    line: str, kind: str
) -> None:
    parsed = DomainListParser().parse_source_file([line], forced_format="adblock")
    item = parsed.lines[0].parsed_item
    assert item is not None and item.item_kind == kind
    assert item.no_target_reason == "regular_expression_has_no_literal_request_host"
    assert item.error_reason is None
    assert not item.targets


@pytest.mark.parametrize(
    ("line", "simple", "kind"),
    [
        (" \t||Ads.Example.com.^ ", True, "network_filter"),
        ("||Ads.Example.com", False, "network_filter"),
        ("||Ads.Example.com/path", False, "network_filter"),
        ("||Ads.Example.com^$third-party", False, "network_filter"),
        ("@@||Ads.Example.com^", False, "exception_network_filter"),
    ],
)
def test_adblock_verifies_simple_positive_form_using_the_literal_host(
    line: str, simple: bool, kind: str
) -> None:
    item = DomainListParser().parse_source_item(line, file_format=InputFileFormat.ADBLOCK)
    assert item is not None and item.item_kind == kind
    assert item.is_simple_positive_adblock_rule is simple
    assert [target.host for target in item.targets] == ["ads.example.com"]


def test_auto_detection_reuses_adblock_syntax(monkeypatch: pytest.MonkeyPatch) -> None:
    parse_syntax = AdblockFormatHandler.parse_syntax
    calls: list[str] = []

    def observe(
        self: AdblockFormatHandler, line: str, syntax: DomainSyntax
    ) -> SourceItemSyntax | None:
        calls.append(line.strip())
        return parse_syntax(self, line, syntax)

    monkeypatch.setattr(AdblockFormatHandler, "parse_syntax", observe)
    parser = DomainListParser()
    lines = ["||Req.Example.com^", "/foo##bar/", "bare.example.net"]
    parsed = parser.parse_source_file(lines)

    assert parsed.file_format is InputFileFormat.ADBLOCK
    assert sorted(calls) == sorted(lines)
    assert list(parser.entries_from_parsed_source_file(parsed)) == [
        DomainEntry("req.example.com", "example.com")
    ]


def test_manual_loader_uses_the_same_automatic_format_and_conflict_checks(
    tmp_path: Path,
) -> None:
    directories = {
        "manually_added": "added",
        "manually_excluded_from_sources": "excluded",
        "manually_selected_for_filtered": "selected",
    }
    for directory in directories.values():
        (tmp_path / directory).mkdir()
    (tmp_path / "added" / "fixture.txt").write_text(
        "[Adblock Plus 2.0]\n||Ads.Example.com^\nbare.example.net\n", encoding="utf-8"
    )
    (tmp_path / "excluded" / "fixture.txt").write_text(
        "server=/X.Example.org/.Y.Example.org/#\n", encoding="utf-8"
    )
    selected_path = tmp_path / "selected" / "fixture.txt"
    selected_path.write_text("DOMAIN-SUFFIX,Chosen.Example.net\n", encoding="utf-8")
    loader = ManualInputLoader(source_root=tmp_path)
    manual = loader.load("fixture", directories)
    assert list(manual.manually_added_entries) == ["ads.example.com"]
    assert list(manual.manually_excluded_from_sources_entries) == [
        "x.example.org",
        "y.example.org",
    ]
    assert list(manual.manually_selected_for_filtered_entries) == ["chosen.example.net"]

    selected_path.write_text("DOMAIN,ads.example.com\n", encoding="utf-8")
    with pytest.raises(ValueError, match="conflicts with manually selected file"):
        loader.load("fixture", directories)


def test_plain_comments_with_embedded_cosmetic_markers_remain_comments() -> None:
    parser = DomainListParser()
    lines = ["ads.example.com", "# Notes about ## and #@# cosmetic markers"]
    plain = parser.parse_source_file(lines)
    assert plain.file_format is InputFileFormat.PLAIN
    assert plain.lines[1].is_ignored
    assert list(parser.entries_from_parsed_source_file(plain)) == [
        DomainEntry("ads.example.com", "example.com")
    ]

    adblock = parser.parse_source_file([*lines, "##.banner"])
    assert adblock.file_format is InputFileFormat.ADBLOCK
    assert adblock.lines[1].is_ignored
    assert adblock.lines[2].parsed_item is not None
    assert adblock.lines[2].parsed_item.item_kind == "cosmetic_filter"
