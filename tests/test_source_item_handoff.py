"""Verify source occurrence provenance and the Prepare-to-Aggregate corpus."""

import json
from pathlib import Path

import pytest

from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.handoffs import HandoffRequest, stage_handoff
from domain_pipeline.prepare import source_items
from domain_pipeline.prepare.models import PreparedInputSet
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import (
    DomainListParser,
    InputFileFormat,
    ParsedSourceItem,
)

_BY_INPUT_DOMAIN = "valid_source_items_by_input_domain"


def _build(
    sources: list[tuple[str, str, str]], *, excluded: set[str] | None = None
) -> SourceItemHandoff:
    parser = DomainListParser()
    jobs = {
        source_id: SourceJob(
            source_id=source_id,
            input_label=source_id,
            output_stem=source_id,
            lines=content.splitlines(keepends=True),
            config={},
        )
        for source_id, content, _ in sources
    }
    return SourceItemHandoff.build(
        batch_id="batch",
        prepared_inputs=PreparedInputSet(
            config={},
            source_jobs_by_id=jobs,
            parsed_source_entry_count=0,
            entries_by_source={},
            manual_routing_by_host={},
            root_plans={},
            preparation_terminal_rows=[],
            excluded_source_hosts=excluded or set(),
            parsed_source_files={
                source_id: parser.parse_source_file(
                    jobs[source_id].lines,
                    source_name=source_id,
                    forced_format=file_format,
                )
                for source_id, _, file_format in sources
            },
        ),
    )


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "items_path": tmp_path / "source-items.jsonl",
        "index_path": tmp_path / "source-item-index.json",
        "diagnostics_path": tmp_path / "source-item-diagnostics.jsonl",
    }


def test_input_index_and_loaded_corpus_use_physical_order(tmp_path: Path) -> None:
    aliases = "0.0.0.0 " + " ".join(["ads.example.com"] * 10 + ["cdn.example.com"])
    handoff = _build(
        [
            (
                "z-first",
                f"\n{aliases}\n" + "\n" * 7 + "0.0.0.0 ads.example.com\n",
                "hosts",
            ),
            ("a-second", "ads.example.com\n", "plain"),
        ]
    )
    index = handoff.index_payload[_BY_INPUT_DOMAIN]
    assert list(index) == ["ads.example.com", "cdn.example.com"]
    assert index["ads.example.com"] == [
        *[
            {"item_id": "z-first:2", "association_id": f"z-first:2:target:{ordinal}"}
            for ordinal in range(1, 11)
        ],
        {"item_id": "z-first:10", "association_id": "z-first:10:target:1"},
        {"item_id": "a-second:1", "association_id": "a-second:1:target:1"},
    ]
    assert index["cdn.example.com"] == [
        {"item_id": "z-first:2", "association_id": "z-first:2:target:11"}
    ]

    paths = _paths(tmp_path)
    handoff.write(**paths)
    items_path = paths["items_path"]
    items_path.write_text(
        "".join(
            reversed(items_path.read_text(encoding="utf-8").splitlines(keepends=True))
        ),
        encoding="utf-8",
    )
    index["ads.example.com"].reverse()
    paths["index_path"].write_text(json.dumps(handoff.index_payload), encoding="utf-8")
    restored = SourceItemHandoff.load(
        batch_id="batch", validate_semantics=True, excluded_source_hosts=set(), **paths
    )
    assert [item["item_id"] for item in restored.item_records] == [
        "z-first:2",
        "z-first:10",
        "a-second:1",
    ]
    assert restored.index_payload == handoff.index_payload


def test_index_decoder_rejects_repeated_domain_key(tmp_path: Path) -> None:
    handoff = _build([("source", "ads.example.com\n", "plain")])
    paths = _paths(tmp_path)
    handoff.write(**paths)
    index_path = paths["index_path"]
    with_duplicate = json.dumps(handoff.index_payload)
    with_duplicate = with_duplicate.replace(
        f'"{_BY_INPUT_DOMAIN}": {{',
        f'"{_BY_INPUT_DOMAIN}": {{"ads.example.com": [], ',
        1,
    )
    index_path.write_text(with_duplicate, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        SourceItemHandoff.load(batch_id="batch", **paths)


@pytest.mark.parametrize("problem", ["missing", "extra", "duplicate", "miskeyed"])
def test_load_rejects_input_index_membership_mismatches(
    tmp_path: Path, problem: str
) -> None:
    handoff = _build(
        [("source", "ads.example.com\nads.example.com\ncdn.example.com\n", "plain")]
    )
    paths = _paths(tmp_path)
    handoff.write(**paths)
    index = handoff.index_payload[_BY_INPUT_DOMAIN]
    ads = index["ads.example.com"]
    cdn = index["cdn.example.com"]
    if problem == "missing":
        ads.pop()
    elif problem == "extra":
        index["unexpected.example.com"] = []
    elif problem == "duplicate":
        ads[-1] = ads[0]
    else:
        ads[-1], cdn[0] = cdn[0], ads[-1]
    paths["index_path"].write_text(json.dumps(handoff.index_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="source-item domain"):
        SourceItemHandoff.load(batch_id="batch", **paths)


@pytest.mark.parametrize("bad_ordinal", [False, 0.0])
def test_load_rejects_noninteger_source_ordinals(
    tmp_path: Path, bad_ordinal: object
) -> None:
    handoff = _build([("source", "ads.example.com\n", "plain")])
    paths = _paths(tmp_path)
    handoff.write(**paths)
    handoff.index_payload["sources"][0]["source_ordinal"] = bad_ordinal
    paths["index_path"].write_text(json.dumps(handoff.index_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid source metadata"):
        SourceItemHandoff.load(batch_id="batch", **paths)


def test_load_rejects_repeated_source_ids_without_occurrences(tmp_path: Path) -> None:
    handoff = _build([("first", "", "plain"), ("second", "", "plain")])
    paths = _paths(tmp_path)
    handoff.write(**paths)
    handoff.index_payload["sources"][1]["source_id"] = "first"
    paths["index_path"].write_text(json.dumps(handoff.index_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate source ID"):
        SourceItemHandoff.load(batch_id="batch", **paths)


@pytest.mark.parametrize("member", ["items_path", "diagnostics_path"])
@pytest.mark.parametrize("separator", ["\r", "\n", "\x85", "\u2028", "\u2029"])
def test_load_rejects_embedded_line_boundaries(
    tmp_path: Path, member: str, separator: str
) -> None:
    handoff = _build(
        [("source", "ads.example.com\ninvalid.example.invalid\n", "plain")]
    )
    paths = _paths(tmp_path)
    handoff.write(**paths)
    path = paths[member]
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
    ]
    records[0]["original_text"] += f"{separator}second.example.com"
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="one physical line"):
        SourceItemHandoff.load(batch_id="batch", **paths)


def test_corpus_preserves_line_text_and_counts_only_retained_occurrences() -> None:
    handoff = _build(
        [
            (
                "hosts",
                "##.ignored\u2028 0.0.0.0 keep.example.com bad.invalid # note  \r\n",
                "hosts",
            ),
            ("plain", "bad.invalid\nblocked.example.com\nco.uk\n", "plain"),
            (
                "adblock",
                "[Adblock Plus 2.0]\x85  ||AdS.Example.COM^ \n##.banner\n",
                "adblock",
            ),
        ],
        excluded={"blocked.example.com"},
    )
    assert handoff.retained_line_count == 6
    assert handoff.valid_source_hosts == {
        "keep.example.com",
        "blocked.example.com",
        "co.uk",
        "ads.example.com",
    }
    assert handoff.item_records[0]["source_line_number"] == 2
    assert (
        handoff.item_records[0]["original_text"]
        == " 0.0.0.0 keep.example.com bad.invalid # note  "
    )
    assert [record["original_text"] for record in handoff.diagnostic_records] == [
        " 0.0.0.0 keep.example.com bad.invalid # note  ",
        "bad.invalid",
    ]


def test_semantic_load_retains_each_reparsed_item_for_conversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _build(
        [("adblock", "  ||AdS.Example.COM^ \n||ads.example.com/a\n", "adblock")]
    )
    paths = _paths(tmp_path)
    handoff.write(**paths)
    parse_source_item = DomainListParser.parse_source_item
    calls: list[str] = []

    def observe(
        parser: DomainListParser, text: str, *, file_format: InputFileFormat
    ) -> ParsedSourceItem | None:
        calls.append(text)
        return parse_source_item(parser, text, file_format=file_format)

    monkeypatch.setattr(DomainListParser, "parse_source_item", observe)
    loaded = SourceItemHandoff.load(
        batch_id="batch", validate_semantics=True, excluded_source_hosts=set(), **paths
    )
    assert calls == ["  ||AdS.Example.COM^ ", "||ads.example.com/a"]
    assert [
        item.is_simple_positive_adblock_rule
        for item in loaded.parsed_items_by_id.values()
    ] == [True, False]


@pytest.mark.parametrize(
    ("changed_fact", "diagnostic"),
    [
        ("order", "target associations do not match"),
        ("root", "target associations do not match"),
        ("exclusion", "exclusion decision does not match"),
        ("target-diagnostic", "target errors do not match target diagnostics"),
    ],
)
def test_semantic_load_rejects_inconsistent_carried_facts(
    tmp_path: Path, changed_fact: str, diagnostic: str
) -> None:
    handoff = _build(
        [
            (
                "source",
                "0.0.0.0 ads.example.com blocked.example.com bad.invalid\n",
                "hosts",
            )
        ],
        excluded={"blocked.example.com"},
    )
    paths = _paths(tmp_path)
    handoff.write(**paths)
    items_path = paths["items_path"]
    item = json.loads(items_path.read_text(encoding="utf-8"))
    associations = item["target_associations"]
    excluded = {"blocked.example.com"}
    if changed_fact == "order":
        associations.reverse()
    elif changed_fact == "root":
        associations[0]["registrable_domain"] = "different.example.net"
    elif changed_fact == "exclusion":
        excluded = set()
    else:
        paths["diagnostics_path"].write_text("", encoding="utf-8")
    items_path.write_text(json.dumps(item) + "\n", encoding="utf-8")
    SourceItemHandoff.load(batch_id="batch", **paths)
    with pytest.raises(ValueError, match=diagnostic):
        SourceItemHandoff.load(
            batch_id="batch",
            validate_semantics=True,
            excluded_source_hosts=excluded,
            **paths,
        )


def test_interrupted_diagnostic_write_leaves_no_completed_trio_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    handoff = _build([("source", "ads.example.com\na.invalid\nb.invalid\n", "plain")])
    state_root = tmp_path / "prepare"
    layout = PathLayout(state_root)
    batch_root = layout.workflow_state.batch_root(batch_id=handoff.batch_id)
    paths = _paths(batch_root)
    handoff.write(**paths)
    write_jsonl = source_items._write_jsonl

    def interrupt_diagnostics(path: Path, records: tuple[dict, ...]) -> None:
        assert not paths["diagnostics_path"].exists()
        if records == handoff.diagnostic_records:
            write_jsonl(path, records[:1])
            raise OSError("interrupted after a complete diagnostic row")
        write_jsonl(path, records)

    monkeypatch.setattr(source_items, "_write_jsonl", interrupt_diagnostics)
    with pytest.raises(OSError, match="interrupted"):
        handoff.write(**paths)
    assert not paths["diagnostics_path"].exists()
    assert set(batch_root.iterdir()) == {paths["items_path"], paths["index_path"]}
    with pytest.raises(ValueError, match="unable to read source-item handoff"):
        SourceItemHandoff.load(batch_id="batch", **paths)

    log = layout.prepare_to_aggregator.diagnostic_member(
        batch_id=handoff.batch_id, kind="batch-log"
    )
    log.source.write_bytes(b"interrupted after a complete diagnostic row\n")
    archive = tmp_path / "failed-prepare"
    assert stage_handoff(
        state_root=state_root,
        destination=archive,
        request=HandoffRequest("prepare-aggregate", handoff.batch_id),
    ) == [str(log.archive_path)]
    assert (archive / log.archive_path).read_bytes() == log.source.read_bytes()
