"""Exercise diagnostic export through the pipeline-run CLI and workflow."""

import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.handoffs import HandoffRequest, stage_handoff, stage_worker_inputs
from domain_pipeline.prepare.models import PreparedInputSet
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import DomainListParser


PROJECT = Path(__file__).resolve().parents[1]
BATCH = "batch-123-attempt-1"
WORKER = "worker-01"


def _run(archive: Path, destination: Path, role: str, kind: str, *,
         identity: tuple[str, str | None] = (BATCH, None)) -> subprocess.CompletedProcess[str]:
    batch, worker = identity
    args = [
        sys.executable, str(PROJECT / "src/pipeline_run.py"), "handoff-export-diagnostic",
        "--archive", str(archive), "--destination", str(destination), "--handoff", role,
        "--batch-id", batch, "--kind", kind,
    ]
    if worker is not None:
        args.extend(["--worker-id", worker])
    return subprocess.run(args, cwd=PROJECT, capture_output=True, text=True, check=False)


def _put(archive: Path, relative: Path, data: str) -> None:
    path = archive / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


@pytest.mark.parametrize("kind", ["settings", "batch"])
def test_prepare_yaml_exports_formatted_json(tmp_path: Path, kind: str) -> None:
    """The CLI resolves the member and preserves values in the final JSON format."""
    archive = tmp_path / "archive"
    destination = tmp_path / "debug" / f"{kind}.json"
    member = PathLayout(archive).prepare_to_aggregator.diagnostic_member(batch_id=BATCH, kind=kind)
    payload = {"z": ["one", 3, None], "a": {"enabled": True, "name": "测试"}}
    _put(archive, member.archive_path, yaml.safe_dump(payload, allow_unicode=True))

    result = _run(archive, destination, "prepare-aggregate", kind)

    assert result.returncode == 0, result.stderr
    assert json.loads(destination.read_text(encoding="utf-8")) == payload
    assert destination.read_text(encoding="utf-8") == json.dumps(
        payload, indent=2, sort_keys=True
    ) + "\n"


@pytest.mark.parametrize(
    ("role", "kind", "worker"),
    [("prepare-aggregate", "validation-log", None),
     ("prepare-aggregate", "batch-log", None),
     ("worker-aggregate", "worker-log", WORKER),
     ("worker-aggregate", "cache-log", WORKER)],
)
def test_log_exports_use_declared_archive_paths(
    tmp_path: Path, role: str, kind: str, worker: str | None
) -> None:
    """Logs are copied byte-for-byte from the selected declared member."""
    archive = tmp_path / "archive"
    destination = tmp_path / "debug" / "result.log"
    layout = PathLayout(archive)
    if worker is None:
        member = layout.prepare_to_aggregator.diagnostic_member(batch_id=BATCH, kind=kind)
    else:
        member = layout.worker_to_aggregator.diagnostic_member(
            batch_id=BATCH, worker_id=worker, kind=kind
        )
    content = "first line\nsecond line: 测试\n"
    _put(archive, member.archive_path, content)

    result = _run(archive, destination, role, kind, identity=(BATCH, worker))

    assert result.returncode == 0, result.stderr
    assert destination.read_bytes() == content.encode("utf-8")


def test_missing_diagnostic_is_optional(tmp_path: Path) -> None:
    """A missing optional member succeeds without creating an output."""
    destination = tmp_path / "missing.json"
    result = _run(tmp_path / "empty", destination, "prepare-aggregate", "settings")
    assert result.returncode == 0, result.stderr
    assert not destination.exists()
    assert "optional file missing" in result.stdout


@pytest.mark.parametrize(
    ("role", "kind", "batch", "worker"),
    [("prepare-aggregate", "worker-log", BATCH, None),
     ("worker-aggregate", "settings", BATCH, WORKER),
     ("worker-aggregate", "worker-log", BATCH, None),
     ("worker-aggregate", "worker-log", BATCH, "../escape"),
     ("prepare-aggregate", "settings", "../escape", None)],
)
def test_invalid_role_kind_or_identity_is_rejected(
    tmp_path: Path, role: str, kind: str, batch: str, worker: str | None
) -> None:
    """Invalid selectors fail rather than exporting a different archive member."""
    destination = tmp_path / "result"
    result = _run(tmp_path / "archive", destination, role, kind, identity=(batch, worker))
    assert result.returncode != 0
    assert not destination.exists()


def test_workflow_passes_archive_roots_and_diagnostic_selectors() -> None:
    """The final debug producer delegates handoff path selection to the CLI."""
    workflow = (PROJECT / ".github/workflows/_pipeline-run-batch.yml").read_text(encoding="utf-8")
    block = workflow.split("      - name: Stage aggregate log artifact", 1)[1].split(
        "      - name: Inspect aggregate cache bundle", 1
    )[0]
    assert ('--handoff prepare-aggregate --batch-id "${{ needs.prepare_run.outputs.batch_id }}"'
            in block)
    assert '--archive .tmp/downloads/prepared --kind "$diagnostic"' in block
    assert ('--handoff worker-aggregate --batch-id "${{ needs.prepare_run.outputs.batch_id }}"'
            in block)
    assert '--worker-id "$worker_id" --archive "$worker_dir" --kind worker-log' in block
    assert '--worker-id "$worker_id" --archive "$worker_dir" --kind cache-log' in block
    assert ".tmp/downloads/prepared/.debug_artifacts/" not in block
    assert '${worker_dir}/.debug_artifacts/' not in block


@pytest.mark.parametrize("kind", ["worker-log", "cache-log"])
def test_worker_log_producer_path_cli(tmp_path: Path, kind: str) -> None:
    """The worker producer uses the source of the declared handoff member."""
    command = [
        sys.executable, str(PROJECT / "src/pipeline_run.py"), "handoff-worker-diagnostic-path",
        "--state-root", str(tmp_path), "--batch-id", BATCH, "--worker-id", WORKER,
        "--kind", kind,
    ]
    result = subprocess.run(command, cwd=PROJECT, capture_output=True, text=True, check=False)
    member = PathLayout(tmp_path).worker_to_aggregator.diagnostic_member(
        batch_id=BATCH, worker_id=WORKER, kind=kind
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(member.source)


def test_workflow_requests_worker_log_producer_paths() -> None:
    """All worker log producers request their paths from the class-backed CLI."""
    workflow = (PROJECT / ".github/workflows/_pipeline-run-batch.yml").read_text(encoding="utf-8")
    worker_job = workflow.split("  run_workers:", 1)[1].split("  aggregate_and_publish:", 1)[0]
    assert worker_job.count("handoff-worker-diagnostic-path") == 3
    assert worker_job.count("--kind cache-log)") == 2
    assert worker_job.count("--kind worker-log)") == 1
    assert '.debug_artifacts/workers/' not in worker_job


def test_failed_prepare_stages_completed_source_trio(tmp_path: Path) -> None:
    """A verified partial source set is staged at its class-declared file paths."""
    root, archive = tmp_path / "state", tmp_path / "staged"
    paths = PathLayout(root).workflow_state
    source_job = SourceJob(
        source_id="source",
        input_label="fixture",
        output_stem="source",
        lines=["example.org\n"],
        config={"input": {"format": "plain"}},
    )
    parser = DomainListParser()
    parsed_source_file = parser.parse_source_file(
        source_job.lines,
        source_name=source_job.input_label,
        forced_format="plain",
    )
    prepared_inputs = PreparedInputSet(
        config={},
        source_jobs_by_id={source_job.source_id: source_job},
        parsed_source_entry_count=1,
        entries_by_source={},
        manual_routing_by_host={},
        root_plans={},
        preparation_terminal_rows=[],
        parsed_source_files={source_job.source_id: parsed_source_file},
    )
    SourceItemHandoff.build(
        batch_id=BATCH,
        prepared_inputs=prepared_inputs,
    ).write(
        items_path=paths.batch_source_items_path(batch_id=BATCH),
        index_path=paths.batch_source_item_index_path(batch_id=BATCH),
        diagnostics_path=paths.batch_source_item_diagnostics_path(batch_id=BATCH),
    )
    staged = stage_handoff(
        state_root=root, destination=archive,
        request=HandoffRequest(handoff="prepare-aggregate", batch_id=BATCH),
    )
    for path in (
        paths.batch_source_items_path(batch_id=BATCH),
        paths.batch_source_item_index_path(batch_id=BATCH),
        paths.batch_source_item_diagnostics_path(batch_id=BATCH),
    ):
        relative = path.relative_to(root)
        assert (archive / relative).read_bytes() == path.read_bytes()
        assert str(relative) in staged


def test_failure_stage_skips_directory_replacing_optional_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An invalid optional file cannot introduce undeclared descendants."""
    root, archive = tmp_path / "state", tmp_path / "staged"
    root.mkdir()
    replacement = root / "settings.json"
    replacement.mkdir()
    (replacement / "extra.json").write_text("{}", encoding="utf-8")
    (root / "prepare-batch.log").write_text("failure details\n", encoding="utf-8")
    staged = stage_handoff(state_root=root, destination=archive,
        request=HandoffRequest(handoff="prepare-aggregate", batch_id=BATCH))
    assert not any(path.name == "extra.json" for path in archive.rglob("*"))
    log = PathLayout(root).prepare_to_aggregator.diagnostic_member(batch_id=BATCH, kind="batch-log")
    assert (archive / log.archive_path).read_text(encoding="utf-8") == "failure details\n"
    assert str(log.archive_path) in staged
    assert "invalid" in capsys.readouterr().err.lower()


def test_required_stage_rejects_directory_replacing_runtime_file(tmp_path: Path) -> None:
    """A directory cannot satisfy a required handoff file."""
    root, archive = tmp_path / "state", tmp_path / "staged"
    for member in PathLayout(root).prepare_to_aggregator.members(batch_id=BATCH):
        if member.required:
            member.source.parent.mkdir(parents=True, exist_ok=True)
            if member.source.name == "worker-ids.csv":
                member.source.mkdir()
                (member.source / "extra.json").write_text("{}", encoding="utf-8")
            else:
                member.source.write_text("fixture\n", encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        stage_handoff(state_root=root, destination=archive,
            request=HandoffRequest(
                handoff="prepare-aggregate", batch_id=BATCH, require_runtime=True
            ))
    assert not any(path.name == "extra.json" for path in archive.rglob("*"))


@pytest.mark.parametrize("symlink_parent", [False, True])
def test_worker_input_rejects_symlink_escape(tmp_path: Path, symlink_parent: bool) -> None:
    """Neither a file nor an ancestor may point outside the staging source root."""
    root, archive = tmp_path / "state", tmp_path / "staged"
    members = PathLayout(root).prepare_to_worker.members(batch_id=BATCH, worker_id=WORKER)
    external = tmp_path / "external"
    external.mkdir()
    if symlink_parent:
        members[0].source.parent.parent.mkdir(parents=True)
        members[0].source.parent.symlink_to(external, target_is_directory=True)
        for member in members:
            (external / member.source.name).write_text("fixture\n", encoding="utf-8")
    else:
        for member in members:
            member.source.parent.mkdir(parents=True, exist_ok=True)
            member.source.write_text("fixture\n", encoding="utf-8")
        target = external / "target"
        target.write_text("fixture\n", encoding="utf-8")
        members[0].source.unlink()
        members[0].source.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        stage_worker_inputs(state_root=root, batch_id=BATCH,
                            worker_ids_json=json.dumps([WORKER]), destination=archive)
    assert not archive.exists()


def test_failed_prepare_omits_incomplete_source_trio(tmp_path: Path) -> None:
    root, archive = tmp_path / "state", tmp_path / "staged"
    layout = PathLayout(root)
    paths = layout.workflow_state
    items = paths.batch_source_items_path(batch_id=BATCH)
    index = paths.batch_source_item_index_path(batch_id=BATCH)
    items.parent.mkdir(parents=True)
    items.write_text("", encoding="utf-8")
    index.write_text("{}", encoding="utf-8")
    (root / "prepare-batch.log").write_text("prepare stopped\n", encoding="utf-8")

    staged = stage_handoff(
        state_root=root, destination=archive,
        request=HandoffRequest("prepare-aggregate", BATCH),
    )

    log = layout.prepare_to_aggregator.diagnostic_member(batch_id=BATCH, kind="batch-log")
    assert staged == [str(log.archive_path)]
    assert (archive / log.archive_path).read_text(encoding="utf-8") == "prepare stopped\n"


def test_prepare_retry_invalidates_previous_source_completion(tmp_path: Path) -> None:
    from argparse import Namespace

    from domain_pipeline.pipeline_run.commands import _handle_prepare_batch

    diagnostics = PathLayout(tmp_path).workflow_state.batch_source_item_diagnostics_path(
        batch_id=BATCH
    )
    diagnostics.parent.mkdir(parents=True)
    diagnostics.write_text("", encoding="utf-8")

    args = Namespace(worker_count=1, run_id="123", run_attempt="1", config="missing.yaml")
    with pytest.raises((ValueError, FileNotFoundError)):
        _handle_prepare_batch(args, tmp_path, tmp_path)
    assert not diagnostics.exists()
