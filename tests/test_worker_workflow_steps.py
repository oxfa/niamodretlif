"""Exercise the workflow's worker result handling with controlled CLI output."""

import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml


@pytest.mark.parametrize(
    ("step_id", "command", "payload", "exit_status", "status_output", "error_reason"),
    [
        pytest.param(
            "init", "initialize-worker-statuses", {"conclusion": "success"},
            0, "overall_conclusion=success", "", id="init-success",
        ),
        pytest.param(
            "init", "initialize-worker-statuses",
            {
                "conclusion": "failure",
                "failure_reason": "manifest missing\nfor worker",
                "status_recording_error": "disk full",
            },
            0, "overall_conclusion=failure",
            "manifest missing for worker; additionally, "
            "failure status could not be recorded: disk full",
            id="init-failure",
        ),
        pytest.param(
            "process", "worker", {"overall_conclusion": "success", "error_reason": None},
            0, "overall_conclusion=success", "", id="process-success",
        ),
        pytest.param(
            "process", "worker",
            {
                "overall_conclusion": "failure",
                "error_reason": "worker input failed\nvalidation",
                "status_recording_error": "disk full",
            },
            1, "overall_conclusion=failure",
            "worker input failed validation; "
            "failure status could not be recorded: disk full",
            id="process-failure",
        ),
        pytest.param(
            "process", "worker", {"overall_conclusion": "failure", "error_reason": None},
            1, "overall_conclusion=failure",
            "worker command failed (exit status 1): stub CLI diagnostic ",
            id="process-stderr-fallback",
        ),
        pytest.param(
            "finalize_handoff", "finalize-worker-aggregate-handoff",
            {"handoff_finalized": True},
            0, "handoff_finalized=true", "", id="finalize-handoff-success",
        ),
        pytest.param(
            "finalize_handoff", "finalize-worker-aggregate-handoff",
            {"handoff_finalized": False},
            1, "handoff_finalized=false",
            "worker handoff finalization failed (exit status 1): stub CLI diagnostic ",
            id="finalize-handoff-stderr-fallback",
        ),
    ],
)
def test_worker_step_exports_cli_result(
    tmp_path: Path,
    step_id: str,
    command: str,
    payload: dict[str, str | bool | None],
    exit_status: int,
    status_output: str,
    error_reason: str,
) -> None:
    """Write the lifecycle outputs and return the CLI's exit status."""
    workflow_path = (
        Path(__file__).resolve().parents[1] / ".github/workflows/_pipeline-run-batch.yml"
    )
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["run_workers"]["steps"]
    script = next(step["run"] for step in steps if step.get("id") == step_id)
    expressions = {
        "needs.prepare_run.outputs.batch_id": "batch-123-attempt-1",
        "matrix.worker_id": "worker-1",
        "inputs.worker_log_level": "debug",
        "needs.prepare_run.outputs.worker_runtime_budget_seconds": "60",
    }
    for expression, value in expressions.items():
        script = script.replace(f"${{{{ {expression} }}}}", value)

    stub = tmp_path / "src" / "pipeline_run.py"
    stub.parent.mkdir()
    stub.write_text(
        '#!/bin/bash\n'
        'test "$1" = "$PIPELINE_COMMAND" || exit 64\n'
        'printf "%s\\n" "$PIPELINE_RESULT"\n'
        'printf "%s\\n" "stub CLI diagnostic" >&2\n'
        'exit "$PIPELINE_EXIT_STATUS"\n',
        encoding="utf-8",
    )
    stub.chmod(0o700)
    output = tmp_path / "github-output"
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", script],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "GITHUB_OUTPUT": str(output),
            "PIPELINE_COMMAND": command,
            "PIPELINE_RESULT": json.dumps(payload),
            "PIPELINE_EXIT_STATUS": str(exit_status),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == exit_status, result.stderr
    assert output.read_text(encoding="utf-8").splitlines() == [
        status_output,
        f"error_reason={error_reason}",
    ]
