"""Tests for configurable operator-managed input directories."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from domain_pipeline.prepare.config.loader import PipelineConfigLoader
from domain_pipeline.prepare.config.models import ManualInputsConfig
from domain_pipeline.prepare.manual_inputs import ManualInputLoader


def test_manual_input_category_directories_are_configurable(tmp_path: Path) -> None:
    """Load operator inputs from directory locations declared in config."""
    config_path = Path("config/block.yaml")
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    payload["manual_inputs"] = {
        "manually_selected_for_filtered": "ops/selected",
        "manually_excluded_from_sources": "ops/excluded",
        "manually_added": "ops/added",
    }
    config = PipelineConfigLoader().load_payload(
        payload,
        config_namespace="direct",
        config_path=config_path,
        validate_runtime_credentials=False,
    )
    directories = config["manual_inputs"]
    expected_hosts = {
        "manually_selected_for_filtered": "selected.example.com",
        "manually_excluded_from_sources": "excluded.example.net",
        "manually_added": "added.example.org",
    }
    for category, host in expected_hosts.items():
        path = tmp_path / directories[category] / "direct.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{host}\n", encoding="utf-8")

    loaded = ManualInputLoader(source_root=tmp_path).load("direct", directories)

    assert set(loaded.manually_selected_for_filtered_entries) == {
        "selected.example.com"
    }
    assert set(loaded.manually_excluded_from_sources_entries) == {
        "excluded.example.net"
    }
    assert set(loaded.manually_added_entries) == {"added.example.org"}


@pytest.mark.parametrize(
    "directory",
    ["", ".", "../outside", "/absolute/path", "manual_inputs/../outside"],
)
def test_manual_input_category_directories_must_stay_inside_repo(
    directory: str,
) -> None:
    """Reject manual-input paths that escape or do not name a directory."""
    with pytest.raises(ValueError, match="relative directory"):
        ManualInputsConfig(manually_added=directory)


def test_manual_input_category_directories_must_be_unique() -> None:
    """Prevent two manual-input categories from sharing the same directory."""
    with pytest.raises(ValueError, match="directories must be unique"):
        ManualInputsConfig(
            manually_selected_for_filtered="ops/shared",
            manually_excluded_from_sources="ops/shared",
            manually_added="ops/added",
        )
