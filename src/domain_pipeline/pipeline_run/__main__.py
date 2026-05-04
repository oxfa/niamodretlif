"""Executable entrypoint for one configured pipeline run."""

from __future__ import annotations

from domain_pipeline.pipeline_run.commands import main

if __name__ == "__main__":
    raise SystemExit(main())
