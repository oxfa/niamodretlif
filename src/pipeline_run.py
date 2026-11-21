#!/usr/bin/env -S uv run --no-config --no-env-file --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "requests>=2.31",
#   "tenacity>=9.0",
#   "dnspython>=2.4",
#   "publicsuffix2>=2.20191221",
#   "PyYAML>=6.0",
#   "pydantic>=2.8,<3",
# ]
# ///
"""Executable entry point for the domain pipeline CLI."""

from __future__ import annotations

from domain_pipeline.pipeline_run.commands import main

if __name__ == "__main__":
    raise SystemExit(main())
