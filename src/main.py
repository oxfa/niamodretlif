#!/usr/bin/env python3
"""Command-line interface for the root-filter and host-DNS pipeline."""

from __future__ import annotations

import argparse
import glob
import logging
import sys
from pathlib import Path

from domain_pipeline.runtime.app import run_pipeline
from domain_pipeline.settings.config import config_namespace_from_path, load_config

__all__ = [
    "main",
]

log = logging.getLogger(__name__)
DEFAULT_CONFIG_PATTERN = str(
    Path(__file__).resolve().parent.parent / "config" / "*.yaml"
)


def _positive_runtime_seconds(value: str) -> float:
    """Return one strictly positive runtime-budget value for argparse."""
    seconds = float(value)
    if seconds <= 0:
        raise argparse.ArgumentTypeError(
            "--max-runtime-seconds must be greater than zero"
        )
    return seconds


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Classify domains from text lists")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATTERN,
        help="Path, directory, or glob pattern for YAML configuration files",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument(
        "--max-runtime-seconds",
        type=_positive_runtime_seconds,
        default=None,
        help=(
            "Soft runtime budget for one run; stop queueing new work when reached "
            "so the workflow can commit cache progress before the hard job limit"
        ),
    )
    return parser.parse_args(argv)


def _configure_logging(verbosity: int = 0) -> None:
    """Set up logging to stderr with timestamps."""
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
        force=True,
    )


def _resolve_config_paths(config_value: str) -> list[Path]:
    """Expand a config file, directory, or glob into concrete YAML paths."""
    config_path = Path(config_value)
    if config_path.is_dir():
        yaml_paths = sorted(config_path.glob("*.yaml")) + sorted(
            config_path.glob("*.yml")
        )
        return [path for path in yaml_paths if path.is_file()]

    if any(char in config_value for char in "*?["):
        return [
            Path(path)
            for path in sorted(glob.glob(config_value))
            if Path(path).is_file()
        ]

    return [config_path]


def main(argv: list[str]) -> int:
    """Main entry point for the script."""
    args = parse_args(argv)
    _configure_logging(args.verbose)
    config_paths = _resolve_config_paths(args.config)
    if not config_paths:
        log.error("No configuration files matched %s", args.config)
        return 2
    if len(config_paths) != 1:
        log.error(
            "Expected exactly one configuration file for %s, found %d",
            args.config,
            len(config_paths),
        )
        return 2
    config_path = config_paths[0]
    try:
        config_namespace_from_path(config_path)
        load_config(config_path)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    return run_pipeline(
        config_path,
        max_runtime_seconds=args.max_runtime_seconds,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
