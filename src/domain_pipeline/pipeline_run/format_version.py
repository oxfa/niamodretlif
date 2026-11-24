"""Version of the cross-job pipeline handoff contract."""

PIPELINE_RUN_FORMAT_VERSION = 4


def has_current_pipeline_run_format(value: object) -> bool:
    """Return whether a handoff marker uses the current integer representation."""
    return type(value) is int and value == PIPELINE_RUN_FORMAT_VERSION
