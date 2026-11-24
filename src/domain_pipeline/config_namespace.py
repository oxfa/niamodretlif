"""Shared validation rule for config-owned namespaces."""

import re

CONFIG_NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
