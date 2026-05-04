"""Global route vocabulary for terminal pipeline results."""

from __future__ import annotations

from typing import Literal

ROUTE_FILTERED = "filtered"
ROUTE_REVIEW = "review"
ROUTE_UNACTIONABLE = "unactionable"
ResultRoute = Literal["filtered", "review", "unactionable"]
