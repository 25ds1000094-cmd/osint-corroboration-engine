from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI(title="OSINT Corroboration Engine")


ALLOWED_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def invalid_response():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


def parse_timestamp(value: Any):
    """
    Parse an ISO-8601 timestamp.

    Returns a timezone-aware datetime, or None if invalid.
    """
    if not isinstance(value, str):
        return None

    try:
        # Support timestamps ending in Z.
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)

        # Treat a timestamp without timezone information as invalid.
        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def is_fresh(as_of: datetime, observed_at: datetime, staleness_days: float):
    """
    A source is fresh when:

        asOf - observedAt <= stalenessDays

    Older observations are stale.
    """
    age = as_of - observed_at

    return age.total_seconds() <= staleness_days * 86400


def valid_source(source: Any):
    """
    Check whether an individual source satisfies the assignment's
    source validity rules.
    """
    if not isinstance(source, dict):
        return False

    required_strings = ["id", "origin", "value", "observedAt"]

    for field in required_strings:
        if not isinstance(source.get(field), str):
            return False

    if source.get("type") not in ALLOWED_TYPES:
        return False

    return True


@app.post("/corroborate")
async def corroborate(body: Any):
    # ---------------------------------------------------------
    # RULE 1: INVALID REQUEST
    # ---------------------------------------------------------

    if not isinstance(body, dict):
        return JSONResponse(content=invalid_response())

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return JSONResponse(content=invalid_response())

    if not isinstance(claim.get("value"), str):
        return JSONResponse(content=invalid_response())

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return JSONResponse(content=invalid_response())

    staleness_days = body.get("stalenessDays")

    # bool is technically a subclass of int in Python.
    # We don't want true/false to count as a number here.
    if isinstance(staleness_days, bool) or not isinstance(
        staleness_days, (int, float)
    ):
        return JSONResponse(content=invalid_response())

    sources = body.get("sources")

    if not isinstance(sources, list):
        return JSONResponse(content=invalid_response())

    claim_value = claim["value"]

    # ---------------------------------------------------------
    # KEEP ONLY VALID + FRESH SOURCES
    # ---------------------------------------------------------

    fresh_sources = []

    for source in sources:
        # Invalid individual sources are ignored entirely.
        if not valid_source(source):
            continue

        observed_at = parse_timestamp(source["observedAt"])

        # Invalid observedAt means this source cannot be used.
        if observed_at is None:
            continue

        if not is_fresh(as_of, observed_at, staleness_days):
            continue

        fresh_sources.append(source)

    # ---------------------------------------------------------
    # RULE 2: AUTHORITATIVE CONTRADICTION
    # ---------------------------------------------------------

    contradicting_sources = [
        source
        for source in fresh_sources
        if source.get("authoritative") is True
        and source["value"] != claim_value
    ]

    if contradicting_sources:
        ids = sorted(
            source["id"]
            for source in contradicting_sources
        )

        return JSONResponse(
            content={
                "verdict": "contradicted",
                "confidence": "low",
                "corroboratingSources": ids,
            }
        )

    # ---------------------------------------------------------
    # RULE 3: SUPPORTING SOURCES
    # ---------------------------------------------------------

    agreeing_sources = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    # Group sources by origin.
    #
    # Same origin = mirrors.
    # Each origin can contribute only one representative.
    representatives = {}

    for source in agreeing_sources:
        origin = source["origin"]

        if origin not in representatives:
            representatives[origin] = source
        else:
            # Choose lexicographically smallest ID.
            if source["id"] < representatives[origin]["id"]:
                representatives[origin] = source

    representative_sources = list(representatives.values())

    # Need at least two independent origins.
    if len(representative_sources) >= 2:
        representative_ids = sorted(
            source["id"]
            for source in representative_sources
        )

        types = {
            source["type"]
            for source in representative_sources
        }

        if len(types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return JSONResponse(
            content={
                "verdict": "supported",
                "confidence": confidence,
                "corroboratingSources": representative_ids,
            }
        )

    # ---------------------------------------------------------
    # RULE 4: UNVERIFIED
    # ---------------------------------------------------------

    return JSONResponse(
        content={
            "verdict": "unverified",
            "confidence": "low",
            "corroboratingSources": [],
        }
    )
