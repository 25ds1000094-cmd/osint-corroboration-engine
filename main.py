from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

ALLOWED_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def make_result(verdict: str, confidence: str, sources: list[str]):
    return {
        "verdict": verdict,
        "confidence": confidence,
        "corroboratingSources": sources,
    }


def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        text = value

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text)

        if parsed.tzinfo is None:
            return None

        return parsed.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def is_valid_source(source: Any) -> bool:
    if not isinstance(source, dict):
        return False

    if not isinstance(source.get("id"), str):
        return False

    if not isinstance(source.get("origin"), str):
        return False

    if not isinstance(source.get("value"), str):
        return False

    if not isinstance(source.get("observedAt"), str):
        return False

    if source.get("type") not in ALLOWED_TYPES:
        return False

    return True


def is_fresh(
    as_of: datetime,
    observed_at: datetime,
    staleness_days: float
) -> bool:

    age_seconds = (as_of - observed_at).total_seconds()

    return age_seconds <= staleness_days * 86400


@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/corroborate")
async def corroborate(request: Request):

    # --------------------------------------------------
    # Read JSON manually.
    #
    # This is important because the assignment requires
    # us to return "invalid" for certain bad requests,
    # rather than FastAPI returning HTTP 422.
    # --------------------------------------------------

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    # --------------------------------------------------
    # RULE 1
    # --------------------------------------------------

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    if not isinstance(claim.get("value"), str):
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    staleness_days = body.get("stalenessDays")

    if isinstance(staleness_days, bool):
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    if not isinstance(staleness_days, (int, float)):
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    sources = body.get("sources")

    if not isinstance(sources, list):
        return JSONResponse(
            status_code=200,
            content=make_result("invalid", "low", [])
        )

    claim_value = claim["value"]

    # --------------------------------------------------
    # Keep only valid and fresh sources
    # --------------------------------------------------

    fresh_sources = []

    for source in sources:

        if not is_valid_source(source):
            continue

        observed_at = parse_timestamp(source["observedAt"])

        if observed_at is None:
            continue

        if not is_fresh(
            as_of,
            observed_at,
            staleness_days
        ):
            continue

        fresh_sources.append(source)

    # --------------------------------------------------
    # RULE 2
    #
    # Fresh authoritative source contradicts claim.
    # --------------------------------------------------

    contradictions = []

    for source in fresh_sources:

        if source.get("authoritative") is True:
            if source["value"] != claim_value:
                contradictions.append(source)

    if contradictions:

        ids = sorted(
            source["id"]
            for source in contradictions
        )

        return JSONResponse(
            status_code=200,
            content=make_result(
                "contradicted",
                "low",
                ids
            )
        )

    # --------------------------------------------------
    # RULE 3
    #
    # Find fresh sources agreeing with claim.
    # --------------------------------------------------

    agreeing_sources = []

    for source in fresh_sources:

        if source["value"] == claim_value:
            agreeing_sources.append(source)

    # --------------------------------------------------
    # Group by origin.
    #
    # Same origin = mirrors.
    # Keep lexicographically smallest ID.
    # --------------------------------------------------

    representatives = {}

    for source in agreeing_sources:

        origin = source["origin"]

        if origin not in representatives:

            representatives[origin] = source

        else:

            current = representatives[origin]

            if source["id"] < current["id"]:
                representatives[origin] = source

    representatives = list(representatives.values())

    # --------------------------------------------------
    # Need at least TWO independent origins.
    # --------------------------------------------------

    if len(representatives) >= 2:

        ids = sorted(
            source["id"]
            for source in representatives
        )

        types = {
            source["type"]
            for source in representatives
        }

        if len(types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return JSONResponse(
            status_code=200,
            content=make_result(
                "supported",
                confidence,
                ids
            )
        )

    # --------------------------------------------------
    # RULE 4
    # --------------------------------------------------

    return JSONResponse(
        status_code=200,
        content=make_result(
            "unverified",
            "low",
            []
        )
    )
