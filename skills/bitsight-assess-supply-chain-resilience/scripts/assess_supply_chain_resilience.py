#!/usr/bin/env python3
"""Assess third-party supply-chain resilience: do our vendors introduce meaningful
risk, and is our supply chain safer or riskier than last week / month / quarter /
year?

Aggregates the monitored vendor portfolio into one supply-chain read from Bitsight's
portfolio statistics (GET /v1/portfolio/statistics): the rating distribution
(advanced / intermediate / basic counts, median, mean), the risk vectors where the
portfolio is weakest, and the trend over a chosen timeframe — computed statelessly by
re-issuing the SAME statistics call back-dated to Bitsight's own historical figures
(no snapshot store). Optionally names the N riskiest vendors
(GET /v2/portfolio, lowest-rated first).

Read-only. Use a per-vendor threat/victimization skill for live single-vendor signal;
this summarizes the whole portfolio, it does not enumerate every vendor.

Auth: set BITSIGHT_API_TOKEN (or BITSIGHT_API_JWT) in the environment or a .env
file; the token is confidential and is never printed. See --help for usage.

Required libraries: none (Python standard library only)."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "<bitsight-user-agent>"
SKILL_VERSION = "2026.247"
DEFAULT_HOST = "https://api.bitsighttech.com"

# window enum -> look-back in days for the back-dated baseline. The statistics
# endpoint requires rating_date within one year of the latest, so `year` is the max.
WINDOW_DAYS = {"week": 7, "month": 30, "quarter": 90, "year": 365}

# Rating buckets the statistics endpoint reports; also the --risky-band choices.
BANDS = ["advanced", "intermediate", "basic"]


class CliError(Exception):
    def __init__(self, message: str, code: str = "ERROR", exit_code: int = 1):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


# ---------------------------------------------------------------------------
# Auth / base URL / .env (contract shared with the other Bitsight skills)
# ---------------------------------------------------------------------------

def resolve_base_url(api_jwt: str | None) -> str:
    """JWT portal_host claim → base URL, applying the /customer-api rule exactly once."""
    default = (os.getenv("BITSIGHT_API_BASE") or DEFAULT_HOST).rstrip("/")
    if not api_jwt:
        return default
    try:
        payload = api_jwt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, KeyError, json.JSONDecodeError, IndexError):
        return default
    host = (claims.get("portal_host") or "").strip().rstrip("/")
    if not host:
        return default
    if host == "https://service.bitsighttech.com":
        return "https://api.bitsighttech.com"
    return host if host.endswith("/customer-api") else f"{host}/customer-api"


def auth_headers(api_jwt: str | None, api_token: str | None) -> dict:
    h = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if api_jwt:
        h["Authorization"] = f"bearer {api_jwt}"
    elif api_token:
        h["Authorization"] = "Basic " + base64.b64encode(f"{api_token}:".encode()).decode()
    return h


def load_dotenv_simple() -> None:
    """Populate os.environ from the nearest .env / .envrc, without clobbering."""
    seen: set[Path] = set()
    starts = [Path(__file__).resolve().parent, Path.cwd(), *Path.cwd().parents]
    for start in starts:
        for name in (".env", ".envrc"):
            path = (start / name).resolve()
            if path in seen or not path.exists():
                continue
            seen.add(path)
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_get_json(url: str, headers: dict, timeout: int, retries: int) -> Any:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8")
            return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                last_error = exc
                continue
            if exc.code == 401:
                raise CliError("Authentication failed — check your API token/JWT.",
                               "AUTH_FAILED", 2) from exc
            if exc.code == 403:
                raise CliError(f"Permission denied: {detail}", "PERMISSION_DENIED", 2) from exc
            if exc.code == 404:
                raise CliError(f"Not found: {detail}", "NOT_FOUND", 2) from exc
            if exc.code == 400:
                raise CliError(f"Bad request: {detail}", "BAD_REQUEST", 2) from exc
            raise CliError(f"HTTP {exc.code}: {detail}", "HTTP_ERROR", 2) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                last_error = exc
                continue
            raise CliError(f"Request failed: {exc}", "NETWORK_ERROR", 2) from exc
    raise CliError(f"Request failed after retries: {last_error}", "NETWORK_ERROR", 2)


def build_url(base: str, path: str, params: dict[str, Any]) -> str:
    clean = {k: v for k, v in params.items() if v is not None and v != ""}
    query = urllib.parse.urlencode(clean, doseq=True)
    url = f"{base}{path}"
    return f"{url}?{query}" if query else url


# ---------------------------------------------------------------------------
# Parsing the portfolio-statistics payload
# ---------------------------------------------------------------------------

def as_num(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def parse_distribution(payload: Any) -> dict | None:
    """statistics.ratings → {distribution{...}, median, mean, min, max, vendor_count}."""
    ratings = (payload or {}).get("ratings") if isinstance(payload, dict) else None
    if not isinstance(ratings, dict):
        return None
    buckets = ratings.get("entity_count_by_bucket") or {}
    dist = {b: int(buckets.get(b) or 0) for b in BANDS}
    return {
        "distribution": dist,
        "vendor_count": sum(dist.values()),
        "median_rating": as_num(ratings.get("median_rating")),
        "mean_rating": as_num(ratings.get("mean_rating")),
        "min_rating": as_num(ratings.get("min_rating")),
        "max_rating": as_num(ratings.get("max_rating")),
    }


def rank_weakest_vectors(payload: Any, top: int = 5) -> list[dict]:
    """risk_vector_averages[] sorted by percent_companies_below_average desc, top ~5.

    The ranking is the value-add — the raw array doesn't say what's weak.
    """
    rows = (payload or {}).get("risk_vector_averages") if isinstance(payload, dict) else None
    scored: list[dict] = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        pct = as_num(r.get("percent_companies_below_average"))
        if pct is None:
            continue
        scored.append({
            "risk_vector": r.get("risk_vector_slug") or r.get("risk_vector_id") or "unknown",
            "name": r.get("risk_vector") or r.get("risk_vector_slug") or "unknown",
            "average_grade": r.get("average_grade"),
            "pct_below_average": round(float(pct), 2),
            "companies_below_average": int(r.get("companies_below_average") or 0),
        })
    scored.sort(key=lambda v: v["pct_below_average"], reverse=True)
    return scored[:top]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def stats_params(args, types: str, rating_date: str | None = None) -> dict:
    p: dict[str, Any] = {"types": types}
    if rating_date:
        p["rating_date"] = rating_date
    if args.tier:
        p["tier"] = args.tier
    if args.folder:
        p["folder"] = args.folder
    if args.scope:
        p["scope"] = args.scope
    return p


def run(args: argparse.Namespace) -> dict:
    api_jwt = args.api_jwt or os.getenv("BITSIGHT_API_JWT")
    api_token = args.api_token or os.getenv("BITSIGHT_API_TOKEN")
    if not api_jwt and not api_token:
        raise CliError(
            "No Bitsight credential found. Provide BITSIGHT_API_JWT or "
            "BITSIGHT_API_TOKEN (environment, .env, or --api-jwt/--api-token).",
            "MISSING_CREDENTIALS", 2)
    if args.tier and args.folder:
        raise CliError("--tier and --folder cannot be used together.", "BAD_REQUEST", 2)
    if args.custom_days is not None and args.custom_days <= 0:
        raise CliError("--custom-days must be a positive integer.", "BAD_REQUEST", 2)
    if args.name_riskiest < 0:
        raise CliError("--name-riskiest must be >= 0.", "BAD_REQUEST", 2)

    base = resolve_base_url(api_jwt)
    headers = auth_headers(api_jwt, api_token)
    window_days = args.custom_days or WINDOW_DAYS[args.window]
    today = dt.date.today()
    as_of = today.isoformat()
    baseline_date = (today - dt.timedelta(days=window_days)).isoformat()
    notes: list[str] = []

    result: dict[str, Any] = {
        "success": True,
        "skill_version": SKILL_VERSION,
        "window": args.window if args.custom_days is None else f"{window_days}d",
        "window_days": window_days,
        "scope": args.scope or "portfolio",
        "risky_band": args.risky_band,
        "as_of": as_of,
        "baseline_date": None,
        "vendor_count": None,
        "median_rating": None,
        "mean_rating": None,
        "distribution": None,
        "risky_vendor_count": None,
        "risky_pct": None,
        "weakest_vectors": [],
        "median_delta": None,
        "risky_count_delta": None,
        "advanced_count_delta": None,
        "direction": "unknown",
        "riskiest_vendors": [],
        "data_complete": False,
        "sources_used": ["cm"],
        "coverage": "none",
    }

    # ---- Current state: distribution + weakest vectors ----
    try:
        current = http_get_json(
            build_url(base, "/v1/portfolio/statistics",
                      stats_params(args, "ratings,risk_vector_averages")),
            headers, args.timeout, args.retries)
    except CliError as exc:
        result["notes"] = [f"portfolio statistics unavailable ({exc.code}: {exc}) — "
                           "supply-chain posture UNKNOWN, not 'no vendor risk'."]
        return result

    dist = parse_distribution(current)
    if not dist or dist["vendor_count"] == 0:
        result["notes"] = ["portfolio statistics returned no rated vendors — "
                           "treated as unknown, not a clean/empty supply chain."]
        return result

    result.update({
        "vendor_count": dist["vendor_count"],
        "median_rating": dist["median_rating"],
        "mean_rating": dist["mean_rating"],
        "min_rating": dist["min_rating"],
        "max_rating": dist["max_rating"],
        "distribution": dist["distribution"],
        "weakest_vectors": rank_weakest_vectors(current),
        "data_complete": True,
        "coverage": "partial",  # upgraded to full if the baseline resolves
    })
    risky_now = dist["distribution"].get(args.risky_band, 0)
    result["risky_vendor_count"] = risky_now
    result["risky_pct"] = (round(risky_now / dist["vendor_count"] * 100, 2)
                           if dist["vendor_count"] else None)

    # ---- Back-dated baseline: the SAME call, same membership, historical figures ----
    prior = None
    try:
        prior_payload = http_get_json(
            build_url(base, "/v1/portfolio/statistics",
                      stats_params(args, "ratings", rating_date=baseline_date)),
            headers, args.timeout, args.retries)
        prior = parse_distribution(prior_payload)
    except CliError as exc:
        notes.append(f"trend baseline unavailable for {baseline_date} ({exc.code}); "
                     "reporting current distribution only — NOT a flat trend.")

    if prior and prior["vendor_count"] > 0:
        result["baseline_date"] = baseline_date
        md = (None if dist["median_rating"] is None or prior["median_rating"] is None
              else dist["median_rating"] - prior["median_rating"])
        risky_then = prior["distribution"].get(args.risky_band, 0)
        rd = risky_now - risky_then
        result["median_delta"] = md
        result["risky_count_delta"] = rd
        result["advanced_count_delta"] = (
            dist["distribution"].get("advanced", 0) - prior["distribution"].get("advanced", 0))
        result["direction"] = fold_direction(md, rd, args.flat_threshold, dist["vendor_count"])
        result["coverage"] = "full"
    else:
        if not notes:
            notes.append(f"trend baseline empty for {baseline_date}; reporting "
                         "current distribution only (trend unavailable for this timeframe).")

    # ---- Optional: name the riskiest (lowest-rated) vendors ----
    if args.name_riskiest > 0:
        try:
            vendors = http_get_json(
                build_url(base, "/v2/portfolio",
                          {"sort": "rating", "fields": "name,rating,industry.name",
                           "limit": args.name_riskiest, "scope": args.scope}),
                headers, args.timeout, args.retries)
            rows = (vendors or {}).get("results") if isinstance(vendors, dict) else None
            result["riskiest_vendors"] = [
                {"name": v.get("name"), "rating": as_num(v.get("rating")),
                 "industry": ((v.get("industry") or {}).get("name")
                              if isinstance(v.get("industry"), dict) else None)}
                for v in (rows or []) if isinstance(v, dict)
            ]
        except CliError as exc:
            notes.append(f"riskiest-vendor naming unavailable ({exc.code}); the aggregate "
                         "answer stands without it.")

    result["notes"] = notes
    return result


def fold_direction(median_delta: int | float | None, risky_count_delta: int | None,
                   flat_threshold: int, vendor_count: int) -> str:
    """improving/declining/flat from the median move, with the risky-band count as
    the tiebreaker when the median is within the flat dead-band.

    risky_count_delta negative = fewer vendors in the risky band = safer.
    """
    if median_delta is None:
        return "unknown"
    if median_delta >= flat_threshold:
        return "improving"
    if median_delta <= -flat_threshold:
        return "declining"
    # median is flat within the dead-band — let a material risky-band shift decide.
    risky_flat = max(1, round(0.01 * vendor_count))  # 1% of the portfolio
    if risky_count_delta is not None:
        if risky_count_delta <= -risky_flat:
            return "improving"
        if risky_count_delta >= risky_flat:
            return "declining"
    return "flat"


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def render_text(result: dict) -> str:
    lines: list[str] = []
    scope = result.get("scope")
    lines.append(f"Supply-chain resilience ({scope}) — window: {result['window']} "
                 f"({result['window_days']}d)")

    def fmt(v: Any) -> str:
        return "unknown" if v is None else str(v)

    if not result.get("data_complete"):
        for note in result.get("notes", []):
            lines.append(f"  note: {note}")
        return "\n".join(lines)

    dist = result.get("distribution") or {}
    arrow = {"improving": "▲", "declining": "▼", "flat": "▬", "unknown": "?"}
    d = result.get("direction", "unknown")
    lines.append(
        f"  {arrow.get(d, '?')} {d.upper()}   "
        f"vendors: {fmt(result.get('vendor_count'))}   "
        f"median: {fmt(result.get('median_rating'))}   "
        f"mean: {fmt(result.get('mean_rating'))}")
    lines.append(
        f"  distribution — advanced: {dist.get('advanced')}   "
        f"intermediate: {dist.get('intermediate')}   basic: {dist.get('basic')}")
    lines.append(
        f"  risky ({result.get('risky_band')}): {fmt(result.get('risky_vendor_count'))} "
        f"({fmt(result.get('risky_pct'))}%)")

    if result.get("baseline_date"):
        lines.append(
            f"  vs {result['baseline_date']}: median {fmt(result.get('median_delta'))} pts, "
            f"risky-band {fmt(result.get('risky_count_delta'))} "
            f"(negative = safer), advanced {fmt(result.get('advanced_count_delta'))}")

    weak = result.get("weakest_vectors") or []
    if weak:
        lines.append("  weakest vectors (% of vendors below average):")
        for v in weak:
            lines.append(f"    {v['name']} ({v.get('average_grade')}): "
                         f"{v['pct_below_average']}%")

    riskiest = result.get("riskiest_vendors") or []
    if riskiest:
        lines.append("  riskiest vendors (lowest-rated):")
        for v in riskiest:
            lines.append(f"    {v.get('name')} — {fmt(v.get('rating'))}"
                         + (f" ({v['industry']})" if v.get("industry") else ""))

    for note in result.get("notes", []):
        lines.append(f"  note: {note}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--window", choices=["week", "month", "quarter", "year"],
                   default="year",
                   help="Trend timeframe (week=7d, month=30d, quarter=90d, year=365d; "
                        "default year). Back-date must be within one year.")
    p.add_argument("--custom-days", dest="custom_days", type=int, metavar="N",
                   help="Override --window with an exact back-date of N days (<=365).")
    p.add_argument("--scope", choices=["spm", "tprm"],
                   help="Scope the portfolio: 'tprm' = third-party vendors only, "
                        "'spm' = own subsidiaries. Omit for the whole monitored portfolio.")
    p.add_argument("--tier", help="Scope to a portfolio tier GUID (mutually exclusive with --folder).")
    p.add_argument("--folder", help="Scope to a portfolio folder GUID (mutually exclusive with --tier).")
    p.add_argument("--risky-band", dest="risky_band", choices=BANDS, default="basic",
                   help="Which rating band counts as 'risky' for the headline count "
                        "(default basic).")
    p.add_argument("--name-riskiest", dest="name_riskiest", type=int, default=0, metavar="N",
                   help="Also return the N lowest-rated vendors by name (default 0 = off).")
    p.add_argument("--flat-threshold", dest="flat_threshold", type=int, default=10,
                   help="|median delta| below this is 'flat' unless the risky-band count "
                        "shifts materially (default 10).")
    p.add_argument("--format", choices=["json", "text"], default="json")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--retries", type=int, default=3,
                   help="HTTP retry attempts on 429/5xx/network errors.")
    p.add_argument("--api-token", help="Override BITSIGHT_API_TOKEN.")
    p.add_argument("--api-jwt", help="Override BITSIGHT_API_JWT (bearer; outranks the token).")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    load_dotenv_simple()
    args = parse_args(argv)
    try:
        result = run(args)
    except CliError as exc:
        error = {"success": False, "error_code": exc.code, "error": str(exc),
                 "skill_version": SKILL_VERSION}
        if args.format == "json":
            print(json.dumps(error, indent=2))
        else:
            print(f"Error [{exc.code}]: {exc}", file=sys.stderr)
        return exc.exit_code
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
