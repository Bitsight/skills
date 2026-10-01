#!/usr/bin/env python3
"""
declining.py - Find Bitsight portfolio companies with declining ratings.

Usage:
    python declining.py --output results.csv CONSTRAINT [CONSTRAINT ...]

Examples:
    python declining.py --output out.csv 'portfolio:-30/2w'
    python declining.py --output out.csv 'portfolio:-10%/3w'
    python declining.py --output out.csv 'portfolio:-30/2w' 'Tier 2:-10%/1m' 'My Folder:-20/10d'

Constraint format:  <selector>:<point_change>[%]/<time_period>
  selector      'portfolio' (all companies), a tier name, or a folder name
  point_change  negative integer — absolute points (e.g. -30) or percentage (e.g. -10%)
  time_period   Nd | Nw | Nm | Nq  (days, weeks, months, quarters)

A company FAILS a constraint when:
  Absolute:   max_rating + point_change >= current_rating
  Percentage: max_rating * (1 + point_change / 100) >= current_rating
Examples:
  max=720, drop=-30 (absolute):  720 + (-30) = 690 >= 680 → FAIL
  max=720, drop=-10% (percent):  720 * 0.90 = 648 >= 640 → FAIL

Environment:
    BITSIGHT_API_TOKEN  Required. Your Bitsight API token.

Output CSV columns: name, guid, failed_constraints
"""

from __future__ import annotations

import os
import sys
import csv
import re
import argparse
import time
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, timedelta
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import requests

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_a, **_k) -> bool:
        return False

API_BASE = os.getenv("BITSIGHT_API_BASE") or "https://api.bitsighttech.com"
REQUEST_DELAY = 0.1  # seconds between requests to avoid rate limiting


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class APISession(requests.Session):
    """HTTP session with attached API base URL."""
    def __init__(self, api_base: str | None = None):
        super().__init__()
        self._api_base = api_base or API_BASE


class AuthInfo:
    """Holds API authentication credentials (token or JWT)."""
    def __init__(self, api_token: str | None = None, api_jwt: str | None = None):
        self.api_token = api_token
        self.api_jwt = api_jwt

    def get_api_base(self) -> str | None:
        """Extract API base URL from JWT's portal_host claim, or None if not available."""
        if not self.api_jwt:
            return None
        try:
            parts = self.api_jwt.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            padding = '=' * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload + padding)
            claims = json.loads(decoded)
            portal_host = claims.get("portal_host", "").strip()
            if not portal_host:
                return None
            portal_host = portal_host.rstrip('/')
            if portal_host == "https://service.bitsighttech.com":
                return "https://api.bitsighttech.com"
            # The claim may already carry the prefix; appending a second one
            # would 404 every request.
            if portal_host.endswith("/customer-api"):
                return portal_host
            return f"{portal_host}/customer-api"
        except (ValueError, KeyError, json.JSONDecodeError):
            return None


# ---------------------------------------------------------------------------
# Constraint parsing
# ---------------------------------------------------------------------------

def period_to_days(period: str) -> int:
    """Convert a period string (e.g. '2w', '1m', '1q') to a number of days."""
    m = re.fullmatch(r'(\d+)([dwmq])', period)
    if not m:
        raise ValueError(f"Invalid time period {period!r}. Expected e.g. 10d, 2w, 3m, 1q")
    n, unit = int(m.group(1)), m.group(2)
    return {'d': n, 'w': n * 7, 'm': n * 30, 'q': n * 91}[unit]


@dataclass(frozen=True)
class Constraint:
    selector: str        # 'portfolio', tier name, or folder name
    point_change: int    # negative, e.g. -30 or -10 (when is_percentage=True)
    is_percentage: bool  # True → point_change is a % drop; False → absolute points
    days: int            # lookback window in days
    raw: str             # original string, used in output

    @classmethod
    def parse(cls, s: str) -> Constraint:
        """Parse a constraint string like 'portfolio:-30/2w' or 'portfolio:-10%/2w'."""
        m = re.fullmatch(r'(.+):(-\d+)(%?)/(\d+[dwmq])', s.strip())
        if not m:
            raise ValueError(
                f"Invalid constraint {s!r}.\n"
                "Expected: <selector>:<point_change>[%]/<period>  "
                "e.g. portfolio:-30/2w or portfolio:-10%/2w"
            )
        selector = m.group(1).strip()
        point_change = int(m.group(2))
        is_percentage = m.group(3) == '%'
        days = period_to_days(m.group(4))
        return cls(selector, point_change, is_percentage, days, s.strip())


# ---------------------------------------------------------------------------
# Bitsight API client
# ---------------------------------------------------------------------------

def _new_session(auth: AuthInfo, api_base: str | None = None) -> APISession:
    """Create an authenticated API session."""
    session = APISession(api_base)
    if auth.api_jwt:
        session.headers.update({"Authorization": f"bearer {auth.api_jwt}"})
    elif auth.api_token:
        session.auth = (auth.api_token, "")
    session.headers.update({"Accept": "application/json", "User-Agent": "<bitsight-user-agent>"})
    return session


class BitsightClient:
    def __init__(self, auth: AuthInfo, api_base: str | None = None):
        self.session = _new_session(auth, api_base)

    def _get(self, path: str, **params) -> Any:
        time.sleep(REQUEST_DELAY)
        resp = self.session.get(f"{self.session._api_base}{path}", params=params if params else None)
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            print(f"  API error {resp.status_code} for {path}: {resp.text[:300]}",
                  file=sys.stderr)
            raise
        return resp.json()

    def get_portfolio(self) -> list[dict]:
        """Return all portfolio companies with current ratings."""
        print("Fetching portfolio companies...", file=sys.stderr)
        data = self._get('/ratings/v1/companies')
        companies = data.get('companies', [])
        print(f"  Found {len(companies)} companies.", file=sys.stderr)
        return companies

    def get_folders(self) -> list[dict]:
        """Return all folders, each with a 'companies' list of GUIDs."""
        return self._get('/ratings/v1/folders')

    def get_tiers(self) -> list[dict]:
        """Return all tiers, each with a 'companies' list of GUIDs."""
        return self._get('/ratings/v1/tiers')

    def get_rating_history(self, guid: str) -> list[tuple[date, int]]:
        """
        Return a sorted (ascending) list of (date, rating) pairs for a company.
        The Bitsight API returns ~370 days of daily ratings in the company detail record.
        """
        data = self._get(f'/ratings/v1/companies/{guid}')
        history = []
        for entry in data.get('ratings', []):
            try:
                d = date.fromisoformat(entry['rating_date'])
                rating = int(entry['rating'])
                history.append((d, rating))
            except (KeyError, ValueError, TypeError):
                continue
        return sorted(history)  # ascending by date


# ---------------------------------------------------------------------------
# Build selector → GUID sets
# ---------------------------------------------------------------------------

def build_selector_map(
    portfolio: list[dict],
    folders: list[dict],
    tiers: list[dict],
) -> dict[str, set[str]]:
    """
    Return a mapping from selector name (lowercased) to a set of company GUIDs.
    Keys: 'portfolio', each folder name, each tier name.
    """
    mapping: dict[str, set[str]] = {}

    # 'portfolio' = every company in the portfolio
    mapping['portfolio'] = {c['guid'] for c in portfolio}

    # Folders
    for folder in folders:
        name = folder.get('name', '').strip().lower()
        if name:
            mapping.setdefault(name, set()).update(folder.get('companies', []))

    # Tiers
    for tier in tiers:
        name = tier.get('name', '').strip().lower()
        if name:
            mapping.setdefault(name, set()).update(tier.get('companies', []))

    return mapping


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def find_declining(
    client: BitsightClient,
    constraints: list[Constraint],
    max_companies: int = 250,
) -> list[tuple[dict, list[Constraint], int, date]]:
    """
    Check each portfolio company against all applicable constraints.
    Returns a list of (company, [failed_constraints], max_rating, max_rating_date)
    for companies that fail at least one constraint.
    """
    portfolio = client.get_portfolio()

    print("Fetching folders and tiers...", file=sys.stderr)
    folders = client.get_folders()
    tiers = client.get_tiers()

    selector_map = build_selector_map(portfolio, folders, tiers)

    # Warn about any selectors that don't match anything
    for c in constraints:
        sel = c.selector.lower()
        if sel not in selector_map:
            print(f"  Warning: selector {c.selector!r} did not match any portfolio, "
                  f"tier, or folder.", file=sys.stderr)

    # Build a per-GUID list of applicable constraints
    guid_to_constraints: dict[str, list[Constraint]] = defaultdict(list)
    for c in constraints:
        guids = selector_map.get(c.selector.lower(), set())
        for guid in guids:
            guid_to_constraints[guid].append(c)

    # Index portfolio by GUID for quick lookup
    portfolio_by_guid = {c['guid']: c for c in portfolio}

    today = date.today()
    results = []
    companies_to_check = [
        guid for guid in guid_to_constraints
        if guid in portfolio_by_guid
    ]
    total = len(companies_to_check)

    # Check if company count exceeds the limit
    if total > max_companies:
        print(f"Error: Found {total} companies to check, but --max-companies limit is {max_companies}.",
              file=sys.stderr)
        print(f"  To process all {total} companies, increase the limit: --max-companies {total}",
              file=sys.stderr)
        sys.exit(1)

    # Phase 1: fetch all rating histories concurrently (bounded to 10 workers).
    print(f"Fetching rating histories for {total} companies (up to 10 concurrent)...",
          file=sys.stderr)
    histories: dict[str, list] = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        future_to_guid = {pool.submit(client.get_rating_history, guid): guid
                          for guid in companies_to_check}
        done = 0
        for future in as_completed(future_to_guid):
            guid = future_to_guid[future]
            done += 1
            try:
                histories[guid] = future.result()
            except Exception as exc:
                name = portfolio_by_guid[guid].get('name', guid)
                print(f"  Warning: failed to fetch history for {name!r}: {exc}",
                      file=sys.stderr)
                histories[guid] = []
            if done % 25 == 0 or done == total:
                print(f"  ... {done}/{total} histories fetched", file=sys.stderr)

    # Phase 2: evaluate constraints sequentially (no I/O).
    for i, guid in enumerate(companies_to_check, 1):
        company = portfolio_by_guid[guid]
        applicable = guid_to_constraints[guid]

        current_rating = company.get('rating')
        if current_rating is None:
            print(f"  Skipping {company['name']!r}: no current rating.", file=sys.stderr)
            continue
        current_rating = int(current_rating)

        history = histories.get(guid, [])
        if not history:
            print(f"  [{i}/{total}] {company['name']!r} — no rating history, skipping.",
                  file=sys.stderr)
            continue

        failed = []
        company_max_rating = None
        company_max_rating_date = None
        for c in applicable:
            window_start = today - timedelta(days=c.days)
            window_entries = [(d, r) for d, r in history if d >= window_start]
            if not window_entries:
                continue
            max_rating = max(r for _, r in window_entries)
            max_rating_date = max(d for d, r in window_entries if r == max_rating)
            if c.is_percentage:
                threshold = max_rating * (1 + c.point_change / 100)
            else:
                threshold = max_rating + c.point_change
            if threshold >= current_rating:
                print(
                    f"  [{i}/{total}] FAIL {c.raw}: {company['name']!r} "
                    f"max={max_rating} on {max_rating_date.isoformat()}, "
                    f"threshold={threshold:.1f}, current={current_rating}",
                    file=sys.stderr,
                )
                failed.append(c)
                if (company_max_rating is None
                        or max_rating > company_max_rating
                        or (max_rating == company_max_rating
                            and max_rating_date > company_max_rating_date)):
                    company_max_rating = max_rating
                    company_max_rating_date = max_rating_date

        if failed:
            results.append((company, failed, company_max_rating, company_max_rating_date))

    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(results: list[tuple[dict, list[Constraint], int, date]], outfile: str) -> None:
    with open(outfile, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'name', 'guid', 'failed_constraints',
            'max_rating', 'max_rating_date', 'current_rating',
        ])
        for company, failed, max_rating, max_rating_date in results:
            writer.writerow([
                company['name'],
                company['guid'],
                '; '.join(c.raw for c in failed),
                max_rating,
                max_rating_date.isoformat() if max_rating_date is not None else '',
                company.get('rating', ''),
            ])
    print(f"\nWrote {len(results)} row(s) to {outfile}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Find Bitsight portfolio companies with declining ratings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        'constraints', nargs='+', metavar='CONSTRAINT',
        help="e.g. 'portfolio:-30/2w'  'Tier 2:-50/1m'  'My Folder:-20/10d'",
    )
    parser.add_argument(
        '--output', '-o', required=True, metavar='FILE',
        help="Output CSV file path",
    )
    parser.add_argument(
        '--max-companies', type=int, default=250, metavar='N',
        help="Maximum number of companies to check (default: 250). "
             "If the portfolio contains more companies, exit with an error.",
    )
    parser.add_argument(
        '--api-token', default=None,
        help="Bitsight API token (HTTP Basic auth)",
    )
    parser.add_argument(
        '--api-jwt', default=None,
        help="Bitsight API JWT (bearer auth, overrides --api-token)",
    )
    args = parser.parse_args()

    api_token = args.api_token or os.environ.get('BITSIGHT_API_TOKEN')
    api_jwt = args.api_jwt or os.environ.get('BITSIGHT_API_JWT')

    if not api_token and not api_jwt:
        print("Error: Either BITSIGHT_API_TOKEN or BITSIGHT_API_JWT must be set.", file=sys.stderr)
        sys.exit(1)

    auth = AuthInfo(api_token=api_token, api_jwt=api_jwt)
    api_base = auth.get_api_base() or API_BASE

    constraints = []
    for raw in args.constraints:
        try:
            constraints.append(Constraint.parse(raw))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"Parsed {len(constraints)} constraint(s):", file=sys.stderr)
    for c in constraints:
        print(f"  {c.raw}  →  selector={c.selector!r}, drop={c.point_change:+d}, "
              f"window={c.days}d", file=sys.stderr)
    print(file=sys.stderr)

    client = BitsightClient(auth, api_base)

    try:
        results = find_declining(client, constraints, max_companies=args.max_companies)
    except requests.HTTPError:
        sys.exit(1)
    except requests.ConnectionError as e:
        print(f"Error: Could not connect to Bitsight API: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.Timeout:
        print("Error: Request to Bitsight API timed out.", file=sys.stderr)
        sys.exit(1)

    if not results:
        print("\nNo companies matched any constraint.", file=sys.stderr)

    write_csv(results, args.output)


if __name__ == '__main__':
    main()
