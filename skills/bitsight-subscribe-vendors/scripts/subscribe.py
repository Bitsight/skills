#!/usr/bin/env python3
"""
Bitsight vendor search-and-subscribe CLI.

Authentication:
    BITSIGHT_API_TOKEN or BITSIGHT_API_JWT can be set in the environment or a .env / .envrc file.
    Use --api-token or --api-jwt CLI flags to override.

Usage:
    python3 subscribe.py [identifier ...]
    python3 subscribe.py --file <path>

Identifiers can be Bitsight company GUIDs, domains, or display names and can
be mixed freely. GUIDs skip the search phase entirely. Domains with a single
search result are auto-confirmed. Display names and ambiguous domain matches
are shown in a confirmation table.

Flags:
    --file <path>           Read identifiers from a file instead of the
                            command line. One per line; comma-separated values
                            also accepted. Lines starting with # are skipped.

Non-interactive flags (can be combined freely):
    --yes                   Skip the file-parse preview confirmation.
    --confirm all|none|<guids>
                            Skip the company-confirmation prompt.
                            <guids> is a comma-separated list of Bitsight
                            company GUIDs to subscribe. GUIDs are stable
                            across runs regardless of search result ordering.
                            Use --resolve-only first to discover them.
                            Examples:  --confirm all
                                       --confirm b9f06faa-...,c1234567-...
    --type <type_key>       Skip the subscription-type prompt. Accepts a
                            subscription type key (e.g. continuous_monitoring).
    --resolve-only          Resolve identifiers and print the confirmation
                            table and available subscription types, then exit
                            without subscribing. Use this for a dry-run first
                            pass to discover GUIDs before committing.

Combining --yes, --confirm, and --type makes the script fully non-interactive.

Recommended two-pass workflow when working non-interactively:
    1. python3 subscribe.py --file vendors.txt --yes --resolve-only
       (inspect the table, note GUIDs for the companies you want)
    2. python3 subscribe.py --file vendors.txt --yes \
           --confirm <guid1>,<guid2>,... --type <type_key>

Authentication:
    BITSIGHT_API_TOKEN must be set in the environment. HTTP Basic Auth is used
    (API key as username, empty password). Never pass the key on the command
    line or paste it into a conversation.
"""


import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_a, **_k) -> bool:
        return False

BASE_URL = os.getenv("BITSIGHT_API_BASE") or "https://api.bitsighttech.com"
USER_AGENT = "<bitsight-user-agent>"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class AuthInfo:
    """Holds API authentication credentials (token or JWT)."""
    def __init__(self, api_token=None, api_jwt=None):
        self.api_token = api_token
        self.api_jwt = api_jwt

    def get_api_base(self):
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
# HTTP helpers
# ---------------------------------------------------------------------------

def _auth_header(auth: AuthInfo) -> str:
    if auth.api_jwt:
        return f"bearer {auth.api_jwt}"
    if auth.api_token:
        token = base64.b64encode(f"{auth.api_token}:".encode()).decode()
        return f"Basic {token}"
    return ""


def get(auth: AuthInfo, url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": _auth_header(auth),
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        # See if the response header for www-authenticate references bitsight, which can help identify auth errors vs other issues
        if e.headers.get("WWW-Authenticate", "").find("bitsight") != -1:
            print(f"Bitsight authentication error -- check your API token: HTTP {e.code} from {url}:\n{body}", file=sys.stderr)
        else:
            print(f"HTTP {e.code} (not Bitsight authentication problem) from {url}:\n{body}", file=sys.stderr)
        sys.exit(1)


def post(auth: AuthInfo, url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": _auth_header(auth),
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"HTTP {e.code} from {url}:\n{body}", file=sys.stderr)
        sys.exit(1)


def get_all_pages(auth: AuthInfo, url: str, key: str) -> list:
    results = []
    next_url: Optional[str] = url
    while next_url:
        data = get(auth, next_url)
        results.extend(data.get(key, []))
        next_url = data.get("next")
    return results


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_cli() -> dict:
    """
    Returns a config dict:
      identifiers: list of (kind, value)
      yes:         bool
      confirm:     str | None   ('all', 'none', '1,3', ...)
      type_key:    str | None
      resolve_only: bool
    """
    args = sys.argv[1:]
    config = {
        "identifiers": [],
        "yes": False,
        "confirm": None,
        "type_key": None,
        "resolve_only": False,
        "file": None,
    }

    i = 0
    positional = []
    while i < len(args):
        a = args[i]
        if a == "--yes":
            config["yes"] = True
        elif a == "--resolve-only":
            config["resolve_only"] = True
        elif a == "--file":
            i += 1
            if i >= len(args):
                print("--file requires a path argument", file=sys.stderr)
                sys.exit(1)
            config["file"] = args[i]
        elif a == "--confirm":
            i += 1
            if i >= len(args):
                print("--confirm requires a value (all, none, or comma-separated GUIDs)", file=sys.stderr)
                sys.exit(1)
            config["confirm"] = args[i].strip().lower()
        elif a == "--type":
            i += 1
            if i >= len(args):
                print("--type requires a type_key value", file=sys.stderr)
                sys.exit(1)
            config["type_key"] = args[i].strip()
        elif a in ("-h", "--help"):
            # Normally consumed by main() before this runs; handled here too so
            # parse_cli() cannot report help as an unknown flag.
            print((__doc__ or "").strip())
            sys.exit(0)
        elif a.startswith("--"):
            print(f"Unknown flag: {a}", file=sys.stderr)
            sys.exit(1)
        else:
            positional.append(a)
        i += 1

    if config["file"] and positional:
        print("Cannot mix --file with positional identifiers", file=sys.stderr)
        sys.exit(1)

    if config["file"]:
        config["identifiers"] = load_file(config["file"], auto_confirm=config["yes"])
    elif positional:
        config["identifiers"] = [classify(a) for a in positional]
    else:
        print("Usage: subscribe.py [--file <path>] [--yes] [--confirm all|none|1,3] "
              "[--type <key>] [--resolve-only] [identifier ...]", file=sys.stderr)
        sys.exit(1)

    return config


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def classify(value: str) -> tuple:
    """Return (type, value) where type is 'guid', 'domain', or 'name'."""
    v = value.strip()
    if UUID_RE.match(v):
        return "guid", v.lower()
    if "." in v and "@" not in v:
        return "domain", v.lower()
    return "name", v


def load_file(path: str, auto_confirm: bool = False) -> list:
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        print(f"Cannot read file '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    identifiers = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Treat each line as a single identifier (names may contain commas)
        if "@" not in line:
            identifiers.append(classify(line))

    if not identifiers:
        print(f"No identifiers found in '{path}'.", file=sys.stderr)
        sys.exit(1)

    counts = {"guid": 0, "domain": 0, "name": 0}
    for kind, _ in identifiers:
        counts[kind] += 1
    sample = ", ".join(v for _, v in identifiers[:5])
    more = f" ... (+{len(identifiers) - 5} more)" if len(identifiers) > 5 else ""
    print(f"Found {len(identifiers)} identifiers: "
          f"{counts['guid']} GUIDs, {counts['domain']} domains, {counts['name']} display names.")
    print(f"Sample: {sample}{more}")

    if not auto_confirm:
        answer = input("Does this look right? [Y/n]: ").strip().lower()
        if answer not in ("", "y", "yes"):
            print("Aborted.")
            sys.exit(0)

    return identifiers


# ---------------------------------------------------------------------------
# Phase 1 — Resolve identifiers
# ---------------------------------------------------------------------------

def fetch_portfolio_guids(auth: AuthInfo, api_base: str) -> set:
    entries = get_all_pages(auth, f"{api_base}/v2/portfolio?fields=guid", "results")
    return {e["guid"].lower() for e in entries if "guid" in e}


def search_company(auth: AuthInfo, api_base: str, query: str) -> list:
    q = urllib.parse.quote(query)
    url = (f"{api_base}/v1/companies/search/"
           f"?expand=details.in_portfolio,details.is_primary,details.confidence,details.self_published"
           f"&limit=100&name={q}")
    data = get(auth, url)
    results = []
    for r in data.get("results", []):
        results.append({
            "guid": r.get("guid", ""),
            "name": r.get("name", ""),
            "primary_domain": r.get("primary_domain", ""),
            "in_portfolio": r.get("details", {}).get("in_portfolio", False),
            "is_primary": r.get("details", {}).get("is_primary", False),
            "confidence": r.get("details", {}).get("confidence", ""),
            "self_published": r.get("details", {}).get("self_published") is not None,
        })
    return results


def resolve_identifiers(auth: AuthInfo, api_base: str, identifiers: list) -> tuple:
    """
    Returns:
        ready:         list of (input_val, guid, name, domain)
        in_portfolio:  list of input_val
        not_found:     list of input_val
        needs_confirm: list of (input_val, kind, [candidates])
    """
    ready, in_portfolio, not_found, needs_confirm = [], [], [], []

    guid_inputs = [(k, v) for k, v in identifiers if k == "guid"]
    non_guid    = [(k, v) for k, v in identifiers if k != "guid"]

    if guid_inputs:
        print("Checking portfolio for GUIDs...")
        portfolio_guids = fetch_portfolio_guids(auth, api_base)
        for kind, val in guid_inputs:
            if val in portfolio_guids:
                in_portfolio.append(val)
            else:
                ready.append((val, val, val, ""))

    for kind, val in non_guid:
        print(f"Searching for '{val}'...")
        candidates = search_company(auth, api_base, val)
        if not candidates:
            not_found.append(val)
        elif kind == "domain" and len(candidates) == 1:
            c = candidates[0]
            if c["in_portfolio"]:
                in_portfolio.append(val)
            else:
                ready.append((val, c["guid"], c["name"], c["primary_domain"]))
        else:
            # Surface all candidates for confirmation, marking any already in portfolio.
            # Never skip an input just because an unrelated result happens to be in portfolio.
            needs_confirm.append((val, kind, candidates))

    return ready, in_portfolio, not_found, needs_confirm


# ---------------------------------------------------------------------------
# Phase 2 — Confirmation for ambiguous / display-name matches
# ---------------------------------------------------------------------------

def _match_score(row: dict) -> int:
    """Score how well a result row's matched company name fits its search input.

    Higher scores mean the match is more relevant to the input that produced it.
    Used to resolve cross-contamination: when the same company appears in
    multiple inputs' result sets, the GUID is assigned to the input where it
    scores highest.
    """
    inp = row["input"].lower()
    name = row["name"].lower()
    if inp == name:
        return 4
    if inp in name or name in inp:
        return 3
    inp_words = set(inp.split())
    name_words = set(name.split())
    return len(inp_words & name_words)


def best_guid_index(rows: list) -> dict:
    """Build a GUID → row mapping that prefers the most relevant input for each GUID.

    When the same GUID appears across multiple inputs' search results (cross-
    contamination), we keep only the row where _match_score is highest so that
    --confirm <guid> is assigned to the correct input.
    """
    index: dict = {}
    for r in rows:
        key = r["guid"].lower()
        if key not in index or _match_score(r) > _match_score(index[key]):
            index[key] = r
    return index


def build_confirm_rows(needs_confirm: list) -> list:
    rows = []
    for input_val, kind, candidates in needs_confirm:
        for c in candidates:
            rows.append({
                "input": input_val,
                "kind": kind,
                "name": c["name"],
                "guid": c["guid"],
                "domain": c["primary_domain"],
                "in_portfolio": c.get("in_portfolio", False),
                "primary": "Yes" if c["is_primary"] else "No",
                "confidence": c.get("confidence", ""),
                "self_pub": "Yes" if c["self_published"] else "No",
            })
    return rows


def print_confirm_table(rows: list) -> None:
    print("\nThe following matches require confirmation:")
    print(f"\n{'Input':<30} {'Matched Company':<30} {'Domain':<25} {'GUID':<36} "
          f"{'In Portfolio':<14} {'Primary':<8} {'Conf':<8} {'Self-Pub'}")
    print("-" * 166)
    for i, r in enumerate(rows, 1):
        is_auto = (r["kind"] == "domain" and
                   sum(1 for rr in rows if rr["input"] == r["input"]) == 1)
        marker = " ✓" if is_auto else ""
        already = "Yes" if r.get("in_portfolio") else "No"
        print(f"{r['input']:<30} {r['name']:<30} {r['domain']:<25} {r['guid']:<36} "
              f"{already:<14} {r['primary']:<8} {r['confidence']:<8} {r['self_pub']}{marker}")
    print()


def resolve_confirm_selection(raw: str, rows: list) -> list:
    """
    Parse a selection string and return list of (input_val, guid, name, domain).

    Accepts:
      - "all" / "none"
      - Comma-separated Bitsight company GUIDs, e.g. "b9f06faa-...,c1234567-..."
    GUIDs are stable across runs regardless of search result ordering.
    Use --resolve-only to discover them before committing.

    There is a 1-1 mapping between GUIDs and the company.
    """
    raw = raw.strip().lower()
    if raw in ("none", ""):
        return []
    if raw == "all":
        selected_rows = rows[:]
    else:
        # Build guid_index preferring the row where the match is most relevant
        # to its input, so that when the same company appears in multiple inputs'
        # result sets (cross-contamination) the GUID is assigned to the right one.
        guid_index = best_guid_index(rows)

        selected_rows = []
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if UUID_RE.match(token):
                r = guid_index.get(token)
                if r:
                    selected_rows.append(r)
                else:
                    print(f"Warning: GUID {token} not found in search results — skipping.")
            else:
                print(f"Warning: '{token}' is not a valid GUID — skipping. "
                      f"Use --resolve-only to find GUIDs.")

    by_input = {}
    for r in selected_rows:
        by_input.setdefault(r["input"], []).append(r)

    confirmed = []
    for input_val, selected in by_input.items():
        if len(selected) > 1:
            # Deduplicate by GUID in case the same row appeared twice
            seen = {}
            for r in selected:
                seen[r["guid"]] = r
            selected = list(seen.values())
        if len(selected) > 1:
            print(f"Warning: multiple rows selected for '{input_val}' — skipping "
                  f"(use a single GUID per input).")
        else:
            r = selected[0]
            confirmed.append((input_val, r["guid"], r["name"], r["domain"]))
    return confirmed


def confirm_matches(needs_confirm: list, pre_confirm: Optional[str] = None) -> list:
    """Return list of (input_val, guid, name, domain). Uses pre_confirm if provided."""
    if not needs_confirm:
        return []

    rows = build_confirm_rows(needs_confirm)
    print_confirm_table(rows)

    if pre_confirm is not None:
        print(f"(Using --confirm {pre_confirm})")
        return resolve_confirm_selection(pre_confirm, rows)

    print("Enter GUIDs to subscribe (comma-separated), 'all', or 'none':")
    raw = input("> ").strip()
    return resolve_confirm_selection(raw, rows)


# ---------------------------------------------------------------------------
# Phase 3 — Subscription type selection
# ---------------------------------------------------------------------------

def fetch_entitlements(auth: AuthInfo, api_base: str) -> dict:
    data = get(auth, f"{api_base}/v1/subscriptions")
    result = {}
    for type_key, value in data.items():
        # The response is a dict keyed by subscription type. Skip non-dict values.
        if not isinstance(value, dict):
            continue
        result[type_key] = {
            "name": value.get("name", type_key),
            "quota": value.get("quota", 0),
            "remaining": value.get("remaining", 0),
        }
    return result


def print_entitlements_table(entitlements: dict) -> None:
    type_list = list(entitlements.items())
    print(f"\n{'#':<4} {'Type Key':<20} {'Display Name':<30} {'Quota':>6}  {'Remaining':>9}")
    print("-" * 72)
    for i, (key, info) in enumerate(type_list, 1):
        rem = info["remaining"]
        rem_str = "⚠ 0 (unavailable)" if rem == 0 else str(rem)
        print(f"{i:<4} {key:<20} {info['name']:<30} {info['quota']:>6}  {rem_str:>9}")


def choose_subscription_type(auth: AuthInfo, api_base: str, n_companies: int, pre_type: Optional[str] = None) -> tuple:
    """
    Returns (type_key, entitlements).
    If pre_type is provided, validates it and uses it without prompting.
    """
    while True:
        entitlements = fetch_entitlements(auth, api_base)
        if not entitlements:
            print("No subscription types found on this account.", file=sys.stderr)
            sys.exit(1)

        type_list = list(entitlements.items())

        if pre_type is not None:
            matched_key = pre_type if pre_type in entitlements else None
            if matched_key is None:
                print(f"--type '{pre_type}' not found. Available types:", file=sys.stderr)
                print_entitlements_table(entitlements)
                sys.exit(1)

            info = entitlements[matched_key]
            if info["remaining"] == 0:
                print(f"Error: subscription type '{matched_key}' has no remaining quota.", file=sys.stderr)
                print_entitlements_table(entitlements)
                sys.exit(1)

            if info["remaining"] < n_companies:
                print(f"Warning: only {info['remaining']} slot(s) remaining, "
                      f"but {n_companies} companies to subscribe. Proceeding with partial subscription.")

            print(f"(Using --type {matched_key})")
            return matched_key, entitlements

        # Interactive path
        print("\nWhich subscription type would you like?\n")
        print_entitlements_table(entitlements)

        raw = input("\nEnter a number: ").strip()
        try:
            idx = int(raw)
            if not (1 <= idx <= len(type_list)):
                raise ValueError
        except ValueError:
            print("Invalid selection — please try again.")
            continue

        type_key, info = type_list[idx - 1]
        if info["remaining"] == 0:
            print(f"'{type_key}' has no remaining quota — please choose another.")
            continue

        if info["remaining"] < n_companies:
            print(f"Warning: only {info['remaining']} slot(s) remaining but you want to subscribe {n_companies}.")
            answer = input("Proceed with partial subscription? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                continue

        return type_key, entitlements


# ---------------------------------------------------------------------------
# Phase 4 — Subscribe
# ---------------------------------------------------------------------------

def do_subscribe(auth: AuthInfo, api_base: str, ready: list, type_key: str) -> tuple:
    payload = {"add": [{"guid": guid, "type": type_key} for _, guid, _, _ in ready]}
    data = post(auth, f"{api_base}/v1/subscriptions/bulk", payload)

    added_guids = set(data.get("added", []))
    error_map = {e["guid"]: e["message"] for e in data.get("errors", [])}

    subscribed, errors = [], []
    for input_val, guid, name, domain in ready:
        if guid in added_guids:
            subscribed.append((input_val, guid, name, domain))
        elif guid in error_map:
            errors.append((input_val, name, error_map[guid]))
        else:
            errors.append((input_val, name, "not in added list and no error reported"))

    return subscribed, errors


# ---------------------------------------------------------------------------
# Phase 5 — Results
# ---------------------------------------------------------------------------

def print_results(subscribed: list, in_portfolio: list, not_found: list,
                  errors: list, entitlements: Optional[dict]) -> None:
    print("\n" + "=" * 60)
    if subscribed:
        print("\nSubscription update complete:")
    else:
        print("\nNothing to subscribe — here's the full summary:")

    def fmt_list(items: list, label: str) -> None:
        if not items:
            return
        print(f"\n{label} ({len(items)}):")
        for item in items:
            print(f"  {item}")

    fmt_list(
        [f"{name} ({domain})" if domain else (name or guid) for _, guid, name, domain in subscribed],
        "Subscribed",
    )
    fmt_list(in_portfolio, "Already in portfolio")
    fmt_list(not_found, "Not found in Bitsight")
    fmt_list([f"{name or input_val} — {msg}" for input_val, name, msg in errors], "Skipped / errors")

    if entitlements:
        print("\nRemaining quota by subscription type:")
        print(f"  {'Type Key':<20} {'Display Name':<30} {'Quota':>6}  {'Remaining':>9}")
        print("  " + "-" * 68)
        for key, info in entitlements.items():
            rem = info["remaining"]
            rem_str = "⚠ 0 (unavailable)" if rem == 0 else str(rem)
            print(f"  {key:<20} {info['name']:<30} {info['quota']:>6}  {rem_str:>9}")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv()

    # Handled first: the credential check below exits non-zero, so --help has to
    # work before it to be usable by someone who has not set a token yet. The
    # module docstring is the full flag reference, so print that.
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print((__doc__ or "").strip())
        sys.exit(0)

    auth_parser = argparse.ArgumentParser(description="Parse auth args", add_help=False)
    auth_parser.add_argument("--api-token", default=None, help="Bitsight API token")
    auth_parser.add_argument("--api-jwt", default=None, help="Bitsight API JWT")
    # Parse only known args, leaving the rest for parse_cli
    known_args, _ = auth_parser.parse_known_args()

    api_token = known_args.api_token or os.environ.get("BITSIGHT_API_TOKEN", "").strip()
    api_jwt = known_args.api_jwt or os.environ.get("BITSIGHT_API_JWT", "").strip()

    if not api_token and not api_jwt:
        print(
            "Either BITSIGHT_API_TOKEN or BITSIGHT_API_JWT must be set.\n"
            "Set it in your shell environment (export BITSIGHT_API_TOKEN=... or export BITSIGHT_API_JWT=...) or a .env / .envrc file.\n"
            "You can find your token under Account → User API Token in the Bitsight portal.",
            file=sys.stderr,
        )
        sys.exit(1)

    auth = AuthInfo(api_token=api_token, api_jwt=api_jwt)
    api_base = auth.get_api_base() or BASE_URL

    cfg = parse_cli()

    # Phase 1 — resolve
    ready, in_portfolio, not_found, needs_confirm = resolve_identifiers(auth, api_base, cfg["identifiers"])

    # --resolve-only: print the confirmation table and available types, then stop
    if cfg["resolve_only"]:
        if needs_confirm:
            rows = build_confirm_rows(needs_confirm)
            rows.sort(key=lambda r: (r["input"].lower(), -_match_score(r)))
            print_confirm_table(rows)
            # Print a filtered GUID index grouped by input, showing only rows
            # where the matched company name has some word overlap with the
            # search input (score >= 1).  This cuts out the noise from unrelated
            # companies and lets the user quickly pick the right GUID for
            # --confirm without wading through hundreds of irrelevant results.
            index = best_guid_index(rows)
            # Group best-match rows by input, keeping only meaningful matches
            by_input_index: dict = {}
            for guid, r in index.items():
                if _match_score(r) >= 1:
                    by_input_index.setdefault(r["input"], []).append((guid, r))
            if by_input_index:
                pass
            else:
                print("\n(No close name matches found — use the table above to identify GUIDs manually.)")
        print()
        if ready:
            names = ", ".join(
                f"{name} ({domain})" if domain else (name or guid)
                for _, guid, name, domain in ready
            )
            print(f"Auto-resolved ({len(ready)}): {names}")
        if in_portfolio:
            print(f"Already in portfolio ({len(in_portfolio)}): {', '.join(in_portfolio)}")
        if not_found:
            print(f"Not found in Bitsight ({len(not_found)}): {', '.join(not_found)}")
        entitlements = fetch_entitlements(auth, api_base)
        print("\nAvailable subscription types:")
        print_entitlements_table(entitlements)
        print("\n-- resolve-only mode: no subscriptions made --")
        sys.exit(0)

    # Phase 2 — confirm ambiguous matches
    confirmed = confirm_matches(needs_confirm, pre_confirm=cfg["confirm"])
    ready.extend(confirmed)

    # Pre-subscription summary
    total = len(ready) + len(in_portfolio) + len(not_found)
    print()
    if total < 10:
        if ready:
            names = ", ".join(
                f"{name} ({domain})" if domain else (name or guid)
                for _, guid, name, domain in ready
            )
            print(f"Ready to subscribe ({len(ready)}): {names}")
        if in_portfolio:
            print(f"Already in portfolio ({len(in_portfolio)}): {', '.join(in_portfolio)}")
        if not_found:
            print(f"Not found in Bitsight ({len(not_found)}): {', '.join(not_found)}")
    else:
        parts = [
            f"Ready to subscribe: {len(ready)}",
            f"Already in portfolio: {len(in_portfolio)}",
            f"Not found: {len(not_found)}",
        ]
        print(" | ".join(parts))

    if not ready:
        print_results([], in_portfolio, not_found, [], None)
        sys.exit(0)

    # Phase 3 — subscription type
    type_key, _ = choose_subscription_type(auth, api_base, len(ready), pre_type=cfg["type_key"])

    # Phase 4 — subscribe
    subscribed, errors = do_subscribe(auth, api_base, ready, type_key)

    # Phase 5 — results
    final_entitlements = fetch_entitlements(auth, api_base)
    print_results(subscribed, in_portfolio, not_found, errors, final_entitlements)


if __name__ == "__main__":
    main()
