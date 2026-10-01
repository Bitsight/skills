#!/usr/bin/env python3
"""Portable CLI for querying company assets, findings, and vulnerabilities.

Runs with the Python standard library on Windows, macOS, and Linux.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SHARED_DIR = Path(__file__).resolve().parent.parent / "shared"
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

from portal_urls import DEFAULT_PORTAL_APP_URL, build_portal_urls


DEFAULT_BASE_URL = "https://service.bitsighttech.com/customer-api/v1"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

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
                return "https://service.bitsighttech.com/customer-api"
            # For customer-api, append if not present
            if not portal_host.endswith("/customer-api"):
                return f"{portal_host}/customer-api"
            return portal_host
        except (ValueError, KeyError, json.JSONDecodeError):
            return None
API_TOKEN_ENV_NAMES = ("BITSIGHT_API_TOKEN", "PORTAL_API_TOKEN")
DEFAULT_VULNERABILITY_EXPAND = (
    "remediation_history,attributed_companies,remediation_validation,tag_details,"
    "assets.tag_details,threat_insights"
)
DEFAULT_VULNERABILITY_FIELDS = (
    "evidence_key,risk_vector,risk_vector_label,severity,severity_category,assets,details,"
    "first_seen,last_seen,impacts_risk_vector_details"
)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class CliError(Exception):
    """Expected user-facing CLI error."""


def load_dotenv(start: Path, explicit_path: str | None = None) -> None:
    paths: list[Path] = []
    if explicit_path:
        paths.append(Path(explicit_path).expanduser())
    paths.extend([start / ".env", Path.cwd() / ".env"])
    paths.extend(parent / ".env" for parent in Path.cwd().parents)

    seen: set[Path] = set()
    for path in paths:
        path = path.resolve()
        if path in seen or not path.exists():
            continue
        seen.add(path)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def parse_key_value(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise CliError(f"Expected key=value for --filter, got: {item}")
        key, value = item.split("=", 1)
        parsed[key] = value
    return parsed


def normalize_base_url(value: str) -> str:
    return value.rstrip("/")


def command_portal_urls(args: argparse.Namespace, auth_header: str | None) -> Any:
    guid = resolve_company_guid(args, auth_header) if not args.company_guid else args.company_guid
    try:
        return build_portal_urls(args, guid)
    except ValueError as exc:
        raise CliError(str(exc)) from exc


def make_auth_header(args: argparse.Namespace) -> str:
    if args.auth_header:
        return args.auth_header

    api_jwt = args.api_jwt or os.environ.get("BITSIGHT_API_JWT")
    if api_jwt:
        return f"bearer {api_jwt}"

    api_token = args.api_token or next((os.environ.get(name) for name in API_TOKEN_ENV_NAMES if os.environ.get(name)), None)
    if not api_token:
        names = " or ".join(API_TOKEN_ENV_NAMES)
        raise CliError(f"Missing API token or JWT. Set {names}, BITSIGHT_API_JWT, add it to .env, or pass --api-token/--api-jwt.")
    scheme = args.auth_scheme or os.environ.get("PORTAL_AUTH_SCHEME", "Basic")
    if scheme.lower() == "basic":
        encoded = base64.b64encode(f"{api_token}:".encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"
    return f"{scheme} {api_token}"


def request_json(
    base_url: str,
    path: str,
    params: dict[str, Any],
    auth_header: str,
    timeout: int,
) -> Any:
    clean_params = {key: value for key, value in params.items() if value is not None and value != ""}
    query = urlencode(clean_params, doseq=True)
    url = f"{base_url}/{path.lstrip('/')}"
    if query:
        url = f"{url}?{query}"

    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": auth_header,
            "User-Agent": "<bitsight-user-agent>",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise CliError(f"HTTP {exc.code} for {url}: {detail}") from exc
    except URLError as exc:
        raise CliError(f"Request failed for {url}: {exc}") from exc

    if not body:
        return None
    return json.loads(body)


def request_collection(
    args: argparse.Namespace,
    path: str,
    params: dict[str, Any],
    auth_header: str,
) -> Any:
    if not args.all_pages:
        return request_json(args.base_url, path, params, auth_header, args.timeout)

    limit = int(params.get("limit") or args.limit)
    offset = int(params.get("offset") or args.offset)
    all_rows: list[dict[str, Any]] = []
    first_payload: Any = None
    page_count = 0

    while True:
        page_params = dict(params)
        page_params["limit"] = limit
        page_params["offset"] = offset
        payload = request_json(args.base_url, path, page_params, auth_header, args.timeout)
        if first_payload is None:
            first_payload = payload

        rows = result_list(payload)
        all_rows.extend(rows)
        page_count += 1

        total_count = payload.get("count") if isinstance(payload, dict) else None
        has_next = bool(payload.get("next")) if isinstance(payload, dict) else len(rows) == limit
        if args.max_pages and page_count >= args.max_pages:
            break
        if total_count is not None and len(all_rows) >= int(total_count):
            break
        if not rows or len(rows) < limit or not has_next:
            break
        offset += limit

    if isinstance(first_payload, dict):
        merged = dict(first_payload)
        merged["results"] = all_rows
        merged["limit"] = limit
        merged["offset"] = int(params.get("offset") or args.offset)
        return merged
    return all_rows


def result_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return payload["results"]
    if isinstance(payload, list):
        return payload
    return []


def company_label(company: dict[str, Any]) -> str:
    name = company.get("name") or company.get("longname") or company.get("company_name") or "unknown"
    guid = company.get("guid") or company.get("company_guid") or "no-guid"
    details = company.get("details") or {}
    suffixes = []
    if details.get("in_portfolio") is not None:
        suffixes.append(f"in_portfolio={details.get('in_portfolio')}")
    if details.get("self_published") is not None:
        suffixes.append(f"self_published={details.get('self_published')}")
    if details.get("has_company_tree") is not None:
        suffixes.append(f"has_company_tree={details.get('has_company_tree')}")
    if details.get("is_primary") is not None:
        suffixes.append(f"is_primary={details.get('is_primary')}")
    if details.get("confidence") is not None:
        suffixes.append(f"confidence={details.get('confidence')}")
    primary_company = details.get("primary_company")
    if isinstance(primary_company, dict):
        primary_name = primary_company.get("name") or primary_company.get("longname")
        primary_guid = primary_company.get("guid")
        if primary_name or primary_guid:
            suffixes.append(f"primary_company={primary_name or primary_guid}")
    suffix = f" ({', '.join(suffixes)})" if suffixes else ""
    return f"{name} [{guid}]{suffix}"


def company_search_params(args: argparse.Namespace) -> dict[str, Any]:
    search_params: dict[str, Any] = {
        "limit": args.search_limit,
        "expand": "details",
        "in_portfolio": args.in_portfolio,
        "scope": args.scope,
    }
    if getattr(args, "company_guid", None):
        search_params["guids"] = args.company_guid
        if getattr(args, "include_non_sellable", None) is not None:
            search_params["include_non_sellable"] = args.include_non_sellable
        if getattr(args, "include_provisional", None) is not None:
            search_params["include_provisional"] = args.include_provisional
        if getattr(args, "include_low_confidence", None) is not None:
            search_params["include_low_confidence"] = args.include_low_confidence
    elif args.company_domain:
        search_params["domain"] = args.company
    else:
        search_params["name"] = args.company
    if getattr(args, "use_db", False):
        search_params["use_db"] = "true"
    return search_params


def search_companies(args: argparse.Namespace, auth_header: str) -> Any:
    if not (args.company or args.company_guid):
        raise CliError("Provide --company, --company --company-domain, or --company-guid.")
    return request_json(args.base_url, "companies/search", company_search_params(args), auth_header, args.timeout)


def resolve_company_guid(args: argparse.Namespace, auth_header: str) -> str:
    if args.company_guid:
        return args.company_guid
    if not args.company:
        raise CliError("Provide --company or --company-guid.")

    payload = search_companies(args, auth_header)
    matches = result_list(payload)
    if not matches:
        raise CliError(f"No company matched {args.company!r}.")

    guid_keys = ("guid", "company_guid")
    if args.select_guid:
        for match in matches:
            if args.select_guid in [str(match.get(key, "")) for key in guid_keys]:
                return args.select_guid
        raise CliError(f"--select-guid {args.select_guid!r} was not found in search results.")

    if len(matches) == 1:
        guid = next((matches[0].get(key) for key in guid_keys if matches[0].get(key)), None)
        if guid:
            # Surface the matched company so the caller can verify it is the intended entity
            # (a unique search hit is not proof of the correct company).
            print(f"SINGLE_MATCH: {company_label(matches[0])} — verify this is the intended company "
                  "before proceeding. If not, refine --company or pass --select-guid <guid>.",
                  file=sys.stderr)
            return str(guid)

    if args.company_index is not None:
        if args.company_index < 1 or args.company_index > len(matches):
            raise CliError(f"--company-index must be between 1 and {len(matches)}.")
        selected = matches[args.company_index - 1]
        guid = next((selected.get(key) for key in guid_keys if selected.get(key)), None)
        if guid:
            return str(guid)

    print("AMBIGUOUS_COMPANY: multiple companies matched. Present this list to the user and ask "
          "them to specify the intended company by GUID. Re-run with --select-guid <guid>:",
          file=sys.stderr)
    for index, match in enumerate(matches, start=1):
        print(f"{index}. {company_label(match)}", file=sys.stderr)
    raise CliError("Company name is ambiguous.")


def add_pagination_and_fields(params: dict[str, Any], args: argparse.Namespace) -> None:
    params["limit"] = args.limit
    params["offset"] = args.offset
    if args.fields:
        params["fields"] = args.fields
    if args.expand:
        params["expand"] = args.expand
    if args.sort:
        params["sort"] = args.sort


def command_assets(args: argparse.Namespace, auth_header: str) -> Any:
    guid = resolve_company_guid(args, auth_header)
    params = parse_key_value(args.filter)
    add_pagination_and_fields(params, args)
    return request_collection(args, f"companies/{guid}/assets", params, auth_header)


def command_companies(args: argparse.Namespace, auth_header: str) -> Any:
    return search_companies(args, auth_header)


def command_company_tree(args: argparse.Namespace, auth_header: str) -> Any:
    guid = resolve_company_guid(args, auth_header)
    if args.guids_only:
        params = {
            "q": args.tree_query,
            "name": args.tree_name,
            "domain": args.tree_domain,
            "ip": args.tree_ip,
        }
        return request_json(
            args.base_url,
            f"companies/{guid}/company-tree/guids",
            params,
            auth_header,
            args.timeout,
        )

    params = {"expand": args.expand}
    return request_json(args.base_url, f"companies/{guid}/company-tree", params, auth_header, args.timeout)


def command_findings(args: argparse.Namespace, auth_header: str) -> Any:
    guid = resolve_company_guid(args, auth_header)
    params = parse_key_value(args.filter)
    add_pagination_and_fields(params, args)
    params.update(
        {
            "risk_vector": args.risk_vector,
            "risk_category": args.risk_category,
            "severity_category": args.severity_category,
            "assets__asset": args.asset,
            "assets__combined_importance": args.asset_importance,
            "assets__is_monitored": args.asset_is_monitored,
            "vulnerabilities": args.vulnerability,
            "q": args.query,
        }
    )
    return request_collection(args, f"companies/{guid}/findings", params, auth_header)


def command_finding_filters(args: argparse.Namespace, auth_header: str) -> Any:
    guid = resolve_company_guid(args, auth_header)
    return request_json(args.base_url, f"companies/{guid}/findings/filters", {}, auth_header, args.timeout)


def command_vulnerabilities(args: argparse.Namespace, auth_header: str) -> Any:
    if args.portfolio:
        raise CliError("Portfolio vulnerability lookups are no longer supported here; use company findings instead.")
    if not (args.company or args.company_guid):
        raise CliError("Vulnerability/CVE lookups require --company or --company-guid so findings can expose CVE data.")
    if args.status:
        raise CliError("--status is only available on the vulnerability catalog endpoint, not company findings.")
    if args.support_started:
        raise CliError("--support-started is only available on the vulnerability catalog endpoint, not company findings.")

    params = parse_key_value(args.filter)
    if args.summary != "raw" and not args.fields:
        args.fields = DEFAULT_VULNERABILITY_FIELDS
    if args.default_expand and not args.expand:
        args.expand = DEFAULT_VULNERABILITY_EXPAND
    add_pagination_and_fields(params, args)
    params.update(
        {
            "q": args.query,
            "risk_vector": args.risk_vector or ("open_ports" if args.open_ports else None),
            "assets__asset": args.asset,
            "assets__identifier": args.asset_identifier,
            "assets__combined_importance": args.asset_importance,
            "assets__is_monitored": args.asset_is_monitored,
            "observed_ips_contains": args.observed_ip,
            "impacts_risk_vector_details": args.impacts_risk_vector_details,
            "cvss__base": args.cvss_base,
        }
    )
    if args.vulnerability or args.cve:
        params["vulnerabilities"] = args.vulnerability or args.cve
    if args.severity:
        params["details.vulnerabilities.severity"] = args.severity.lower()

    guid = resolve_company_guid(args, auth_header)
    payload = request_collection(args, f"companies/{guid}/findings", params, auth_header)
    payload = apply_client_side_vulnerability_filters(payload, args)
    if args.summary == "raw":
        return payload
    return summarize_vulnerabilities(payload, args.summary)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_present(data: dict[str, Any], keys: tuple[str, ...]) -> Any:
    return next((data[key] for key in keys if data.get(key) not in (None, "")), None)


def extract_cvss(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("base")
    return value


def cve_from_values(*values: Any) -> str | None:
    for value in values:
        if not value:
            continue
        match = CVE_PATTERN.search(str(value))
        if match:
            return match.group(0).upper()
    return None


def extract_assets(finding: dict[str, Any]) -> list[dict[str, Any]]:
    assets = []
    for asset in as_list(finding.get("assets")):
        if not isinstance(asset, dict):
            assets.append({"asset": str(asset)})
            continue
        value = first_present(asset, ("asset", "masked_asset", "name", "identifier", "ip_address"))
        if not value:
            continue
        assets.append(
            {
                "asset": str(value),
                "identifier": first_present(asset, ("identifier", "asset_identifier")),
                "category": first_present(asset, ("category", "asset_type")),
                "importance": first_present(
                    asset,
                    ("combined_importance", "importance_category", "importance"),
                ),
                "is_monitored": asset.get("is_monitored"),
            }
        )
    return assets


def normalize_vulnerability(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        cve = cve_from_values(raw)
        return {"cve": cve, "name": str(raw)} if cve else None

    catalog = raw.get("cve") if isinstance(raw.get("cve"), dict) else {}
    name = first_present(raw, ("name", "id", "cve_id")) or first_present(catalog, ("name", "id"))
    alias = first_present(raw, ("alias",)) or first_present(catalog, ("alias",))
    display_name = first_present(raw, ("display_name", "displayName")) or first_present(
        catalog,
        ("display_name", "displayName"),
    )
    cve = cve_from_values(name, alias, display_name)
    if not cve:
        return None
    return {
        "cve": cve,
        "name": name,
        "alias": alias,
        "display_name": display_name,
        "severity": first_present(raw, ("severity",)) or first_present(catalog, ("severity",)),
        "confidence": first_present(raw, ("confidence",)) or first_present(catalog, ("confidence",)),
        "cvss": extract_cvss(first_present(raw, ("cvss",)) or first_present(catalog, ("cvss",))),
    }


def extract_vulnerabilities(finding: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[Any] = []
    details = finding.get("details") if isinstance(finding.get("details"), dict) else {}
    candidates.extend(as_list(details.get("vulnerabilities")))
    candidates.extend(as_list(finding.get("vulnerabilities")))

    seen: set[str] = set()
    vulnerabilities = []
    for candidate in candidates:
        normalized = normalize_vulnerability(candidate)
        if not normalized or normalized["cve"] in seen:
            continue
        seen.add(normalized["cve"])
        vulnerabilities.append(normalized)

    if vulnerabilities:
        return vulnerabilities

    for cve in sorted({match.group(0).upper() for match in CVE_PATTERN.finditer(json.dumps(finding))}):
        vulnerabilities.append({"cve": cve, "name": cve})
    return vulnerabilities


def apply_client_side_vulnerability_filters(payload: Any, args: argparse.Namespace) -> Any:
    if not args.confidence:
        return payload

    requested_confidences = {value.strip().upper() for value in args.confidence.split(",") if value.strip()}
    filtered_rows = [
        row
        for row in result_list(payload)
        if any(
            str(vulnerability.get("confidence", "")).upper() in requested_confidences
            for vulnerability in extract_vulnerabilities(row)
        )
    ]

    if isinstance(payload, dict):
        filtered_payload = dict(payload)
        filtered_payload["results"] = filtered_rows
        filtered_payload["count"] = len(filtered_rows)
        filtered_payload["links"] = {"next": None, "previous": None}
        filtered_payload["next"] = None
        filtered_payload["previous"] = None
        return filtered_payload
    return filtered_rows


def summarize_vulnerabilities(payload: Any, summary: str) -> dict[str, Any]:
    rows = result_list(payload)
    cves: dict[str, dict[str, Any]] = {}
    assets: dict[str, dict[str, Any]] = {}

    for finding in rows:
        finding_id = str(
            first_present(finding, ("evidence_key", "rolledup_observation_id", "temporary_id")) or ""
        )
        finding_assets = extract_assets(finding)
        finding_vulnerabilities = extract_vulnerabilities(finding)
        for vulnerability in finding_vulnerabilities:
            cve = vulnerability["cve"]
            cve_entry = cves.setdefault(
                cve,
                {
                    "cve": cve,
                    "finding_count": 0,
                    "assets": set(),
                    "severities": set(),
                    "confidences": set(),
                    "cvss": set(),
                    "examples": [],
                },
            )
            cve_entry["finding_count"] += 1
            if vulnerability.get("severity"):
                cve_entry["severities"].add(str(vulnerability["severity"]))
            if vulnerability.get("confidence"):
                cve_entry["confidences"].add(str(vulnerability["confidence"]))
            if vulnerability.get("cvss") is not None:
                cve_entry["cvss"].add(str(vulnerability["cvss"]))
            if finding_id and len(cve_entry["examples"]) < 5:
                cve_entry["examples"].append(finding_id)

            for asset in finding_assets:
                asset_name = asset["asset"]
                cve_entry["assets"].add(asset_name)
                asset_entry = assets.setdefault(
                    asset_name,
                    {
                        "asset": asset_name,
                        "identifier": asset.get("identifier"),
                        "category": asset.get("category"),
                        "importance": asset.get("importance"),
                        "is_monitored": asset.get("is_monitored"),
                        "finding_count": 0,
                        "cves": set(),
                    },
                )
                asset_entry["finding_count"] += 1
                asset_entry["cves"].add(cve)

    serializable_cves = []
    for entry in cves.values():
        serializable_cves.append(
            {
                "cve": entry["cve"],
                "finding_count": entry["finding_count"],
                "asset_count": len(entry["assets"]),
                "assets": sorted(entry["assets"]),
                "severities": sorted(entry["severities"]),
                "confidences": sorted(entry["confidences"]),
                "cvss": sorted(entry["cvss"]),
                "example_findings": entry["examples"],
            }
        )
    serializable_cves.sort(key=lambda item: (-item["finding_count"], item["cve"]))

    serializable_assets = []
    for entry in assets.values():
        serializable_assets.append(
            {
                "asset": entry["asset"],
                "identifier": entry["identifier"],
                "category": entry["category"],
                "importance": entry["importance"],
                "is_monitored": entry["is_monitored"],
                "finding_count": entry["finding_count"],
                "cves": sorted(entry["cves"]),
                "cve_count": len(entry["cves"]),
            }
        )
    serializable_assets.sort(key=lambda item: (-item["cve_count"], -item["finding_count"], item["asset"]))

    result = {
        "summary": summary,
        "finding_count": len(rows),
        "cve_count": len(serializable_cves),
    }
    if summary == "cves":
        result["cves"] = serializable_cves
    elif summary == "assets":
        result["assets"] = serializable_assets
    else:
        result["cves"] = serializable_cves
        result["assets"] = serializable_assets
    return result


def emit_csv(payload: Any) -> None:
    rows = result_list(payload)
    if not rows:
        return
    fieldnames = sorted({key for row in rows for key in row.keys()})
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)


def emit(payload: Any, output: str) -> None:
    if output == "csv":
        emit_csv(payload)
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default=os.environ.get("PORTAL_API_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--api-token", default=None,
                        help="Bitsight API token (HTTP Basic auth)")
    parser.add_argument("--api-jwt", default=None,
                        help="Bitsight API JWT (bearer auth, overrides --api-token)")
    parser.add_argument("--auth-scheme", default=None, help="Default: Basic. Set to Token/Bearer/etc. if needed.")
    parser.add_argument("--auth-header", default=os.environ.get("PORTAL_AUTH_HEADER"), help="Raw Authorization header.")
    parser.add_argument("--env-file", default=None)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--output", choices=("json", "csv"), default="json")


def add_company(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--company", help="Company name or domain to resolve.")
    parser.add_argument("--company-guid", help="Company GUID; skips name resolution.")
    parser.add_argument("--company-domain", action="store_true", help="Resolve --company using company search domain.")
    parser.add_argument("--company-index", type=int, help="1-based choice when company search returns multiple matches.")
    parser.add_argument("--select-guid", help="GUID to select from ambiguous company search results.")
    parser.add_argument("--search-limit", type=int, default=10)
    parser.add_argument("--in-portfolio", choices=("true", "false"), default=None)
    parser.add_argument("--scope", default=None, help="Optional search scope such as spm.")


def add_company_search_overrides(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include-non-sellable", choices=("true", "false"), default=None, help="Search GUIDs that may resolve to private/non-sellable companies.")
    parser.add_argument("--include-provisional", choices=("true", "false"), default=None, help="Include provisional companies when searching by GUID.")
    parser.add_argument("--include-low-confidence", choices=("true", "false"), default=None, help="Include low-confidence companies when searching by GUID.")
    parser.add_argument("--use-db", action="store_true", help="Use DB-backed company search instead of OpenSearch.")


def add_query_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--filter", action="append", default=[], help="Raw API query filter as key=value. Repeatable.")
    parser.add_argument("--fields", help="Comma-separated field selection.")
    parser.add_argument("--expand", help="Comma-separated expansion selection.")
    parser.add_argument("--sort", help="Comma-separated sort fields, prefix with - for descending. Must use = syntax: --sort=-last_seen (space form --sort -last_seen fails because argparse treats the leading dash as a flag).")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--all-pages", action="store_true", help="Fetch every page before emitting output.")
    parser.add_argument("--max-pages", type=int, default=None, help="Safety cap used with --all-pages.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query Portal Customer API resources.")
    add_common(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    assets = subparsers.add_parser("assets", help="Get assets for a company.")
    add_company(assets)
    add_query_options(assets)
    assets.set_defaults(func=command_assets)

    companies = subparsers.add_parser("companies", help="Search companies and show disambiguation details.")
    add_company(companies)
    add_company_search_overrides(companies)
    companies.set_defaults(func=command_companies)

    company_tree = subparsers.add_parser("company-tree", help="Inspect the company tree for a company.")
    add_company(company_tree)
    company_tree.add_argument("--expand", default="confidence", help="Comma-separated tree expansions, e.g. confidence,is_shell.")
    company_tree.add_argument("--guids-only", action="store_true", help="Return only visible GUIDs in the tree.")
    company_tree.add_argument("--tree-query", help="Filter tree GUIDs by q terms.")
    company_tree.add_argument("--tree-name", help="Filter tree GUIDs by company name prefix.")
    company_tree.add_argument("--tree-domain", help="Filter tree GUIDs by domain or website.")
    company_tree.add_argument("--tree-ip", help="Filter tree GUIDs by IP address.")
    company_tree.set_defaults(func=command_company_tree)

    findings = subparsers.add_parser("findings", help="Get findings for a company.")
    add_company(findings)
    add_query_options(findings)
    findings.add_argument("--risk-vector")
    findings.add_argument("--risk-category")
    findings.add_argument("--severity-category")
    findings.add_argument("--asset")
    findings.add_argument("--asset-importance")
    findings.add_argument("--asset-is-monitored", choices=("true", "false"))
    findings.add_argument("--vulnerability")
    findings.add_argument("--query")
    findings.set_defaults(func=command_findings)

    portal_urls = subparsers.add_parser("portal-urls", help="Build browser URLs for Bitsight portal pages.")
    add_company(portal_urls)
    portal_urls.add_argument("--portal-product", choices=("cm", "spm", "both"), default="cm", help="Portal product URL family. Default: cm.")
    portal_urls.add_argument("--portal-app-url", default=os.environ.get("PORTAL_APP_URL"), help=f"Override portal app URL. Default for cm: {DEFAULT_PORTAL_APP_URL}.")
    portal_urls.add_argument("--risk-vector", action="append", default=[], help="Risk vector slug or label. Repeatable; comma-separated values are accepted.")
    portal_urls.add_argument("--asset", action="append", default=[], help="Asset hostname, domain, IP, or search term. Repeatable; comma-separated values are accepted.")
    portal_urls.add_argument("--affects-rating", action="store_true", help="Add AFFECTS_RATING to generated risk-vector finding links.")
    portal_urls.add_argument("--vulnerability", action="append", default=[], help="CVE ID, vulnerability name, or alias. Repeatable; comma-separated values are accepted.")
    portal_urls.add_argument("--cve", action="append", default=[], help="Alias for --vulnerability.")
    portal_urls.add_argument("--report-minimum", action="store_true", help="Include the minimum risk-vector links needed for the sample posture report. Add asset links with --asset.")
    portal_urls.set_defaults(func=command_portal_urls)

    finding_filters = subparsers.add_parser("finding-filters", help="Get available finding filter values for a company.")
    add_company(finding_filters)
    finding_filters.set_defaults(func=command_finding_filters)

    vulns = subparsers.add_parser("vulnerabilities", help="Get company findings with vulnerability/CVE data.")
    add_company(vulns)
    add_query_options(vulns)
    vulns.add_argument("--portfolio", action="store_true", help=argparse.SUPPRESS)
    vulns.add_argument("--query")
    vulns.add_argument("--severity", help="Server-side filter by details.vulnerabilities.severity, e.g. severe.")
    vulns.add_argument("--status", help=argparse.SUPPRESS)
    vulns.add_argument("--confidence", help="Client-side filter by vulnerability confidence; combine with server-side filters or --all-pages.")
    vulns.add_argument("--support-started", help=argparse.SUPPRESS)
    vulns.add_argument("--vulnerability", help="Server-side filter findings by CVE/name/alias through vulnerabilities.")
    vulns.add_argument("--cve", help="Alias for --vulnerability.")
    vulns.add_argument("--risk-vector", help="Filter findings by risk vector, commonly open_ports for CVEs.")
    vulns.add_argument("--open-ports", action="store_true", help="Shortcut for --risk-vector open_ports.")
    vulns.add_argument("--asset", help="Filter vulnerability findings by asset.")
    vulns.add_argument("--asset-identifier", help="Filter vulnerability findings by asset identifier.")
    vulns.add_argument("--asset-importance", help="Filter vulnerability findings by asset importance.")
    vulns.add_argument("--asset-is-monitored", choices=("true", "false"), help="Filter vulnerability findings by monitored asset status.")
    vulns.add_argument("--observed-ip", help="Filter findings by observed IP substring.")
    vulns.add_argument("--impacts-risk-vector-details", help="Filter by impact reason, e.g. AFFECTS_RATING.")
    vulns.add_argument("--cvss-base", help="Filter by cvss__base range expression accepted by the API.")
    vulns.add_argument("--default-expand", action="store_true", help="Use the standard findings expansions for vulnerability investigations.")
    vulns.add_argument("--summary", choices=("raw", "cves", "assets", "both"), default="raw", help="Summarize raw findings into CVE and/or asset groupings.")
    vulns.set_defaults(func=command_vulnerabilities)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    load_dotenv(Path(__file__).resolve().parent, args.env_file)

    # If JWT is provided, extract api_base from it
    api_jwt = args.api_jwt or os.environ.get("BITSIGHT_API_JWT")
    if api_jwt:
        auth_info = AuthInfo(api_jwt=api_jwt)
        jwt_api_base = auth_info.get_api_base()
        if jwt_api_base and not os.environ.get("PORTAL_API_BASE_URL"):
            args.base_url = jwt_api_base

    args.base_url = normalize_base_url(args.base_url)
    try:
        auth_header = None
        if args.command != "portal-urls" or not args.company_guid:
            auth_header = make_auth_header(args)
        payload = args.func(args, auth_header)
        emit(payload, args.output)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
