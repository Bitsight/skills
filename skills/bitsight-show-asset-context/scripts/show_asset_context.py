#!/usr/bin/env python3
"""Project own-org (SPM) assets to a compact operational-context object.

For each first-party asset it returns what is *running* on the asset — customer
tags, cloud provider/region/service, identified products (with a derived
EOL/obsolete support_risk), and network services — plus the flags is_cloud and
has_obsolete_product, and a portfolio-wide summary. It is the "what runs on my
assets / show me everything about IP X" lens over GET /v1/companies/{guid}/assets.

Auth: set BITSIGHT_API_TOKEN (or BITSIGHT_API_JWT) in the environment or a .env
file; the token is confidential and is never printed. See --help for usage.

Required libraries: none (Python standard library only)."""

from __future__ import annotations

import argparse
import base64
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
SKILL_VERSION = "2026.243"
DEFAULT_HOST = "https://api.bitsighttech.com"
PAGE_SIZE = 1000

# Support status (from the assets API `product.support` enum) → operational risk.
# unknown MUST map to "unknown", never "none": absence of information is not a
# clean bill of health (the hard unknown != absent guard).
PRODUCT_SUPPORT_RISK = {
    "obsolete-version": "high",
    "obsolete-package": "high",
    "obsolete-os-release": "high",
    "unknown-patch-status": "medium",
    "possible-backports": "medium",
    "incomplete-version": "low",
    "current-version": "none",
    "current-package": "none",
    "unknown": "unknown",
}
SUPPORT_CHOICES = [
    "current-version", "current-package", "obsolete-package", "obsolete-version",
    "obsolete-os-release", "unknown-patch-status", "possible-backports",
    "incomplete-version", "unknown",
]
IMPORTANCE_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

# Fields requested from the assets endpoint. tags + cloud_context need no
# entitlement; products + services require Infrastructure Analytics.
ASSET_FIELDS = (
    "asset,asset_type,is_ip,identifier,importance_category,is_monitored,"
    "ip_addresses,tags,cloud_context,products,services"
)
ASSET_EXPAND = "tag_details"


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
# Own-org resolution
# ---------------------------------------------------------------------------

def resolve_my_company(base: str, headers: dict, timeout: int, retries: int) -> dict:
    """GET /v1/users/current → customer.my_company_guid (the canonical own-org id)."""
    payload = http_get_json(build_url(base, "/v1/users/current", {"fields": "customer"}),
                            headers, timeout, retries)
    customer = (payload or {}).get("customer") or {}
    guid = customer.get("my_company_guid") or ""
    if not guid:
        raise CliError(
            "Could not resolve your organization's company GUID from /v1/users/current; "
            "pass --company-guid explicitly.",
            "NO_COMPANY", 2)
    return {"guid": guid, "name": customer.get("name") or ""}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalise_cloud_context(raw: Any) -> dict | None:
    if not isinstance(raw, dict):
        return None
    provider = raw.get("provider") or {}
    regions = raw.get("region") or []
    services = raw.get("service") or []
    if not isinstance(regions, list):
        regions = [regions]
    if not isinstance(services, list):
        services = [services]
    if not provider.get("slug") and not provider.get("name") and not regions and not services:
        return None
    return {
        "provider_name": provider.get("name", ""),
        "provider_slug": provider.get("slug", ""),
        "regions": regions,
        "services": services,
    }


def normalise_products(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        support = p.get("support") or "unknown"
        out.append({
            "product": p.get("product", ""),
            "vendor": p.get("vendor", ""),
            "version": p.get("version") or "",
            "type": p.get("type", ""),
            "support": support,
            "support_risk": PRODUCT_SUPPORT_RISK.get(support, "unknown"),
            "first_seen": p.get("first_seen"),
            "last_seen": p.get("last_seen"),
        })
    return out


def normalise_tag_details(raw: Any) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out = []
    for t in raw:
        if not isinstance(t, dict):
            continue
        out.append({
            "guid": t.get("guid", ""),
            "name": t.get("name", ""),
            "is_public": bool(t.get("is_public", False)),
            "is_inherited": bool(t.get("is_inherited", False)),
        })
    return out


def project_asset(raw: dict) -> dict:
    products = normalise_products(raw.get("products"))
    cloud = normalise_cloud_context(raw.get("cloud_context"))
    services = raw.get("services") if isinstance(raw.get("services"), list) else []
    tags = raw.get("tags") if isinstance(raw.get("tags"), list) else []
    return {
        "asset": raw.get("asset", ""),
        "asset_type": raw.get("asset_type", ""),
        "is_ip": bool(raw.get("is_ip", False)),
        "identifier": raw.get("identifier", ""),
        "importance": raw.get("importance_category") or "unknown",
        "is_monitored": bool(raw.get("is_monitored", False)),
        "ip_addresses": raw.get("ip_addresses") or [],
        "tags": tags,
        "tag_details": normalise_tag_details(raw.get("tag_details")),
        "cloud_context": cloud,
        "is_cloud": cloud is not None,
        "products": products,
        "product_count": len(products),
        "has_obsolete_product": any(p["support_risk"] == "high" for p in products),
        "services": services,
        "service_count": len(services),
    }


# ---------------------------------------------------------------------------
# Fetch + client-side filters
# ---------------------------------------------------------------------------

def matches_cloud(record: dict, provider: str | None, region: str | None, service: str | None) -> bool:
    """cloud_context.* filters are silently ignored server-side (verified against
    the live API), so they are enforced here, client-side."""
    cloud = record.get("cloud_context")
    if not cloud:
        return False
    if provider and provider.lower() not in {
        str(cloud.get("provider_slug", "")).lower(),
        str(cloud.get("provider_name", "")).lower(),
    }:
        return False
    if region and region.lower() not in {str(r).lower() for r in cloud.get("regions", [])}:
        return False
    if service and service.lower() not in {str(s).lower() for s in cloud.get("services", [])}:
        return False
    return True


def matches_tag(record: dict, tag: str) -> bool:
    needle = tag.lower()
    return (any(str(t).lower() == needle for t in record.get("tags", []))
            or any(td.get("name", "").lower() == needle for td in record.get("tag_details", [])))


def fetch_context(base: str, headers: dict, guid: str, server_filters: dict,
                  args: argparse.Namespace) -> dict:
    """Page through the assets endpoint, projecting and applying client-side filters."""
    cloud_active = bool(args.cloud_provider or args.cloud_region or args.cloud_service)
    tag_active = bool(args.tag)
    client_active = cloud_active or tag_active
    limit = args.limit  # 0 = no cap on returned records

    records: list[dict] = []
    scanned = 0
    total: int | None = None
    offset = 0
    truncated = False

    path = f"/v1/companies/{guid}/assets"
    while True:
        params = dict(server_filters)
        params.update({
            "fields": ASSET_FIELDS,
            "expand": ASSET_EXPAND,
            "limit": PAGE_SIZE,
            "offset": offset,
        })
        payload = http_get_json(build_url(base, path, params), headers, args.timeout, args.retries)
        page = (payload or {}).get("results") if isinstance(payload, dict) else None
        page = page or []
        if total is None and isinstance(payload, dict):
            total = payload.get("count")

        for raw in page:
            record = project_asset(raw)
            if cloud_active and not matches_cloud(record, args.cloud_provider,
                                                  args.cloud_region, args.cloud_service):
                continue
            if tag_active and not matches_tag(record, args.tag):
                continue
            records.append(record)
            if limit and len(records) >= limit:
                break

        scanned += len(page)
        if limit and len(records) >= limit:
            # More may remain only if we stopped mid-scan.
            truncated = (total is not None and scanned < total) or len(page) == PAGE_SIZE
            break
        if not page or (total is not None and scanned >= total):
            break
        if client_active and args.max_scan and scanned >= args.max_scan:
            truncated = total is not None and scanned < total
            break
        offset += PAGE_SIZE

    records.sort(key=lambda r: (IMPORTANCE_RANK.get(r["importance"], 4), r["asset"]))
    return {"records": records, "scanned": scanned, "total": total, "truncated": truncated}


# ---------------------------------------------------------------------------
# Summary + availability
# ---------------------------------------------------------------------------

def context_availability(records: list[dict]) -> dict:
    has_products = any(r["product_count"] > 0 for r in records)
    has_services = any(r["service_count"] > 0 for r in records)
    return {
        "tags": any(r["tags"] for r in records),
        "cloud_context": any(r["is_cloud"] for r in records),
        "products": has_products,
        "services": has_services,
        "infrastructure_analytics_fields_populated": has_products or has_services,
    }


def summarize(records: list[dict]) -> dict:
    cloud_providers: dict[str, int] = {}
    service_counts: dict[str, int] = {}
    product_vendors: dict[str, int] = {}
    obsolete_assets: list[str] = []
    tagged = 0
    cloud_assets = 0
    for r in records:
        if r["tags"]:
            tagged += 1
        if r["is_cloud"]:
            cloud_assets += 1
            slug = r["cloud_context"].get("provider_slug") or r["cloud_context"].get("provider_name") or "unknown"
            cloud_providers[slug] = cloud_providers.get(slug, 0) + 1
        for svc in r["services"]:
            service_counts[svc] = service_counts.get(svc, 0) + 1
        for p in r["products"]:
            vendor = p.get("vendor") or "unknown"
            product_vendors[vendor] = product_vendors.get(vendor, 0) + 1
        if r["has_obsolete_product"]:
            obsolete_assets.append(r["asset"])
    top = lambda d, n=10: sorted(d.items(), key=lambda x: (-x[1], x[0]))[:n]
    return {
        "total_tagged": tagged,
        "total_cloud": cloud_assets,
        "cloud_providers": [{"slug": k, "asset_count": v} for k, v in top(cloud_providers)],
        "top_services": [{"service": k, "asset_count": v} for k, v in top(service_counts)],
        "top_product_vendors": [{"vendor": k, "asset_count": v} for k, v in top(product_vendors)],
        "assets_with_obsolete_products": sorted(obsolete_assets),
        "obsolete_product_count": len(obsolete_assets),
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_server_filters(args: argparse.Namespace) -> dict:
    filters: dict[str, Any] = {}
    if args.asset:
        filters["asset"] = args.asset
    if args.ip_address:
        filters["ip_address"] = args.ip_address
    if args.asset_kind == "ip":
        filters["is_ip"] = "true"
    elif args.asset_kind == "domain":
        filters["is_ip"] = "false"
    if args.importance:
        filters["importance_categories"] = ",".join(args.importance)
    if args.monitored_only:
        filters["is_monitored"] = "true"
    if args.service:
        filters["services"] = args.service
    if args.product_vendor:
        filters["product.vendor"] = args.product_vendor
    if args.product_support:
        filters["product.support"] = args.product_support
    return filters


def run(args: argparse.Namespace) -> dict:
    api_jwt = args.api_jwt or os.getenv("BITSIGHT_API_JWT")
    api_token = args.api_token or os.getenv("BITSIGHT_API_TOKEN")
    if not api_jwt and not api_token:
        raise CliError(
            "No Bitsight credential found. Provide BITSIGHT_API_JWT or "
            "BITSIGHT_API_TOKEN (environment, .env, or --api-jwt/--api-token).",
            "MISSING_CREDENTIALS", 2)

    base = resolve_base_url(api_jwt)
    headers = auth_headers(api_jwt, api_token)

    company_guid = args.company_guid or ""
    company_name = ""
    if not company_guid:
        me = resolve_my_company(base, headers, args.timeout, args.retries)
        company_guid, company_name = me["guid"], me["name"]

    server_filters = build_server_filters(args)
    fetched = fetch_context(base, headers, company_guid, server_filters, args)
    records = fetched["records"]

    availability = context_availability(records)
    notes: list[str] = []
    if (args.cloud_provider or args.cloud_region or args.cloud_service):
        notes.append(
            "cloud_context filters are enforced client-side because the assets API "
            "silently ignores them server-side; results reflect the scanned set only.")
    if records and not availability["infrastructure_analytics_fields_populated"]:
        notes.append(
            "products/services are empty — Infrastructure Analytics may not be enabled for "
            "this tenant. Absence of products does NOT mean an asset has none (unknown != absent).")
    if fetched["truncated"]:
        notes.append(
            f"result set truncated: scanned {fetched['scanned']} of {fetched['total']} assets. "
            "Raise --limit / --max-scan or narrow the filters for full coverage.")

    return {
        "success": True,
        "skill_version": SKILL_VERSION,
        "company_guid": company_guid,
        "company_name": company_name,
        "total_assets": len(records),
        "scanned_assets": fetched["scanned"],
        "total_available": fetched["total"],
        "truncated": fetched["truncated"],
        "filters_applied": {
            **server_filters,
            **({"cloud_context.provider_slug": args.cloud_provider} if args.cloud_provider else {}),
            **({"cloud_context.region": args.cloud_region} if args.cloud_region else {}),
            **({"cloud_context.service": args.cloud_service} if args.cloud_service else {}),
            **({"tag": args.tag} if args.tag else {}),
        },
        "context_availability": availability,
        "summary": summarize(records),
        "notes": notes,
        "assets": records,
    }


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------

def render_text(result: dict) -> str:
    lines: list[str] = []
    who = result.get("company_name") or result.get("company_guid")
    lines.append(f"Asset context for {who}")
    lines.append(f"  assets returned: {result['total_assets']}  "
                 f"(scanned {result['scanned_assets']} of {result.get('total_available')})")
    if result["truncated"]:
        lines.append("  ** results truncated — see notes **")
    s = result["summary"]
    lines.append(f"  tagged: {s['total_tagged']}   cloud: {s['total_cloud']}   "
                 f"assets with obsolete products: {s['obsolete_product_count']}")
    if s["cloud_providers"]:
        lines.append("  cloud providers: " +
                     ", ".join(f"{c['slug']}({c['asset_count']})" for c in s["cloud_providers"]))
    if s["top_product_vendors"]:
        lines.append("  top product vendors: " +
                     ", ".join(f"{v['vendor']}({v['asset_count']})" for v in s["top_product_vendors"][:5]))
    if s["top_services"]:
        lines.append("  top services: " +
                     ", ".join(f"{v['service']}({v['asset_count']})" for v in s["top_services"][:5]))
    for note in result.get("notes", []):
        lines.append(f"  note: {note}")
    lines.append("")
    for r in result["assets"][:50]:
        flags = []
        if r["is_cloud"]:
            flags.append("cloud")
        if r["has_obsolete_product"]:
            flags.append("obsolete-product")
        flag_str = f" [{', '.join(flags)}]" if flags else ""
        lines.append(f"- {r['asset']} ({r['importance']}, {r['asset_type']}){flag_str}")
        if r["tags"]:
            lines.append(f"    tags: {', '.join(map(str, r['tags']))}")
        if r["is_cloud"]:
            c = r["cloud_context"]
            region = ",".join(c["regions"]) or "-"
            lines.append(f"    cloud: {c['provider_slug'] or c['provider_name']} region={region}")
        if r["product_count"]:
            lines.append(f"    products: {r['product_count']}"
                         + (f" (obsolete present)" if r["has_obsolete_product"] else ""))
        if r["service_count"]:
            lines.append(f"    services: {', '.join(map(str, r['services'][:8]))}")
    if len(result["assets"]) > 50:
        lines.append(f"  … and {len(result['assets']) - 50} more (see JSON output)")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("asset", nargs="?",
                   help="Optional asset (hostname or IP) to focus on, e.g. an IP you want "
                        "'everything about'. Shortcut for --asset.")
    p.add_argument("--company-guid",
                   help="Own-org company GUID. If omitted, resolved from /v1/users/current.")
    p.add_argument("--asset", dest="asset_opt", help="Filter to a single asset name (hostname or IP).")
    p.add_argument("--ip-address", dest="ip_address", help="Filter by IP address.")
    p.add_argument("--asset-kind", choices=["ip", "domain", "all"], default="all",
                   help="Restrict to IPs, domains, or all (default: all).")
    p.add_argument("--importance", action="append", choices=["critical", "high", "medium", "low"],
                   help="Filter by importance category. Repeatable.")
    p.add_argument("--monitored-only", dest="monitored_only", action="store_true",
                   help="Return only monitored assets.")
    p.add_argument("--tag", help="Filter to assets carrying this tag name (matched client-side).")
    p.add_argument("--service", help="Filter by network service name (e.g. HTTPS). "
                                      "Requires Infrastructure Analytics.")
    p.add_argument("--product-vendor", dest="product_vendor",
                   help="Filter by identified product vendor. Requires Infrastructure Analytics.")
    p.add_argument("--product-support", dest="product_support", choices=SUPPORT_CHOICES,
                   help="Filter by product support status. Requires Infrastructure Analytics.")
    p.add_argument("--cloud-provider", dest="cloud_provider",
                   help="Filter by cloud provider slug/name (e.g. aws). Enforced client-side.")
    p.add_argument("--cloud-region", dest="cloud_region",
                   help="Filter by cloud region. Enforced client-side.")
    p.add_argument("--cloud-service", dest="cloud_service",
                   help="Filter by cloud service. Enforced client-side.")
    p.add_argument("--limit", type=int, default=1000,
                   help="Max asset context records to return (default 1000; 0 = no cap).")
    p.add_argument("--max-scan", type=int, default=10000,
                   help="Safety cap on assets scanned when a client-side (cloud/tag) filter is "
                        "active (default 10000; 0 = no cap).")
    p.add_argument("--format", choices=["json", "text"], default="json")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--retries", type=int, default=3,
                   help="HTTP retry attempts on 429/5xx/network errors.")
    p.add_argument("--api-token", help="Override BITSIGHT_API_TOKEN.")
    p.add_argument("--api-jwt", help="Override BITSIGHT_API_JWT (bearer; outranks the token).")
    args = p.parse_args(argv)
    # Positional asset is a shortcut for --asset; the explicit flag wins.
    args.asset = args.asset_opt or args.asset
    return args


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
