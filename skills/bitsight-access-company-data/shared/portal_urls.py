"""Browser URL builders for the Bitsight portal."""

from __future__ import annotations

import argparse
import re
from typing import Any
from urllib.parse import urlencode


DEFAULT_PORTAL_HOST = "https://service.bitsighttech.com"
DEFAULT_PORTAL_APP_URL = f"{DEFAULT_PORTAL_HOST}/app/tprm"
PORTAL_PRODUCTS = {
    "cm": {
        "label": "Continuous Monitoring",
        "app_path": "tprm",
    },
    "spm": {
        "label": "Security Posture Management",
        "app_path": "spm",
    },
}
RISK_VECTOR_LABELS = {
    "application_security": "Application security",
    "dkim": "DKIM",
    "dmarc": "DMARC",
    "dnssec": "DNSSEC",
    "mobile_software": "Mobile software",
    "open_ports": "Open ports",
    "spf": "SPF",
    "ssl_certificates": "SSL certificates",
    "ssl_configurations": "SSL configurations",
    "web_appsec": "Web appsec",
}
RISK_VECTOR_ALIASES = {
    "application security": "application_security",
    "dkim": "dkim",
    "dmarc": "dmarc",
    "dnssec": "dnssec",
    "mobile software": "mobile_software",
    "open ports": "open_ports",
    "spf": "spf",
    "ssl certificates": "ssl_certificates",
    "ssl configurations": "ssl_configurations",
    "tls/ssl configurations": "ssl_configurations",
    "web appsec": "web_appsec",
    "web application security": "web_appsec",
}
REPORT_MINIMUM_VECTORS = [
    "ssl_configurations",
    "dnssec",
    "dmarc",
    "dkim",
    "ssl_certificates",
    "application_security",
    "web_appsec",
    "spf",
    "mobile_software",
    "open_ports",
]
# No default assets: asset links are company-specific, so callers pass them with --asset.
REPORT_MINIMUM_ASSETS: list[str] = []


def normalize_portal_app_url(value: str) -> str:
    return value.rstrip("/")


def portal_url(base_url: str, path: str, params: dict[str, Any] | None = None) -> str:
    url = f"{normalize_portal_app_url(base_url)}/{path.lstrip('/')}"
    if params:
        clean_params = {key: value for key, value in params.items() if value not in (None, "", [])}
        if clean_params:
            url = f"{url}?{urlencode(clean_params, doseq=True)}"
    return url


def product_app_url(args: argparse.Namespace, product: str) -> str:
    if args.portal_app_url:
        return normalize_portal_app_url(args.portal_app_url)
    return f"{DEFAULT_PORTAL_HOST}/app/{PORTAL_PRODUCTS[product]['app_path']}"


def company_page_url(
    app_url: str,
    guid: str,
    page: str,
    params: dict[str, Any] | None = None,
) -> str:
    page_paths = {
        "overview": f"company/{guid}/overview/",
        "rating_details": f"company/{guid}/rating-details/",
        "findings": f"company/{guid}/findings/",
        "assets": f"company/{guid}/infrastructure/assets/table/",
    }
    if page == "ratings_tree":
        return portal_url(app_url, "ratings-tree/", {"guid": guid})
    return portal_url(app_url, page_paths[page], params)


def normalize_risk_vector(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Risk vector cannot be empty.")
    if cleaned in RISK_VECTOR_LABELS:
        return cleaned
    key = re.sub(r"\s+", " ", cleaned.replace("_", " ")).lower()
    return RISK_VECTOR_ALIASES.get(key, cleaned)


def split_csv_values(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def build_product_portal_urls(args: argparse.Namespace, guid: str, product: str) -> dict[str, Any]:
    risk_vectors = [normalize_risk_vector(value) for value in split_csv_values(args.risk_vector)]
    assets = split_csv_values(args.asset)
    if args.report_minimum:
        risk_vectors.extend(vector for vector in REPORT_MINIMUM_VECTORS if vector not in risk_vectors)
        assets.extend(asset for asset in REPORT_MINIMUM_ASSETS if asset not in assets)

    app_url = product_app_url(args, product)
    links: dict[str, Any] = {
        "company_guid": guid,
        "portal_product": product,
        "portal_product_label": PORTAL_PRODUCTS[product]["label"],
        "portal_app_url": app_url,
        "links": {
            "overview": company_page_url(app_url, guid, "overview"),
            "rating_details": company_page_url(app_url, guid, "rating_details"),
            "ratings_tree": company_page_url(app_url, guid, "ratings_tree"),
            "findings": company_page_url(app_url, guid, "findings", {"sort": "-last_seen"}),
            "rating_impacting_findings": company_page_url(
                app_url,
                guid,
                "findings",
                {"impacts_risk_vector_details": "AFFECTS_RATING", "sort": "-last_seen"},
            ),
            "assets": company_page_url(app_url, guid, "assets", {"sort": "-importance"}),
            "open_port_findings": company_page_url(
                app_url,
                guid,
                "findings",
                {"risk_vector": "open_ports", "sort": "-last_seen"},
            ),
        },
    }

    if risk_vectors:
        links["risk_vectors"] = [
            {
                "label": RISK_VECTOR_LABELS.get(vector, vector),
                "risk_vector": vector,
                "findings_url": company_page_url(
                    app_url,
                    guid,
                    "findings",
                    {
                        "risk_vector": vector,
                        "impacts_risk_vector_details": "AFFECTS_RATING" if args.affects_rating else None,
                        "sort": "-last_seen",
                    },
                ),
            }
            for vector in risk_vectors
        ]

    if assets:
        links["assets"] = [
            {
                "asset": asset,
                "asset_inventory_url": company_page_url(app_url, guid, "assets", {"search": asset, "sort": "-importance"}),
                "findings_url": company_page_url(app_url, guid, "findings", {"assets.asset": asset, "sort": "-last_seen"}),
                "rating_impacting_findings_url": company_page_url(
                    app_url,
                    guid,
                    "findings",
                    {"affects_rating": "true", "assets.asset": asset, "sort": "-last_seen"},
                ),
            }
            for asset in assets
        ]

    if args.vulnerability or args.cve:
        vulnerabilities = split_csv_values(args.vulnerability + args.cve)
        links["vulnerabilities"] = [
            {
                "vulnerability": vulnerability,
                "findings_url": company_page_url(
                    app_url,
                    guid,
                    "findings",
                    {"vulnerabilities": vulnerability, "sort": "-last_seen"},
                ),
            }
            for vulnerability in vulnerabilities
        ]

    return links


def build_portal_urls(args: argparse.Namespace, guid: str) -> dict[str, Any]:
    if args.portal_product == "both":
        products = {
            product: build_product_portal_urls(args, guid, product)
            for product in ("cm", "spm")
        }
        return {
            "company_guid": guid,
            "portal_product": "both",
            "report_behavior": {
                "recommended_selector": "Generated reports should ask the user to choose CM or SPM on the first Bitsight-link click after page load, then reuse that choice for subsequent link clicks in the same page session.",
                "storage_scope": "page-session",
            },
            "products": products,
        }
    return build_product_portal_urls(args, guid, args.portal_product)
