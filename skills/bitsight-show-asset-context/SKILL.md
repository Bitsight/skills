---
name: bitsight-show-asset-context
description: Answers "what products and services are running on my own-org assets?" and "show me the operational context of IP X." Projects first-party (SPM) assets to compact context objects — customer tags, cloud provider/region/service, identified products with derived EOL/support_risk, and network services — plus is_cloud and has_obsolete_product flags and a portfolio summary. Use for own-org asset operational context and single-asset product/service lookups. Do NOT use for IP ownership or attribution questions (use bitsight-validate-ip-attribution), for findings, risk vectors, or CVE data (use bitsight-access-company-data), to assess a third-party vendor, or to mutate anything.
version: 2026.243
tags: SPM, Attack Surface Management, Asset Intelligence
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
---

# Bitsight Show Asset Context

## Purpose

Answers **"what is running on my own-org assets?"** and the single-asset variant **"show me
everything related to IP X."** For each first-party (SPM) asset it returns a compact
operational-context object: customer **tags**, **cloud** provider/region/service, **identified
products** (with a derived EOL/obsolete `support_risk`), and detected network **services** — plus
the boolean flags `is_cloud` and `has_obsolete_product`, and a portfolio-wide rollup.

The delta over the raw `/assets` page is the per-asset **compaction**, the support→risk **scoring**,
and a hard **unknown ≠ absent** guard: a product whose support status is unknown is scored `unknown`
(never `none`), and when Infrastructure Analytics is not entitled the empty products/services are
reported as *unavailable*, not as "this asset runs nothing."

Read-only. It answers *what runs on* an asset — not *who owns it* (that is a separate ownership
capability) and not a third-party vendor's posture.

## Approach

This skill runs `scripts/show_asset_context.py` — a self-contained Python CLI with no third-party
dependencies. It makes one or two SPM (ratings API) calls:

1. **Resolve own org** (only if `--company-guid` is not given) — `GET /v1/users/current` →
   `customer.my_company_guid`. This is the canonical first-party company id.
2. **Fetch + project assets** — `GET /v1/companies/{guid}/assets` with
   `fields=asset,asset_type,is_ip,identifier,importance_category,is_monitored,ip_addresses,tags,cloud_context,products,services`
   and `expand=tag_details`, paginated. Each asset is projected to the context object above and
   sorted by importance.

**Filter placement (verified against the live API):** `asset`, `ip_address`, `is_ip`,
`importance_categories`, `services`, `product.vendor`, and `product.support` filter **server-side**.
The `cloud_context.*` filters are **silently ignored server-side** (they return the entire inventory),
so `--cloud-provider/--cloud-region/--cloud-service` and `--tag` are enforced **client-side** by
scanning up to `--max-scan` assets; the output flags `truncated` and explains any cap that was hit —
it never presents a partial scan as complete.

## Before Starting

Confirm before running. If missing, ask before proceeding.

**1. API token — confidential**

Do NOT display or echo `BITSIGHT_API_TOKEN` (or `BITSIGHT_API_JWT`). Check the shell environment,
then `.env`/`.envrc`. If missing:
> *"Please set your Bitsight API key: `export BITSIGHT_API_TOKEN=<your-key>` (or in a `.env` file).
> Find it under Account → User API Token in the Bitsight portal."*

Never ask the user to paste the token into chat.

**2. Scope**

By default the skill reports **your own organization's** assets (auto-resolved). To focus on one
asset — "everything about IP X" — pass the IP/hostname as the positional argument. To inspect a
specific first-party company (e.g. a subsidiary GUID), pass `--company-guid`.

## Authentication

`BITSIGHT_API_TOKEN` is sent as the HTTP Basic username (empty password); a `BITSIGHT_API_JWT`, if
set, is sent as a bearer token and its `portal_host` claim also selects the API base. The assets and
users endpoints live on the SPM/ratings host (`https://api.bitsighttech.com`); the script resolves
the base automatically (JWT `portal_host` → `BITSIGHT_API_BASE` → the ratings host default) and
applies the `/customer-api` rule where required. Every request includes
`User-Agent: <bitsight-user-agent>`, set automatically.

## Running the Script

```bash
BITSIGHT_API_TOKEN=<token> python3 <skill-dir>/scripts/show_asset_context.py
```

**Everything about one IP (or hostname):**
```bash
python3 <skill-dir>/scripts/show_asset_context.py 203.0.113.50 --format text
```

**Only critical/high assets that run an obsolete product:**
```bash
python3 <skill-dir>/scripts/show_asset_context.py --importance critical --importance high --product-support obsolete-version
```

**Cloud assets on a given provider (enforced client-side):**
```bash
python3 <skill-dir>/scripts/show_asset_context.py --cloud-provider aws --max-scan 20000
```

**A specific subsidiary by GUID:**
```bash
python3 <skill-dir>/scripts/show_asset_context.py --company-guid <guid> --limit 500
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `asset` (positional) | — | Asset (hostname or IP) to focus on. Shortcut for `--asset`. |
| `--company-guid` | auto | Own-org company GUID; skips the `/v1/users/current` resolve. |
| `--asset` | — | Filter to a single asset name (server-side). |
| `--ip-address` | — | Filter by IP address (server-side). |
| `--asset-kind` | `all` | `ip`, `domain`, or `all` (maps to `is_ip`). |
| `--importance` | — | `critical`/`high`/`medium`/`low`. Repeatable (server-side). |
| `--monitored-only` | off | Only monitored assets (server-side). |
| `--tag` | — | Tag name; matched **client-side**. |
| `--service` | — | Network service name (server-side; needs Infrastructure Analytics). |
| `--product-vendor` | — | Identified product vendor (server-side; needs Infrastructure Analytics). |
| `--product-support` | — | Product support status enum (server-side; needs Infrastructure Analytics). |
| `--cloud-provider` | — | Cloud provider slug/name; enforced **client-side**. |
| `--cloud-region` | — | Cloud region; enforced **client-side**. |
| `--cloud-service` | — | Cloud service; enforced **client-side**. |
| `--limit` | `1000` | Max context records returned (`0` = no cap). |
| `--max-scan` | `10000` | Assets scanned when a client-side filter is active (`0` = no cap). |
| `--format` | `json` | `json` or `text`. |
| `--retries` | `3` | HTTP retry attempts on 429/5xx/network errors. |
| `--api-token` | env | Override `BITSIGHT_API_TOKEN`. |
| `--api-jwt` | env | Override `BITSIGHT_API_JWT` (bearer; outranks the token). |

## Understanding the Output

```json
{
  "success": true,
  "company_guid": "…",
  "company_name": "…",
  "total_assets": 1,
  "scanned_assets": 1,
  "total_available": 1250,
  "truncated": false,
  "filters_applied": { "asset": "203.0.113.50" },
  "context_availability": {
    "tags": true, "cloud_context": false, "products": true, "services": true,
    "infrastructure_analytics_fields_populated": true
  },
  "summary": {
    "total_tagged": 1, "total_cloud": 0,
    "cloud_providers": [],
    "top_services": [{ "service": "HTTPS", "asset_count": 1 }],
    "top_product_vendors": [{ "vendor": "oracle", "asset_count": 1 }],
    "assets_with_obsolete_products": [],
    "obsolete_product_count": 0
  },
  "notes": [],
  "assets": [
    {
      "asset": "203.0.113.50",
      "asset_type": "IP",
      "is_ip": true,
      "importance": "critical",
      "is_monitored": false,
      "tags": ["Example Tag", "Production"],
      "cloud_context": null,
      "is_cloud": false,
      "products": [
        { "product": "mysql", "vendor": "oracle", "version": "5.7.44",
          "type": "application", "support": "unknown", "support_risk": "unknown" }
      ],
      "product_count": 5,
      "has_obsolete_product": false,
      "services": ["HTTP", "HTTPS", "MySQL"],
      "service_count": 3
    }
  ],
  "skill_version": "2026.243"
}
```

- **`support_risk`**: `high` = obsolete (version/package/OS release); `medium` = unknown-patch /
  possible-backports; `low` = incomplete-version; `none` = current; **`unknown` = unknown support**
  (not clean). `has_obsolete_product` is true only when a product scores `high`.
- **`is_cloud`** is true when the asset carries any `cloud_context`; `cloud_context: null` means no
  cloud context, not "on-prem confirmed."
- **`context_availability.infrastructure_analytics_fields_populated: false`** with assets present
  means products/services could not be read (likely no Infrastructure Analytics entitlement) —
  **absence is unknown, not zero.** A `note` says so.
- **`truncated: true`** means a client-side filter stopped at `--max-scan`/`--limit`; `scanned_assets`
  vs `total_available` shows the gap. Raise the caps or narrow filters for full coverage.

## Relaying Results

1. Lead with the asset (or the count of assets) and the headline flags — how many are cloud-hosted,
   how many run an obsolete product, and the top product vendors/services.
2. For a single-asset lookup, present its tags, cloud context, products (call out any obsolete ones),
   and services directly.
3. If `notes` is non-empty, surface it — especially the Infrastructure-Analytics caveat
   (unknown ≠ absent) and any `truncated` scan — rather than implying full/clean coverage.
4. Never present `support: unknown` products as safe, and never present a `null` cloud_context as a
   confirmed on-prem asset.

If the script exits with an error (`success: false`):
- **`MISSING_CREDENTIALS`** → ask the user to set `BITSIGHT_API_TOKEN`.
- **`NO_COMPANY`** → own-org GUID could not be resolved; pass `--company-guid`.
- **`AUTH_FAILED` / `PERMISSION_DENIED`** → the token is invalid or lacks SPM/asset access.
- **`NOT_FOUND`** → the company GUID is wrong or not visible to this account.
- **`NETWORK_ERROR` / `HTTP_ERROR`** → transient; retries with backoff already ran — suggest retrying.
