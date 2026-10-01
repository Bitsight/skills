## Quick Start

Gets assets for a company given name, domain, or GUID.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp" --filter importance_categories=critical,high --limit 100
```

Auth: `BITSIGHT_API_TOKEN` or `PORTAL_API_TOKEN`, or `.env`. Set `PORTAL_API_BASE_URL` for non-default hosts.

## Workflow

1. Identify company input: `--company-guid` · `--company` · `--company --company-domain`.
2. Add asset filters with repeated `--filter key=value` flags.
3. Select fields with `--fields`, add expansions with `--expand`, page with `--limit` · `--offset`.
4. **Common names return 10+ matches.** Follow [company-selection.md](../shared/company-selection.md): inspect search details and the company tree, choose the GUID that best represents the requested business, and ask for clarification when a parent/subsidiary/self-published choice is ambiguous. Reuse GUID on follow-up queries.
5. For browser-ready links in report artifacts, see [portal-urls.md](../shared/portal-urls.md). Asset inventory links may use table search, but asset-scoped findings links must use exact `assets.asset=<asset>` filters, not generic `search=<asset>`.

## Common Filters

- `q`: search across asset, IP, and analytics fields.
- `asset` · `identifier` · `ip_address` · `asset_type` · `is_ip`.
- `importance_categories`: comma-separated `critical` · `high` · `medium` · `low`.
- `countries` · `country_codes`.
- `findings__total_count` plus `_lt` · `_lte` · `_gt` · `_gte` suffixes.
- `tags_contains` · `ssids` · `ssids_isnull`.
- `hosted_by__guid` · `hosted_by_isnull` · `origin_subsidiary__guid` · `origin_subsidiary_isnull`.
- `services` · `product__support` · `product__vendor` · `product__name_version`.
- `cloud_context__provider_slug` · `cloud_context__region` · `cloud_context__service`.

## Examples

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp" --fields asset,asset_type,importance_category,findings --filter q=login
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company-domain --company example.com --filter is_ip=true --filter findings__total_count_gt=0 --sort=-findings__total_count
```

Company check before asset reporting:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "Example Corp"
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid GUID --expand confidence,is_shell
```

## Refs

- [asset-filtering.md](../references/asset-filtering.md) — complete filter guidance.
- [cli.md](../references/cli.md) — shared CLI options and environment setup.
- [company-selection.md](../shared/company-selection.md) — tree-aware company disambiguation and clarification rules.
- [portal-urls.md](../shared/portal-urls.md) — browser-ready Bitsight deep links for reports and handoffs.

## KB

**Asset model:** Assets are internet-observable hostnames, domains, IPs attributed to the company. Importance reflects rating weight: `critical`/`high` → highest impact; `medium`/`low` → lesser weight. Assets with no findings can still appear in inventory.

"Monitored assets" = all attributed assets — no special filter needed. `is_monitored` belongs to Critical Asset Management (CAM) feature with separate API; do not filter by it for general queries.

[Understanding Assets, Attributions, and Findings](https://help.bitsighttech.com/hc/en-us/articles/28483070843671) · [Companies API Endpoint](https://help.bitsighttech.com/hc/en-us/articles/231656647) · [Bitsight Data](https://help.bitsighttech.com/hc/en-us/categories/4410547986199)
