# Asset Filtering Reference

## Endpoint

`GET /companies/{guid}/assets`

The CLI resolves `{guid}` from `--company` with `GET /companies/search?name=...` or `GET /companies/search?domain=...` when `--company-domain` is set.

## Asset Identity Filters

- `q`: broad search across asset and IP fields, subject to IP visibility.
- `asset`: hostname, IP, or mobile asset value.
- `identifier`: unique mobile asset identifier.
- `ip_address`: IP address match.
- `asset_type`: host, IP, Android, or iOS depending on API representation.
- `is_ip`: `true` or `false`.

## Importance And Grace Period Filters

- `importance_categories`: comma-separated `critical`, `high`, `medium`, `low`.
- `is_in_grace_period`: `true` or `false`.
- `grace_period_end_date`, `grace_period_end_date_lt`, `grace_period_end_date_lte`, `grace_period_end_date_gt`, `grace_period_end_date_gte`.
- `overrides__importance`, `overrides_isnull`, `combined_overrides__importance` when override data is visible.

## Geography And Ownership Filters

- `countries`: country display names.
- `country_codes`: two-letter country codes.
- `hosted_by__guid`, `hosted_by_isnull`.
- `origin_subsidiary__guid`, `origin_subsidiary_isnull`.

## Finding Count Filters

- `findings__total_count`.
- `findings__total_count_lt`.
- `findings__total_count_lte`.
- `findings__total_count_gt`.
- `findings__total_count_gte`.

## Infrastructure Analytics Filters

These are accepted when the user has access to infrastructure analytics:

- `services`.
- `tags_contains`, `tags_isnull`.
- `ssids`, `ssids_isnull`.
- `product__support`, `product__vendor`, `product__name_version`.
- `cloud_context__provider_slug`, `cloud_context__region`, `cloud_context__service`.

## Delegated Security Controls Filters

These are accepted only for companies with delegated security controls enabled:

- `delegated_security_controls__has_delegated_security_controls`.
- `delegated_security_controls__types__slug`.
- `delegated_security_controls__findings__total_count` and `_lt`, `_lte`, `_gt`, `_gte` variants.

## CLI Patterns

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp" --filter q=portal --filter importance_categories=critical,high
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company-guid 00000000-0000-0000-0000-000000000000 --filter cloud_context__provider_slug=aws --fields asset,cloud_context,findings
```
