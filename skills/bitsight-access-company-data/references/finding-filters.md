# Finding Filters Reference

## Endpoint

`GET /companies/{guid}/findings` on `https://service.bitsighttech.com/customer-api/v1`

The CLI resolves `{guid}` through `/companies/search` unless `--company-guid` is provided.

Use `GET /companies/{guid}/findings/filters` to discover the company's available finding filter values, including CVEs under `vulnerabilities`.

## Primary Filters

- `risk_vector`: comma-separated risk-vector slugs.
- `risk_category`: comma-separated risk categories.
- `severity_category`: API-supported severity label.
- `affects_rating`: `true` or `false`.
- `impacts_risk_vector_details`: comma-separated values such as `AFFECTS_RATING` and other API-defined impact reasons.
- `grade`, `grade_lt`, `grade_gt`: rating grade filters.
- `evidence_key`: finding identifier. **Semantics vary by risk vector** — for `ssl_certificates` this is the certificate serial number, not a hostname; for `spf`/`dkim`/`dmarc` it is the domain name. Do not use `evidence_key` to filter SSL certificate findings by hostname — use `assets__asset` instead.
- `rolledup_observation_id`: rolled-up finding identifier.
- `q`: broad search.

## Date And Duration Filters

- `first_seen`, `first_seen_lt`, `first_seen_lte`, `first_seen_gt`, `first_seen_gte`.
- `last_seen`, `last_seen_lt`, `last_seen_lte`, `last_seen_gt`, `last_seen_gte`.
- `decay_date`, `decay_date_lt`, `decay_date_lte`, `decay_date_gt`, `decay_date_gte`.
- `duration_lte`, `duration_gte`.
- `remaining_decay_lt`, `remaining_decay_lte`, `remaining_decay_gt`, `remaining_decay_gte`.

## Asset-Scoped Filters

- `assets__asset`: hostname, IP, or asset value.
- `assets__identifier`: asset identifier.
- `assets__category`: asset category.
- `assets__hosted_by`: hosting company.
- `assets__combined_importance`: `critical`, `high`, `medium`, `low`, or `none`.
- `assets__is_monitored`: `true` or `false`.
- `observed_ips_contains`: observed IP substring.

## Vulnerability Filters On Findings

- `vulnerabilities`: CVE identifier or alias such as `CVE-2023-27522` or `POODLE`.
- `details.vulnerabilities.severity`: lowercase severity such as `severe`, `material`, `moderate`, or `minor`.
- `cvss__base`: CVSS base score range filter.

## Remediation And Refresh Filters

- `last_refresh_status_label`.
- `last_remediation_status_date` and `_lt`, `_lte`, `_gt`, `_gte` variants.
- `last_remediation_status_label`.
- `remediation_assignments`.

## Attribution, Tags, And Threat Filters

- `tags_contains`.
- `attributed_companies__guid`.
- `attributed_companies__name`.
- `assessment_name`.
- `threat_groups`.
- `threat_activity_score_label`.

## CLI Examples

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company "Example Corp" --filter affects_rating=true --filter first_seen_gte=2024-01-01
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company-guid 00000000-0000-0000-0000-000000000000 --filter risk_vector=open_ports --filter details.vulnerabilities.severity=severe --filter impacts_risk_vector_details=AFFECTS_RATING
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py finding-filters --company "Example Corp"
```
