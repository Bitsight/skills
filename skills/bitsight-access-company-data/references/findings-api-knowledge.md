# Findings API Knowledge Map

Use this file as a short index. For machine-readable detail, query recipes, observed filter behavior, and vector playbooks, read `../assets/findings-api-knowledge.json`.

## Verified API Behavior

- Findings are read with `GET https://service.bitsighttech.com/customer-api/v1/companies/{guid}/findings`.
- Severe rating-impacting findings map to `details.vulnerabilities.severity=severe`, `impacts_risk_vector_details=AFFECTS_RATING`, `sort=-last_seen`, and the standard findings expansions.
- Browser-ready portal URL patterns are documented in `../shared/portal-urls.md`.
- `GET /companies/{guid}/findings/filters` lists the CVEs available for a company. Its `vulnerabilities` values include `name`, `alias`, `display_name`, `severity`, and `confidence`.
- Use `GET /companies/search?expand=details` for company disambiguation and `GET /companies/{guid}/company-tree` plus `/company-tree/guids` for tree-aware company selection.

## Do This

- Use `vulnerabilities=CVE-...` or `vulnerabilities=ALIAS` for named CVE lookup.
- Use `details.vulnerabilities.severity=severe` for severity filtering.
- Use `impacts_risk_vector_details=AFFECTS_RATING` for findings that affect rating.
- Use `risk_vector=open_ports` only when the question is explicitly about open ports or exposed services.
- Use `assets__asset`, `assets__identifier`, `assets__combined_importance`, `assets__is_monitored`, and `observed_ips_contains` for asset scoping.
- Fetch `finding-filters` first when the user asks what CVEs exist for a company or when you need valid CVE aliases/severities/confidences.
- Before reporting findings for a named company, inspect company search details and the company tree when multiple parent, subsidiary, primary, or self-published companies could match.
- Ask for clarification rather than guessing when the correct business company remains ambiguous after tree inspection.
- Prefer `--company-guid` for unattended workflows so company search ambiguity cannot block execution.
- Use JSON output for `--summary cves|assets|both`; CSV is intended for raw row output.
- Correlate internal/external results after export by joining JSON on stable keys such as asset, identifier, IP, CVE, and `evidence_key`.

## Avoid This

- Do not use `details.vulnerabilities.name` for CVE lookup. It is ignored and returns unfiltered findings.
- Do not depend on `details.vulnerabilities.confidence` as a server-side filter. Filter confidence client-side after narrowing with server-side filters and a bounded page count.
- Do not prefer vulnerability catalog or portfolio vulnerability endpoints for company CVE answers. They do not provide per-finding asset/CVE detail.

## Vector Pointers

- `open_ports`: exposed-service CVEs. Best for severe rating-impacting CVEs shown on the findings page, affected IPs/assets, service/product/version, and CPE detail.
- `ssl_configurations`: SSL/TLS vulnerability findings such as POODLE, FREAK, or ROBOT-style checks.
- `patching_cadence`: named CVE findings that are not necessarily open-port related.
- `server_software`: vulnerable or unsupported server software scoped by asset and CVE/severity.
- `desktop_software`: desktop software CVE scope.
- `mobile_software`: mobile software CVE scope.

## Fast Recipes

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py finding-filters --company-guid {guid}
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company-guid {guid} --severity severe --impacts-risk-vector-details AFFECTS_RATING --default-expand --sort=-last_seen
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company-guid {guid} --open-ports --summary cves --all-pages
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company-guid {guid} --cve CVE-2023-27522 --summary assets --all-pages
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company-guid {guid} --asset login.example.com --summary cves --all-pages
```
