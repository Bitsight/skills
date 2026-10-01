## Quick Start

For CVE and vulnerability questions about named company. Uses `GET /companies/{guid}/findings` — not vulnerability catalog endpoints, which omit per-finding CVE and asset detail.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company-guid {guid} --open-ports --severity severe --impacts-risk-vector-details AFFECTS_RATING --default-expand --sort=-last_seen
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company "Example Corp" --open-ports --summary cves --all-pages --limit 500
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company "Example Corp" --open-ports --cve CVE-2023-27522 --summary assets --all-pages
```

Auth: `BITSIGHT_API_TOKEN` or `PORTAL_API_TOKEN`, or `.env`.

## Endpoint

Always provide `--company` or `--company-guid`. **Common names return 10+ matches.** Before querying CVEs, follow [company-selection.md](../shared/company-selection.md): inspect search details and the company tree, select the GUID that best represents the requested business, and ask for clarification when a parent/subsidiary/self-published choice remains ambiguous. Calls `GET /companies/{guid}/findings` with vuln filters.

**Before querying by CVE alias (POODLE, BEAST, DROWN, HEARTBLEED, etc.), run `finding-filters` first** — it lists every CVE present for the company, so you can verify which aliases exist and query them by exact name or CVE ID. Aliases not in the catalog return zero results.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py finding-filters --company-guid {guid}
```

For verified details, read [findings-api-knowledge.json](../assets/findings-api-knowledge.json) — jump to `vector_playbooks.open_ports` or `task_to_query` instead of reading every reference file.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company-guid {guid} --filter details.vulnerabilities.severity=severe --filter impacts_risk_vector_details=AFFECTS_RATING --default-expand --limit 100 --offset 0 --sort=-last_seen
```

For browser-ready Bitsight links in report artifacts, see [portal-urls.md](../shared/portal-urls.md).

Company check before vulnerability reporting:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "Example Corp"
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid GUID --expand confidence,is_shell
```

## Common Parameters

- `--cve` / `--vulnerability`: server-side `vulnerabilities` filter for CVE IDs or aliases (e.g. `CVE-2023-27522`, `POODLE`).
- `--open-ports`: shortcut for `risk_vector=open_ports`. **CVE data is only populated when `--open-ports` or `--cve`/`--vulnerability` is active — broad unfilitered queries return empty `details.vulnerabilities`.**
- `--risk-vector`: explicit scope when not using `--open-ports`.
- `--severity` → `details.vulnerabilities.severity`; values: `severe` · `material` · `moderate` · `minor`.
- `--confidence`: client-side filter on `details.vulnerabilities[].confidence`; narrow server-side first.
- `--cvss-base` → `cvss__base`.
- `--impacts-risk-vector-details`: e.g. `AFFECTS_RATING`.
- `--asset` → `assets__asset`.
- `--asset-importance` → `assets__combined_importance`.
- `--asset-is-monitored`: **Do not use for general queries.** CAM-specific; has its own API.
- `--filter key=value`: raw filters e.g. `first_seen_gte=2024-01-01`.
- `--all-pages`: fetch all pages before output.
- `--summary cves|assets|both`: aggregate findings into CVE counts or asset lists. Output structure differs from raw findings — key is `cves` (not `results`):
  ```json
  {"summary": "cves", "finding_count": N, "cve_count": N,
   "cves": [{"cve": "CVE-...", "finding_count": N, "asset_count": N,
              "assets": [...], "severities": [...], "cvss": [...], "example_findings": [...]}]}
  ```
  For `--summary assets` the top-level key is `assets`. For `--summary both`, both keys are present.

## CVE Occurrence Counts

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company "Example Corp" --open-ports --summary cves --all-pages --limit 500
```

Use `--severity severe` · `--asset-importance critical,high` · or `--filter` flags to narrow.

## Asset Filtering With Vulnerabilities

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company "Example Corp" --open-ports --asset login.example.com --summary cves --all-pages
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company "Example Corp" --open-ports --cve CVE-2023-27522 --summary assets --all-pages
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py vulnerabilities --company "Example Corp" --open-ports --severity severe --asset-importance critical,high --summary both --all-pages
```

## Refs

- [findings-api-knowledge.md](../references/findings-api-knowledge.md) — verified behavior and vector playbooks.
- [findings-api-knowledge.json](../assets/findings-api-knowledge.json) — machine-readable knowledge.
- [vulnerability-options.md](../references/vulnerability-options.md) — parameter structure.
- [vulnerability-options.json](../assets/vulnerability-options.json) — machine-readable parameters.
- [company-selection.md](../shared/company-selection.md) — tree-aware company disambiguation and clarification rules.
- [portal-urls.md](../shared/portal-urls.md) — browser-ready Bitsight deep links for reports and handoffs.

## KB

**Severity tiers** (`details.vulnerabilities.severity`):
- `severe`: critical/high-impact, often actively exploited.
- `material`: significant CVSS score.
- `moderate`: medium-level risk.
- `minor`: low CVSS or narrow exposure.

Use `cvss__base` for numeric CVSS filtering. `--confidence` is client-side only.

[Security Ratings Calculation](https://help.bitsighttech.com/hc/en-us/articles/231950968) · [Risk Categories & Vectors](https://help.bitsighttech.com/hc/en-us/articles/360007320574) · [Findings Remediation API](https://help.bitsighttech.com/hc/en-us/articles/360053410533) · [Bitsight Data](https://help.bitsighttech.com/hc/en-us/categories/4410547986199)
