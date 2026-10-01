## Quick Start

Retrieves findings for named company filtered by risk vector, severity, rating impact, or assets.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company "Example Corp" --risk-vector open_ports,ssl_certificates --asset-importance critical,high --limit 100
```

Auth: `BITSIGHT_API_TOKEN` or `PORTAL_API_TOKEN`, or `.env`. Default host: `https://service.bitsighttech.com/customer-api/v1`.

## Workflow

1. Resolve company via `--company`, `--company --company-domain`, or `--company-guid`. **Common names return 10+ matches.** Before reporting findings, follow [company-selection.md](../shared/company-selection.md): inspect search details and the company tree, select the GUID that best represents the business scope, and ask for clarification when a parent/subsidiary/self-published choice remains ambiguous.
2. For CVE or vulnerability questions, check [findings-api-knowledge.md](../references/findings-api-knowledge.md) or [findings-api-knowledge.json](../assets/findings-api-knowledge.json).
3. Choose risk-vector family from [risk-vectors.md](../references/risk-vectors.md) or [risk-vectors.json](../assets/risk-vectors.json).
4. Combine finding filters with asset filters for asset-scoped questions.
5. Use `--fields` · `--expand` · `--sort=-field` · `--limit` · `--offset`. Sort descending: `--sort=-severity` not `--sort -severity`.
6. **Before querying by CVE alias (POODLE, BEAST, DROWN, etc.), run `finding-filters` first** to discover which CVEs are present for the company — aliases not in the catalog return zero results.
7. For browser-ready links in report artifacts, see [portal-urls.md](../shared/portal-urls.md). For asset-scoped findings links, use exact `assets.asset=<asset>` filters; do not use generic `search=<asset>`, which searches finding identifiers/evidence text instead of selecting the asset.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py finding-filters --company-guid 00000000-0000-0000-0000-000000000000
```

## Common Finding Filters

- `--risk-vector`: slugs e.g. `botnet_infections` · `open_ports` · `ssl_certificates` · `server_software`.
- `--risk-category`: e.g. `Compromised Systems` · `Diligence` · `User Behavior`.
- `--severity-category`: severity label.
- `--asset` → `assets__asset`.
- `--asset-importance` → `assets__combined_importance`; values: `critical` · `high` · `medium` · `low` · `none`.
- `--vulnerability`: CVE names and aliases via `vulnerabilities` filter.
- `--query`: broad search.
- `--filter key=value`: raw API filter, e.g. `details.vulnerabilities.severity=severe` or `vulnerabilities=CVE-2023-27522`.

## Company Selection

Use `companies` to inspect disambiguation signals:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "Example Corp"
```

Use `company-tree` before interpreting high-impact findings when multiple companies could match:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid GUID --expand confidence,is_shell
```

Do not assume `in_portfolio=true` is the correct answer if a self-published, child, or primary company better matches the user's business. If the correct company cannot be selected confidently, ask the user to clarify instead of reporting findings.

## Priority / Top Issues Workflow

For "top priority issues" or "what should they fix first" questions:

1. Get a severity + vector breakdown using `affects_rating=true` (scopes to rating-impacting findings only):

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company-guid GUID --filter affects_rating=true --severity-category severe --fields risk_vector --limit 500 --all-pages
```

2. Repeat for `--severity-category material`.
3. **Prioritize Compromised Systems vectors first** (`botnet_infections` · `malware_servers` · `spam_propagation` · `potentially_exploited`) — they carry the highest rating weight and indicate active compromise. Diligence issues (SSL, ports, DMARC) come after.
4. Within each severity tier, group by `risk_vector` to identify which areas need the most work.

## Asset Filtering With Findings

"Monitored assets" means all company assets — no special filter needed.

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company "Example Corp" --asset login.example.com --risk-vector ssl_certificates --fields evidence_key,risk_vector,severity,assets
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company "Example Corp" --asset-importance critical --filter first_seen_gte=2024-01-01
```

For CVE investigations, use the `vulnerabilities` subcommand.

## Refs

- [findings-api-knowledge.md](../references/findings-api-knowledge.md) — verified API behavior and vector playbooks.
- [findings-api-knowledge.json](../assets/findings-api-knowledge.json) — machine-readable findings API knowledge.
- [risk-vectors.md](../references/risk-vectors.md) — risk-vector structure and parameters.
- [finding-filters.md](../references/finding-filters.md) — full filter guidance.
- [risk-vectors.json](../assets/risk-vectors.json) — machine-readable risk-vector catalog.
- [portal-urls.md](../shared/portal-urls.md) — browser-ready Bitsight deep links for reports and handoffs.

## KB

**Grades:** `GOOD` · `FAIR` · `NEUTRAL` · `WARN` · `BAD` → letter grades (A–F) per vector → overall security rating. Use `affects_rating=true` and `impacts_risk_vector_details=AFFECTS_RATING` to isolate rating-impacting findings.

**Risk categories:**
- **Compromised Systems** (`botnet_infections` · `malware_servers` · `spam_propagation` · `potentially_exploited` · `unsolicited_comm`): active compromise. Highest rating weight.
- **Diligence** (`open_ports` · `ssl_certificates` · `ssl_configurations` · `patching_cadence` · `server_software` · `spf` · `dkim` · `dmarc` · `application_security` etc.): configuration quality. Broadest category.
- **User Behavior** (`file_sharing` · `mobile_app_publications`): employee activity. Lowest weight.

[Risk Categories & Vectors](https://help.bitsighttech.com/hc/en-us/articles/360007320574) · [Security Ratings Calculation](https://help.bitsighttech.com/hc/en-us/articles/231950968) · [Impacts Risk Vector Grade](https://help.bitsighttech.com/hc/en-us/articles/26455589957015) · [API Fields: Finding Grades](https://help.bitsighttech.com/hc/en-us/articles/1500004356421) · [Bitsight Data](https://help.bitsighttech.com/hc/en-us/categories/4410547986199)
