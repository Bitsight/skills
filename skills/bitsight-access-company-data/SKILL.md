---
name: bitsight-access-company-data
description: Retrieve raw Bitsight data records for a named company — asset lists, individual finding records, CVE/vulnerability entries, open ports, CVSS, risk vector evidence, and rating drivers. Use when the user wants underlying data to inspect or export, not a summarised posture analysis. Do NOT use for prioritised security recommendations or posture summaries (use bitsight-generate-spm-insights for own-org or bitsight-generate-vendor-insights for a vendor). Do NOT use for own-org asset operational context with products/services (use bitsight-show-asset-context).
version: 1.0
tags: CM, SPM, Data
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
scope: company
---

# Search Infrastructure and Security Data for a Company

Single installable skill for company assets, findings, and vulnerabilities. Read **one** workflow file for the matched task; do not load every workflow, reference, or JSON catalog unless that workflow points you there.

## Quick Start

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "Example Corp"
```

### API Token — Confidential

Do NOT load, display, or echo the `BITSIGHT_API_TOKEN` value in the conversation. Check for it in this order:
1. Shell environment (`BITSIGHT_API_TOKEN`)
2. A `.env` or `.envrc` file in the working directory

If not found, ask the user to set it — do not ask them to paste the token directly into the conversation:
*"Please set your Bitsight API token in your shell environment (`export BITSIGHT_API_TOKEN=...`) or a `.env` / `.envrc` file, then try again. You can find your token under **Account → User API Token** in the Bitsight portal."*

Default host: `https://api.bitsighttech.com/`.
Set the User-Agent: header on all Bitsight API requests to '<bitsight-user-agent>'.

## Task Router

| User intent | CLI subcommand | Read next |
|-------------|----------------|-----------|
| Asset inventory, importance, cloud, hosted assets | `assets` | [workflows/assets.md](workflows/assets.md) |
| Findings, risk vectors, rating drivers, remediation priority | `findings` | [workflows/findings.md](workflows/findings.md) |
| CVEs, open ports, vulnerability counts, affected assets | `vulnerabilities` | [workflows/vulnerabilities.md](workflows/vulnerabilities.md) |
| Company name ambiguity, parent/subsidiary choice | `companies`, `company-tree` | [shared/company-selection.md](shared/company-selection.md) |
| Browser-ready Bitsight links in reports | `portal-urls` | [shared/portal-urls.md](shared/portal-urls.md) |

For JSON knowledge, jump to named keys (e.g. `vector_playbooks.open_ports`, `task_to_query`) in [assets/findings-api-knowledge.json](assets/findings-api-knowledge.json) — do not read the full file unless needed.

## Shared Guardrails (always apply)

1. **Company selection:** Common names return 10+ matches. Before reporting assets, findings, or CVEs, follow [shared/company-selection.md](shared/company-selection.md). When the script prints `SINGLE_MATCH`, verify the name/domain/GUID match the intended company before proceeding. When the script prints `AMBIGUOUS_COMPANY`, **stop, present the candidate list to the user, and ask them to specify the intended company by GUID. Never use `--company-index` to self-select; only `--select-guid <guid>` with an explicit user-provided GUID unblocks an ambiguous result.**
2. **CVE aliases:** Before querying by alias (POODLE, BEAST, DROWN, etc.), run `finding-filters` to see which CVEs exist for the company. Aliases not in the catalog return zero results.
3. **CVE population:** CVE data appears only with `--open-ports` or `--cve`/`--vulnerability` on `vulnerabilities`. Broad unfilitered queries return findings without `details.vulnerabilities`.
4. **Sort syntax:** Use `--sort=-field` (no space), e.g. `--sort=-severity`.
5. **`is_monitored`:** CAM-only — ignore for general asset/vulnerability queries.
6. **Asset-scoped findings links:** Use exact `assets.asset=<asset>`; do not use generic `search=<asset>` (searches evidence text, not asset scope).
7. **SSL CVEs:** POODLE/BEAST/DROWN are not populated via `risk_vector=ssl_configurations`. Use `--cve POODLE` or the CVE ID directly.

## Layout

- `workflows/` — task-specific commands and parameters (read one per session)
- `references/` — deep filter/API docs (on demand)
- `assets/` — machine-readable catalogs and playbooks (partial reads)
- `shared/` — company selection and portal URL builders
- `scripts/portal_api.py` — portable stdlib CLI. This is the only file that makes API calls; it only performs read operations. It does not change any data or state in the Bitsight service.

## KB

[Bitsight Data](https://help.bitsighttech.com/hc/en-us/categories/4410547986199) · [Bitsight API](https://help.bitsighttech.com/hc/en-us/categories/360005934253-BitSight-API) · [Risk Categories & Vectors](https://help.bitsighttech.com/hc/en-us/articles/360007320574)
