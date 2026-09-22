---
name: bitsight-assess-supply-chain-resilience
description: Answers "do our third parties introduce meaningful risk, and is our supply chain safer or riskier than last week/month/quarter/year?" Aggregates the monitored vendor portfolio into one read — rating distribution (advanced/intermediate/basic counts, median, mean), the weakest risk vectors across the portfolio, and the trend over a chosen timeframe (stateless — re-issues the same statistics call back-dated to Bitsight's own historical figures, no snapshot store) — with optional named riskiest vendors. Use when a board/CISO/vendor-risk lead asks whether the supply chain is improving or declining, or as the third-party leg of a posture brief. Do NOT use for a single vendor's posture or live victimization (use a per-vendor threat/assessment skill), for a per-vendor decline list (use bitsight-find-declining-vendors), or for a polished executive PDF (use bitsight-generate-supply-chain-risk-report).
version: 2026.247
tags: CM, Third Party, Supply Chain, Exposure and Resilience
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
---

# Bitsight Assess Supply Chain Resilience

## Purpose

Answers one board-level question about **your third-party portfolio**: *"Do our vendors introduce
meaningful risk, and is our supply chain getting safer or riskier than last week / month / quarter /
year?"*

It aggregates the monitored portfolio into a single supply-chain read:

- the **rating distribution** — how many vendors are advanced / intermediate / basic, plus median
  and mean;
- the **weakest risk vectors** across the portfolio (where the most vendors fall below average);
- the **trend** over a chosen timeframe — the median move, and how many vendors slipped into or
  climbed out of the risky band.

The trend is **stateless**: the baseline is obtained by re-issuing the *same* statistics call
back-dated to Bitsight's own historical figures for the *same portfolio membership* — nothing is
stored between runs, and it is a true "our current vendors, then vs. now" comparison. Optionally it
also names the N riskiest (lowest-rated) vendors.

Read-only. It summarizes ~tens of thousands of vendors — it does not enumerate them, assess a single
vendor's posture, detect live victimization, or produce a formatted report.

## Approach

This skill runs `scripts/assess_supply_chain_resilience.py` — a self-contained Python CLI with no
third-party dependencies. Endpoints verified against the Bitsight MCP.

1. **Current state** — `GET /v1/portfolio/statistics?types=ratings,risk_vector_averages`. The
   portfolio is **implicit own-org** (no GUID); `--scope`, `--tier`, or `--folder` narrow it.
   Returns `ratings{median_rating, mean_rating, min_rating, max_rating, entity_count_by_bucket{advanced, intermediate, basic}}`
   and `risk_vector_averages[]{risk_vector, risk_vector_slug, average_grade, companies_below_average, percent_companies_below_average}`.
   - `vendor_count` = sum of the three buckets; `risky_vendor_count` = the `--risky-band` bucket
     (default `basic`); `risky_pct` = that share of the portfolio.
   - **`weakest_vectors`** = `risk_vector_averages` sorted by `percent_companies_below_average`
     descending, top ~5 — the ranking is the value-add; the raw array doesn't say what's weak.
2. **Back-dated baseline** — the *same* statistics call with `rating_date = today − window_days`.
   Because it reuses the same membership, the deltas are a genuine then-vs-now comparison, not a
   re-sampled portfolio. From it: `median_delta`, `risky_count_delta` (negative = safer — the most
   business-legible field), and `advanced_count_delta`.
   - `direction` fold: `improving` if `median_delta ≥ flat_threshold`; `declining` if
     `median_delta ≤ −flat_threshold`; when the median is inside the dead-band, a material shift in
     the risky-band count (≥1% of the portfolio) breaks the tie; else `flat`. **`unknown`** whenever
     the baseline can't be read — never inferred as `flat`.
   - The `rating_date` must be within one year, so `year` (365d) is the maximum window.
3. **Optional — name the riskiest vendors** (`--name-riskiest N`) — `GET /v2/portfolio?sort=rating&fields=name,rating,industry.name&limit=N`
   (lowest-rated first). Enrichment only: if it fails, `riskiest_vendors` is `[]` and the aggregate
   answer still stands.

## Before Starting

Confirm before running. If missing, ask before proceeding.

**1. API token — confidential**

Do NOT display or echo `BITSIGHT_API_TOKEN` (or `BITSIGHT_API_JWT`). Check the shell environment,
then `.env`/`.envrc`. If missing:
> *"Please set your Bitsight API key: `export BITSIGHT_API_TOKEN=<your-key>` (or in a `.env` file).
> Find it under Account → User API Token in the Bitsight portal."*

Never ask the user to paste the token into chat.

**2. Scope**

The skill reads **your monitored vendor portfolio** (auto-resolved; no GUID). Narrow it with
`--scope tprm` (third-party vendors only), `--tier`, or `--folder`. Pick the trend window with
`--window` (default `year`) or `--custom-days`, choose which band counts as risky with
`--risky-band`, and add `--name-riskiest N` to list the lowest-rated vendors.

## Authentication

`BITSIGHT_API_TOKEN` is sent as the HTTP Basic username (empty password); a `BITSIGHT_API_JWT`, if
set, is sent as a bearer token and its `portal_host` claim also selects the API base. These
endpoints live on the SPM/ratings host (`https://api.bitsighttech.com`); the script resolves the
base automatically (JWT `portal_host` → `BITSIGHT_API_BASE` → the ratings host default) and applies
the `/customer-api` rule where required. Every request includes `User-Agent: <bitsight-user-agent>`,
set automatically.

## Running the Script

```bash
BITSIGHT_API_TOKEN=<token> python3 <skill-dir>/scripts/assess_supply_chain_resilience.py
```

**A year trend over third-party vendors, as text:**
```bash
python3 <skill-dir>/scripts/assess_supply_chain_resilience.py --scope tprm --window year --format text
```

**A quarter view naming the 5 riskiest vendors:**
```bash
python3 <skill-dir>/scripts/assess_supply_chain_resilience.py --window quarter --name-riskiest 5
```

**Scoped to a critical-vendor tier:**
```bash
python3 <skill-dir>/scripts/assess_supply_chain_resilience.py --tier <tier-guid> --risky-band intermediate
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--window` | `year` | Trend timeframe: `week`(7d) / `month`(30d) / `quarter`(90d) / `year`(365d). |
| `--custom-days` | — | Override `--window` with an exact back-date of N days (≤365). |
| `--scope` | portfolio | `tprm` = third-party vendors only, `spm` = own subsidiaries; omit for the whole portfolio. |
| `--tier` / `--folder` | — | Scope to a portfolio tier / folder GUID (mutually exclusive). |
| `--risky-band` | `basic` | Which rating band counts as "risky": `advanced` / `intermediate` / `basic`. |
| `--name-riskiest` | `0` | Also return the N lowest-rated vendors by name (0 = off). |
| `--flat-threshold` | `10` | `\|median delta\|` below this is `flat` unless the risky-band count shifts materially. |
| `--format` | `json` | `json` or `text`. |
| `--timeout` / `--retries` | `60` / `3` | Per-request timeout (s); HTTP retries on 429/5xx/network. |
| `--api-token` / `--api-jwt` | env | Override `BITSIGHT_API_TOKEN` / `BITSIGHT_API_JWT` (bearer outranks token). |

## Understanding the Output

The example below is **illustrative only** — a fictional portfolio with made-up values to show the
shape of the response. It is not real data. A live run returns your own portfolio's actual figures.

```json
{
  "success": true,
  "window": "year",
  "window_days": 365,
  "scope": "tprm",
  "risky_band": "basic",
  "as_of": "2026-09-03",
  "baseline_date": "2025-09-03",
  "vendor_count": 1200,
  "median_rating": 740,
  "mean_rating": 720,
  "min_rating": 300,
  "max_rating": 820,
  "distribution": { "advanced": 610, "intermediate": 520, "basic": 70 },
  "risky_vendor_count": 70,
  "risky_pct": 5.83,
  "weakest_vectors": [
    { "risk_vector": "application_security", "name": "Web Application Headers", "average_grade": "C", "pct_below_average": 32.5, "companies_below_average": 390 },
    { "risk_vector": "ssl_certificates", "name": "SSL Certificates", "average_grade": "B", "pct_below_average": 24.8, "companies_below_average": 298 }
  ],
  "median_delta": 10,
  "risky_count_delta": -12,
  "advanced_count_delta": 18,
  "direction": "improving",
  "riskiest_vendors": [
    { "name": "Example Vendor A (illustrative)", "rating": 320, "industry": "Manufacturing" }
  ],
  "data_complete": true,
  "sources_used": ["cm"],
  "coverage": "full",
  "notes": []
}
```

- **`direction`**: `improving` / `declining` / `flat` from `median_delta` (with the risky-band count
  as tiebreaker). `unknown` means the baseline call failed — **unknown ≠ flat**; report current-only
  and say the trend is unavailable, never imply stability.
- **`risky_count_delta`** is the most business-legible figure: *"12 fewer vendors are in the risky
  band than a year ago"* (negative = safer).
- **`coverage`**: `full` (current + baseline), `partial` (current only — baseline unavailable),
  `none` (the statistics call failed → all metrics `null`).
- **`data_complete: false` / `null` metrics** mean the call failed — that is **unknown**, never "no
  vendor risk" or a clean supply chain.
- **`weakest_vectors`** is ranked by the share of vendors below the portfolio average for that
  vector — it names *where* the supply chain is soft, not any single vendor.
- **`riskiest_vendors`** is populated only with `--name-riskiest`; its failure never degrades the
  aggregate answer.

## Relaying Results

1. Lead with the headline: vendor count, median rating and `direction`, and the risky-band count with
   its delta — e.g. *"1,200 vendors, median 740, improving over the year: 12 fewer in the risky band,
   18 more reached advanced."*
2. Name the top one or two `weakest_vectors` as where the portfolio is soft.
3. With `--name-riskiest`, list the lowest-rated vendors — but frame them as the tail of an
   improving/declining aggregate, not the whole story.
4. If `notes` is non-empty, surface it — especially the baseline-unavailable and scope caveats —
   rather than implying full coverage.
5. Never present `direction: "unknown"`, `coverage: "none"`, or `null` metrics as "flat" or "no
   vendor risk." Distinguish unknown (call failed) from a confirmed low risky count (only credible
   when `data_complete: true`).

If the script exits with an error (`success: false`):
- **`MISSING_CREDENTIALS`** → ask the user to set `BITSIGHT_API_TOKEN`.
- **`BAD_REQUEST`** → check flags (`--tier` and `--folder` are mutually exclusive; `--custom-days` ≤ 365).
- **`AUTH_FAILED` / `PERMISSION_DENIED`** → the token is invalid or lacks CM/portfolio access.
- **`NETWORK_ERROR` / `HTTP_ERROR`** → transient; retries with backoff already ran — suggest retrying.
