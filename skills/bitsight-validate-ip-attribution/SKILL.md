---
name: bitsight-validate-ip-attribution
description: Validates whether one or more specific IP addresses are correctly attributed to a named company, answering "what does Bitsight claim, and what is true right now?" side by side. It reads Bitsight's own attribution reasons (source, matched CIDR, each reason's category / expiry / last-seen) and independently probes the live IP (RDAP, reverse DNS, TLS certificate, whois), then states for every factor whether it SUPPORTS, CONTRADICTS, or was NEVER CHECKED and returns a per-IP verdict (confirmed / disputed / uncorroborated / unsubstantiated / live-only / mixed). Use to defend or overturn a specific attribution, triage a vendor-alert IP, or audit an EASM footprint. Do NOT use to list a company's whole asset inventory (use an asset-inventory skill), to find who inside your org owns a first-party asset (use an ownership skill), or to mutate/suppress attributions.
version: 2026.257
tags: SPM, Attack Surface Management, Attribution, EASM
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
---

# Bitsight Validate IP Attribution

## Purpose

Answers a single, sharp question for one or more specific IP addresses: **is this IP correctly
attributed to this company — and can we prove it right now?** It puts two columns side by side:

- **What Bitsight claims** — Bitsight's own attribution reasons for the IP against the company's
  footprint: the source (RIR/BGP/customer-provided), the matched CIDR, and every reason with its
  category, whether it is **expired**, and when it was **last seen**.
- **What is true right now** — independent live probes of the IP: **RDAP**, **reverse DNS**, the
  **TLS certificate** on port 443, and **whois**. Each probe is labelled `support`, `contradict`,
  `inconclusive`, `not_checked`, or `error`.

A verdict that only repeats Bitsight's cached reasoning is not a validation, so the skill never
collapses the two columns. It returns a transparent per-IP verdict — `confirmed`, `disputed`,
`uncorroborated`, `unsubstantiated`, `live_only`, or `mixed` — together with the exact list of
factors that support it, contradict it, or could not be checked. Read-only: it never mutates or
suppresses anything.

Intended for TPRM analysts, SOC analysts triaging a vendor-alert IP, and attribution/EASM engineers
who need to defend or overturn a specific attribution.

## Approach

The skill runs `scripts/validate_ip_attribution.py` — a self-contained Python CLI with no
third-party dependencies.

1. **Resolve the company** (skipped if `--company-guid` is given) — `GET /v1/companies/search`
   by `name=` or `domain=` → the company `guid`, `name`, and `primary_domain`. The name and
   domain become the *footprint tokens* the live probes match against.
2. **Read Bitsight's claim** — for each IP, `GET /v1/companies/{guid}/infrastructure/reasons`
   with `net_cidr=<ip>` (and `all_matching_cidrs`, optionally `include_subsidiaries`). A `null`
   body means Bitsight does **not** attribute the IP to the company; a non-empty array is the
   attribution, one entry per matching CIDR, each with its `source` and `reasons[]`. A
   `Customer-Provided` match carries no derivation reasons — it is asserted, not derived.
3. **Probe the live IP** (unless `--skip-live`) — RDAP (`rdap.org/ip/<ip>`), reverse DNS (`PTR`),
   the TLS certificate CN/SANs on `:443`, and port-43 whois (via the IANA referral). Each probe's
   evidence is compared to the footprint tokens: a company domain/brand hit → `support`; a known
   cloud/hosting provider → `inconclusive` (companies host there legitimately); a different named
   organization → `contradict`; nothing usable → `inconclusive`; the probe could not run →
   `not_checked`.
4. **Decide the verdict** — folds the Bitsight claim and the live factors per IP (see
   *Understanding the Output*).

**Design invariants.** `not_checked ≠ contradict` (a probe that could not run never counts against
an attribution). A cloud/hosting provider in RDAP/PTR is `inconclusive`, never a contradiction —
hosting on AWS does not disprove ownership. Bitsight reasons flagged `is_expired` are surfaced as
expired, not silently dropped. Private/reserved IPs and CIDRs skip the host probes with an explicit
`not_checked` reason rather than guessing.

## Before Starting

Confirm before running. If missing, ask before proceeding.

**1. API token — confidential**

Do NOT display or echo `BITSIGHT_API_TOKEN` (or `BITSIGHT_API_JWT`). Check the shell environment,
then `.env`/`.envrc`. If missing:
> *"Please set your Bitsight API key: `export BITSIGHT_API_TOKEN=<your-key>` (or in a `.env` file).
> Find it under Account → User API Token in the Bitsight portal."*

Never ask the user to paste the token into chat.

**2. Scope**

You need the **IP(s)** to validate and the **company** they are claimed to belong to (a name or
domain via `--company`, or a `--company-guid`). Reading a company's attribution reasons requires the
"view infrastructure" entitlement on that company; a `403` means the token lacks it for that GUID.

## Authentication

`BITSIGHT_API_TOKEN` is sent as the HTTP Basic username (empty password); a `BITSIGHT_API_JWT`, if
set, is sent as a bearer token and its `portal_host` claim also selects the API base. The company
and infrastructure endpoints live on the SPM/ratings host (`https://api.bitsighttech.com`); the
script resolves the base automatically (JWT `portal_host` → `BITSIGHT_API_BASE` → the ratings host
default) and applies the `/customer-api` rule where required. Every request includes
`User-Agent: <bitsight-user-agent>`, set automatically. The live RDAP/DNS/TLS/whois probes are
unauthenticated and hit the public internet, not Bitsight.

## Running the Script

```bash
BITSIGHT_API_TOKEN=<token> python3 <skill-dir>/scripts/validate_ip_attribution.py 203.0.113.10 --company example.com
```

**Validate several IPs against a company GUID, text output:**
```bash
python3 <skill-dir>/scripts/validate_ip_attribution.py 203.0.113.10 198.51.100.4 \
  --company-guid <guid> --company-domain example.com --format text
```

**Bitsight claim only (no live probes — fast, offline-safe):**
```bash
python3 <skill-dir>/scripts/validate_ip_attribution.py 203.0.113.10 --company-guid <guid> --skip-live
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `ip` (positional) | — | One or more IP addresses or CIDRs to validate (required, repeatable). |
| `--company` | — | Company name or domain; resolved via `/v1/companies/search`. |
| `--company-guid` | — | Company GUID; skips name/domain resolution. |
| `--company-name` | — | Company name for live-evidence matching when `--company-guid` is used. |
| `--company-domain` | — | Known company domain(s) to match live evidence against. Repeatable. |
| `--include-subsidiaries` | off | Also consider CIDRs attributed to the company's subsidiaries. |
| `--no-all-matching` | off | Only the single best-matching CIDR (default: all matching CIDRs). |
| `--skip-live` | off | Report only Bitsight's claim; no RDAP/DNS/TLS/whois probes. |
| `--live-timeout` | `6.0` | Per-probe timeout for live checks, seconds. |
| `--timeout` | `30` | HTTP timeout for Bitsight API calls, seconds. |
| `--retries` | `3` | HTTP retry attempts on 429/5xx/network errors. |
| `--format` | `json` | `json` or `text`. |
| `--api-token` | env | Override `BITSIGHT_API_TOKEN`. |
| `--api-jwt` | env | Override `BITSIGHT_API_JWT` (bearer; outranks the token). |

## Understanding the Output

*The values below are fictional and illustrative only.*

```json
{
  "success": true,
  "company": { "guid": "<your-company-guid>", "name": "Example Corp (illustrative)", "primary_domain": "example.com" },
  "footprint_tokens": { "domains": ["example.com"], "brands": ["example"] },
  "live_checks_run": true,
  "ip_count": 1,
  "verdict_counts": { "confirmed": 1 },
  "results": [
    {
      "ip": "203.0.113.10",
      "bitsight_claim": {
        "attributed": true,
        "match_count": 1,
        "sources": ["ARIN"],
        "has_reasons": true,
        "all_reasons_expired": false,
        "matches": [
          { "cidr": "203.0.113.0/24", "source": "ARIN", "as_number": 64500,
            "whois_url": "/rdap/?query=203.0.113.0/24",
            "reasons": [
              { "category": "organization_name", "value": "Example Corp",
                "is_expired": false, "record": "WHOIS", "last_seen": "2026-06-01" }
            ] }
        ]
      },
      "live_evidence": {
        "rdap":        { "status": "support", "registrant": "Example Corp", "country": "US", "evidence": "Example Corp" },
        "whois":       { "status": "support", "registrant": "Example Corp" },
        "reverse_dns": { "status": "support", "ptr": "mail.example.com" },
        "tls":         { "status": "inconclusive", "note": "no TLS on :443 (timeout)" }
      },
      "verdict": "confirmed",
      "verdict_reason": "Bitsight attributes the IP and live evidence corroborates it",
      "factors_supporting": ["rdap", "whois", "reverse_dns"],
      "factors_contradicting": [],
      "factors_unchecked": []
    }
  ],
  "skill_version": "2026.257"
}
```

**Verdicts** (per IP):
- **`confirmed`** — Bitsight attributes the IP *and* at least one live factor supports it.
- **`disputed`** — a live factor contradicts (ties the IP to a *different* named org) and none support.
- **`uncorroborated`** — Bitsight attributes the IP but no live factor could confirm it (cached
  reasoning only). **Not the same as clean** — treat as "unverified", especially if
  `all_reasons_expired` is true.
- **`live_only`** — Bitsight does **not** attribute the IP, but live evidence ties it to the company:
  a possible attribution *gap* worth surfacing.
- **`unsubstantiated`** — neither Bitsight nor any live factor ties the IP to the company.
- **`mixed`** — factors both support and contradict; route to human review.

**Factor statuses:** `support` (footprint hit), `contradict` (a different org), `inconclusive`
(cloud/hosting provider, or nothing identifying), `not_checked` (probe could not run — e.g. no PTR,
no TLS, private IP), `error`. `not_checked`/`error` never count against an attribution.

## Relaying Results

1. Lead with the per-IP verdict and its one-line reason. For a batch, summarize `verdict_counts`
   first, then drill into the non-`confirmed` IPs.
2. Always present the two columns together — "Bitsight claims X *because* …; live evidence
   says Y". Never report the verdict without the supporting/contradicting/unchecked factor lists.
3. Call out **`uncorroborated`** and **expired reasons** explicitly — a stale WHOIS reason that no
   live probe can confirm is exactly the case an analyst needs to see, not a clean pass.
4. Flag **`live_only`** as a coverage gap (Bitsight may be missing the CIDR) and **`disputed`** as a
   likely mis-attribution to escalate. Treat `mixed` as needs-human-review.
5. Never present `inconclusive`/`not_checked` as either confirmation or contradiction.

If the script exits with an error (`success: false`):
- **`MISSING_CREDENTIALS`** → ask the user to set `BITSIGHT_API_TOKEN`.
- **`NO_COMPANY`** → the name/domain matched nothing; ask for a `--company-guid`.
- **`AUTH_FAILED` / `PERMISSION_DENIED`** → the token is invalid or lacks "view infrastructure" for
  that company GUID.
- **`NOT_FOUND`** → the company GUID is wrong or not visible to this account.
- **`NETWORK_ERROR` / `HTTP_ERROR`** → transient; retries with backoff already ran — suggest retrying.
