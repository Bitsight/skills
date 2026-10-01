---
name: bitsight-check-certificate-expiry
description: Check if your SPM companies have any SSL certificates that will expire within a few days. This also checks to see whether certificates have been renewed since Bitsight's last scan.
version: 1.0
tags: SPM
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
scope: portfolio
---

# Skill: Bitsight SSL Certificate Expiry Checker

## Overview

This skill uses a provided Python script, [scripts/check_certificate.py](scripts/check_certificate.py), to do all the heavy lifting:

1. Discovers all "my company" and "mysub" entities from the Bitsight portfolio.
2. Fetches all SSL certificate findings for those companies.
3. For each company, walks upcoming expirations in order (probing endpoints live with a shared cache so each endpoint is contacted at most once) to find the first certificate that has **not** yet been renewed — looking up to `NEXT_EXPIRY_LOOKAHEAD_DAYS` ahead.
4. Checks all certificates expiring within `EXPIRY_THRESHOLD_DAYS` and reports any still-expiring endpoints.
5. Prints a single **JSON object** describing the results to stdout.
6. Exits non-zero if any action is required.

**Do not reimplement this logic.** Run the script — there may be a lot of findings to check and they could overflow your context window, and the script also performs live TLS probing with careful certificate-reading and retry logic. The script emits structured JSON to stdout; **you read that JSON and format it for the user** (Markdown report, Jira ticket, email, CSV, etc.).

When this skill is invoked, the user may want a specific output: a Markdown report, a Jira ticket, an email, a CSV, etc. **If the user does not say what they want done with the output, ask them before formatting.** If the desired output is a file, ask where to put it.

### TLS-intercepting proxies (e.g. Claude chat / Claude cowork)

A direct TLS probe cannot work behind a TLS-intercepting proxy: the proxy terminates TLS and presents its *own* re-signed certificate, so a socket read returns the proxy's expiry, never the origin's. This affects `openssl`, `curl`, and any direct socket too.

The script handles this automatically. It first probes `google.com` and checks the issuer is "Google Trust Services"; if not, a proxy is assumed and it **falls back to Certificate Transparency logs (crt.sh)** to determine live expiry. CT is proxy-immune (it's an HTTPS API returning JSON), but it reflects *issued* certs rather than what is deployed, and cannot check bare IPs or non-standard ports. The chosen method is reported in the output as `probe_method` (`"socket"`, `"ct"`, or `"api"`), with caveats in `probe_method_note`. Force a method with `--probe-method {auto,socket,ct,api}` if needed.

The **best option behind a TLS-intercepting proxy** is `--probe-method api`: it asks the Bitsight **live-certificates API** to probe each finding's endpoint *server-side* (outside your network) and return the actually-served leaf certificate. This is both proxy-immune **and** deployment-accurate (unlike `ct`, which only sees *issued* certs). It batches findings per company (up to 200 observation IDs per call). The API refuses outbound connections to non-public (private/loopback/link-local/reserved) addresses. `auto` does not select `api`; request it explicitly.

## Steps

### 0. API Token — Confidential

Do NOT load, display, or echo the `BITSIGHT_API_TOKEN` value in the conversation. The script reads it itself from:
1. Shell environment (`BITSIGHT_API_TOKEN`)
2. A `.env` file in the working directory (via `python-dotenv`)

If it is not set, the script exits `2` with `{"status": "config_error", ...}`. In that case ask the user to set it — do not ask them to paste the token into the conversation:

*"Please set your Bitsight API token in your shell environment (`export BITSIGHT_API_TOKEN=...`) or a `.env` file, then try again. You can find your token under **Account → User API Token** in the Bitsight portal."*

### 1. Install dependencies (once)

```
pip install requests python-dotenv cryptography
```

### 2. Run the script

```
python scripts/check_certificate.py [--threshold DAYS] [--lookahead DAYS] [--timeout SECS]
```

Configuration — every value is settable by CLI flag, environment variable, or `.env`; **CLI flag overrides env var overrides default**:

| CLI flag | Env var | Default | Description |
|----------|---------|---------|-------------|
| `--api-token TOKEN` | `BITSIGHT_API_TOKEN` | — (required) | Bitsight API token |
| `--threshold DAYS` | `EXPIRY_THRESHOLD_DAYS` | `5` | Days ahead to flag in the attention report |
| `--lookahead DAYS` | `NEXT_EXPIRY_LOOKAHEAD_DAYS` | `30` | How far to walk for the next unrenewed cert |
| `--timeout SECS` | `CONNECT_TIMEOUT` | `10` | TCP connect timeout when probing |
| `--probe-method M` | `CERT_PROBE_METHOD` | `auto` | `socket`, `ct` (crt.sh, proxy-immune), `api` (Bitsight live-certificates, server-side, proxy-immune + deployment-accurate), or `auto` |

No company GUID is required — companies are auto-discovered from the portfolio. Progress is written to **stderr**; the JSON result is the only thing on **stdout**, so capture stdout cleanly (e.g. `python scripts/check_certificate.py > result.json`).

**You must set `User-Agent: <bitsight-user-agent>` on every Bitsight API request.** The provided script already does this, so when you run the script you do not need to do anything extra. If you ever call the Bitsight API directly (e.g. for ad-hoc debugging) you must set this header yourself.

### 3. Read the JSON output

The script prints one JSON object. Shape:

```jsonc
{
  "status": "ok",                       // or "config_error"
  "generated": "2026-06-09T12:00:00+00:00",
  "threshold_days": 5,
  "lookahead_days": 30,
  "probe_method": "socket",             // "socket" (direct TLS), "ct" (crt.sh), or "api" (Bitsight live-certificates)
  "probe_method_note": null,            // caveats string when probe_method == "ct" or "api"
  "proxy_warning": null,                // string if a TLS-intercepting proxy was detected
  "companies_checked": [
    { "name": "Acme Inc", "guid": "...", "my_company": true }
  ],
  "next_expiry_by_company": [           // one entry per company
    {
      "company_name": "Acme Inc",
      "reason": "unrenewed_within_lookahead",  // why cert is / isn't populated (see below)
      "cert": {                         // null unless reason == "unrenewed_within_lookahead"
        "subject": "foo.com",           // friendly name (see "Cert naming" below)
        "subject_dn": "CN=foo.com",     // raw certificate subject DN
        "expiry_date": "2026-05-01",    // Bitsight's recorded expiry
        "days_away": 8,
        "already_renewed": false,
        "probe_results": [
          { "hostname": "foo.com", "port": 443,
            "address": "203.0.113.7",   // IP actually connected to (origin, not a proxy); null if not captured
            "live_expiry": "2026-05-01", "days_until_expiry": 8,
            "status": "expiring" }      // "renewed" | "expiring" | an error string
        ]
      },
      "nearest_expiry": {               // the soonest upcoming cert, even if beyond lookahead; null if none
        "subject": "foo.com",
        "bitsight_expiry": "2026-05-01",  // Bitsight's recorded (possibly stale) date
        "bitsight_days_away": 8,
        "live_status": "renewed",         // "renewed" | "expiring" | error | "not_checked"
        "live_expiry": "2026-08-03"       // actual served-cert expiry from the probe; null if not_checked
      }
    }
  ],
  "attention_records": [                // certs expiring within threshold that are still expiring/unreachable
    {
      "company_name": "Acme Inc",
      "subject": "foo.com",             // friendly name (see "Cert naming" below)
      "subject_dn": "CN=foo.com",       // raw certificate subject DN
      "bitsight_expiry": "2026-05-01",
      "days_away": 3,
      "endpoints": [
        { "hostname": "foo.com", "port": 443, "address": "203.0.113.7",
          "live_expiry": "2026-05-01", "days_until_expiry": 3, "status": "expiring",
          "attribution": {
            "sources": ["DNS"],
            "reasons": ["foo.com maps to 203.0.113.7 (DNS_hostname, DNS, last seen 2026-06-29)"]
          } }
      ]
    }
  ],
  "summary": {
    "findings_checked": 12,             // unique certs within the threshold window
    "unique_endpoints_probed": 30,      // total live endpoints contacted across all walks
    "renewed": 25,
    "still_expiring_or_unreachable": 5
  },
  "action_required": true
}
```

Interpreting `next_expiry_by_company[].reason` — explains why `cert` is or isn't populated. `cert` is **only** non-null for `unrenewed_within_lookahead`; the other three are not problems:
- `unrenewed_within_lookahead` — a cert expiring within the lookahead window is **not yet renewed**. This is the actionable case; `cert` is populated.
- `all_renewed` — certs expire within the lookahead window but every one has already been renewed. Good news.
- `none_within_lookahead` — the company's nearest cert expires *beyond* the lookahead window (default 30 days). Nothing expiring soon. See `nearest_expiry` for when it actually expires.
- `no_upcoming_findings` — no SSL findings with a future expiry for this company (no data, or all already expired).

Most `cert: null` companies are `none_within_lookahead` — expected, not a bug. If you want to surface companies further out, raise `--lookahead`. Note that in `ct` mode `all_renewed` will be very common because crt.sh reports the newest *issued* cert (usually later than Bitsight's snapshot); treat those as "likely renewed, not confirmed deployed".

`nearest_expiry` reports **both** Bitsight's recorded date (`bitsight_expiry`, which may be stale) and what the live probe actually found (`live_status` + `live_expiry`). When `live_status` is `"renewed"`, the cert was renewed since Bitsight's scan — quote `live_expiry` (the new date), **not** `bitsight_expiry`/`bitsight_days_away`. `live_status: "not_checked"` means the cert is beyond the lookahead and was never probed, so only the Bitsight date is known.

Cert naming (`subject`):
- `subject` is a **friendly label**, chosen to be the name most relevant to what was checked: an observed endpoint hostname if it appears in the certificate's SAN list, otherwise the certificate's CN, otherwise the first SAN. `subject_dn` always holds the raw certificate subject DN (e.g. `CN=foo.com`) for reference. Use `subject` in user-facing output; fall back to `subject_dn` only if `subject` looks ambiguous.

Each flagged (non-renewed) endpoint also carries an `attribution` object explaining **why that host is attributed to the company** — use it to tell the owner how the asset got into their Bitsight footprint. It has `sources` (e.g. `"DNS"`, `"Certificates"`, `"Registered Domain"`, `"Primary Domain"`, `"Customer-Provided"`) and `reasons` (human-readable evidence lines such as `"foo.com maps to 203.0.113.7 (DNS_hostname, DNS, last seen …)"` or `"admin@example.com used to register example.com (point_of_contact_email, WHOIS, …, expired)"`). `Customer-Provided` (empty `reasons`) means the customer told Bitsight they own this asset. The field is present only on endpoints that need action (renewed endpoints are not annotated); it may be `{"sources": [], "reasons": []}` if the lookup returned nothing, and absent entirely if the lookup failed.

Each per-endpoint result also carries `address` — the IP actually connected to. In `api` mode this is the IP the Bitsight service reached server-side (the real origin, never an in-network proxy). In `socket` mode it is the local socket's peer (the origin when there is no proxy, but the proxy's IP when one is present). In `ct` mode it is always `null` (no connection is made). It may also be `null` when the probe failed before connecting.

Interpreting per-endpoint `status`:
- A per-endpoint `status` of `"renewed"` means the live certificate now expires later than Bitsight recorded (it was renewed since the last scan). `"expiring"` means it still expires soon. Any other value is an error string — the endpoint could not be confirmed renewed.
- In `socket` mode, error strings look like `"connection_timeout"`, `"certificate_verify_failed"`.
- In `ct` mode, error strings look like `"ct_no_ip_lookup"` (bare IP — CT can't be queried), `"ct_no_match"` (no current CT-logged cert for the domain), or `"ct_request_error"/"ct_http_5xx"` (crt.sh unreachable/slow). When `probe_method` is `"ct"`, read `probe_method_note` and tell the user that "renewed" reflects an *issued* cert, not confirmed deployment.
- In `api` mode, an endpoint the API could not reach carries the API's own error string (e.g. a refused non-public address) or `"api_no_certificate"`; `"api_bad_pem"` means the returned PEM could not be parsed; `"api_not_probed"` means the endpoint was not among the API's returned results (no matching observation / missing hostname or port). Unlike `ct`, a `"renewed"` here reflects the actually-deployed leaf cert.

### 4. Exit code

- `0` — no action needed.
- `1` — action needed (a threshold record is still expiring/unreachable, or a company has an unrenewed cert within the lookahead window). `action_required` mirrors this.
- `2` — configuration error (missing token, no companies found). A TLS-intercepting proxy no longer causes exit `2`; the script falls back to CT and continues.

### 5. Produce the output the user asked for

Using the JSON, render the result in the form the user requested. If they did not specify, ask first. Some common shapes:

- **Markdown report** — Companies Checked, a "Next Unrenewed Certificate Expiry (per company)" table, an "Endpoint Detail" section, a Summary block, and a "Certificates Requiring Attention" section grouped by company+cert, sorted by earliest expiry.
- **Jira ticket / email** — one item per company (or per attention record) that needs action.
- **CSV** — one row per attention record or per company.

Lead with what needs action (`attention_records` and any `next_expiry_by_company[].cert` where `already_renewed` is false), and note companies where everything is already renewed. For each flagged endpoint, surface its `attribution` (why the host is attributed to the company) so the owner knows how the asset entered their footprint — e.g. "attributed via DNS: foo.com → 203.0.113.7" or "customer-provided".

---

## Reference: how the script works

The detail below documents the behavior already implemented in [scripts/check_certificate.py](scripts/check_certificate.py). It is the source of truth for *what the script does* — you should not need to reimplement any of it, but it helps when interpreting the JSON or debugging an environment issue.

### Discovering target companies

```
GET https://api.bitsighttech.com/v2/portfolio
    ?fields=guid,name,my_company,subscription_type,subscription_type_key&scope=spm-and-tree
```

Authentication is HTTP Basic Auth — API token as username, empty password. The `User-Agent` header must be set to `<bitsight-user-agent>` on every Bitsight request. Read-only. Target companies are those whose **`subscription_type.slug`** is `"my_company"` or `"my_subsidiary"`. The top-level `my_company` and `subscription_type_key` fields are requested but are often absent from the response, so the slug is the reliable signal (the script treats the other two as fallbacks only). The `"continuous_monitoring"` slug is **not** a target.

### Fetching SSL findings

```
GET https://api.bitsighttech.com/ratings/v1/companies/{guid}/findings
    ?format=json&affects_rating=true&risk_vector=ssl_configurations&page_count=100
```

Uses `risk_vector` (not `risk_category`). Pagination follows the `next` field; HTTP 404 is treated as "no findings"; HTTP 429 triggers exponential backoff. Fetches run concurrently across companies.

The leaf certificate lives at `details.diligence_annotations.certchain[0]` (`endDate`, `startDate`, `subjectName`, `issuerName`, `dnsName[]`). `endDate` is `"YYYY-MM-DD HH:MM:SS"` in UTC with no timezone suffix, parsed with `strptime(..., "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)`. Findings with no `certchain` are skipped.

Endpoints to probe come from `details.diligence_annotations.attributed_observed_ips[]` (each `"hostname[ip]:port"` or `"ip:port"`, parsed with `r'^([^\[]+?)(?:\[.*?\])?:(\d+)$'`), falling back to `assets[].asset` at port 443. Findings are deduplicated by `(subjectName, endDate)` with endpoint sets **and** SAN lists (`dnsName[]`) unioned.

The friendly `subject` shown in output is resolved from the unioned data: an observed endpoint hostname that appears in the cert's SAN list wins, else the CN parsed from `subjectName`, else the first SAN, else the raw `subjectName`. The raw DN is preserved as `subject_dn`.

### Probe cache and TLS handling

Each `(hostname, port)` is contacted at most once and cached (threshold-independent raw data), then reclassified per threshold. Because only expiry dates matter (not chain trust or hostname match), the probe retries while relaxing verification one axis at a time — adding `OP_LEGACY_SERVER_CONNECT` on `UNSAFE_LEGACY_RENEGOTIATION_DISABLED`, and dropping to `CERT_NONE` on `SSLCertVerificationError`. The context also lowers `minimum_version` to TLS 1.0 and sets `DEFAULT@SECLEVEL=0`, so older endpoints that only serve TLS 1.0/1.1 (and the weaker ciphers/keys they use) can still be reached to read their expiry. The cert is read via `getpeercert(binary_form=True)` + `cryptography.x509.load_der_x509_certificate(...).not_valid_after_utc`, which works regardless of verify mode. All datetime comparisons are UTC-aware.

In `ct` mode the live expiry comes instead from `GET https://crt.sh/?q=<domain>&output=json&exclude=expired`: the script takes the latest `not_after` among logged certs whose names match the hostname (exact or wildcard), memoized per hostname. This is proxy-immune but domain-keyed, so bare IPs and specific ports cannot be checked. crt.sh can be slow (tens of seconds) for domains with large CT history; the script uses a 60s timeout with retry/backoff and degrades to a `ct_*` error status rather than failing.

In `api` mode the live cert comes from `POST https://api.bitsighttech.com/ratings/v1/companies/{guid}/findings/live-certificates` with body `{"rolledup_observation_ids": [...], "timeout": <secs>}`. Each finding's `rolledup_observation_id` is collected during parsing; before the per-endpoint walks run, the script batches a company's observation IDs (up to `API_PROBE_BATCH` = 200 per call, scoped to certs expiring within `max(threshold, lookahead)` days) and POSTs them. The service probes each endpoint server-side and returns `results[]` of `{rolledup_observation_id, endpoint, hostname, port, address, pem, error}` (`address` is the IP the service connected to). The script parses each returned `pem` with `x509.load_pem_x509_certificate(...)` for its `not_after` and fills `_probe_cache` so the walks become pure cache reads (a miss yields `api_not_probed`). The key the walks use (parsed from the finding's observed endpoints) often differs from what the API echoes — a finding may record a bare IP (`203.0.113.58:443`) while the API returns the enriched form (`gateway.example.net[203.0.113.58]:443`, `hostname` set, `address` = the IP). So each result's cert is stored under every key form the walk might use: the IP (`address`), the `hostname`, the parsed echoed `endpoint`, and the finding's own endpoint key (joined via the `rolledup_observation_id` that was sent). Storing one cert under several aliases is harmless — they all name the same endpoint. This is proxy-immune (the connection originates from the service, outside your network) and reflects the actually-deployed cert; the service refuses non-public addresses.

### Endpoint attribution (why a host is attributed)

After the threshold and per-company walks, the script explains why each **flagged** (non-renewed) endpoint is attributed to its company, via:

```
GET https://api.bitsighttech.com/v1/companies/{guid}/infrastructure/reasons/
    ?net_cidr=<ip>&all_matching_cidrs=true&include_subsidiaries=false&source.slug=      # for an IP host
    ?domain=<domain>&all_matching_domains=true&include_subsidiaries=false&source.slug=  # for a hostname
```

Read-only. The host is looked up under the company that owns the finding (name→guid map); IPs use the `net_cidr`/`all_matching_cidrs` form and domains use the `domain`/`all_matching_domains` form (feeding a hostname to `net_cidr` returns HTTP 400). `include_subsidiaries` is `false` (the `ATTR_INCLUDE_SUBSIDIARIES` constant) because each SPM company — my_company **and** each subsidiary — is discovered and queried on its own guid, so subsidiary infrastructure is already covered; flip the constant to `"true"` to explain subsidiary-attributed infra within a single parent query. The response is a list of `{source, reasons[], cidr, domain, …}`; each reason carries a `category`, `evidence.summary` (`from`→`to`) and `evidence.steps[]` (`relation`, `record`, `last_seen`). The script collapses these to `{sources, reasons}` (deduplicated, one summary line per reason) and attaches them to the endpoint. Lookups run concurrently, deduplicated by `(guid, host)` with a per-thread session; only non-renewed endpoints are queried (renewed ones need no action).

### Common mistakes (already handled by the script)

| Wrong | Right |
|-------|-------|
| `risk_category=ssl_certificates` | `risk_vector=ssl_configurations` |
| `details.distrusted_certificate.not_after` | `details.diligence_annotations.certchain[0].endDate` |
| `datetime.fromisoformat(endDate)` | `strptime(endDate, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)` |
| `assets[].port` for port | `attributed_observed_ips` parsed with regex |
| Filter on the top-level `my_company` / `subscription_type_key` fields (often absent) | Filter on `subscription_type.slug` (`"my_company"` or `"my_subsidiary"`) |
| `ssl.CERT_OPTIONAL` to skip verification | `ssl.CERT_NONE` — `CERT_OPTIONAL` still validates when a cert is presented |
| `getpeercert()` with `CERT_NONE` (returns `{}`) | `getpeercert(binary_form=True)` + `x509.load_der_x509_certificate()` |
| Catching `ssl.SSLError` to detect cert errors | Catch `ssl.SSLCertVerificationError` (subclass) |
| Probing the same endpoint multiple times | Cache raw cert data per `(host, port)` |
| Counting only threshold endpoints | `unique_endpoints_probed` counts all endpoints probed across every walk |
| Finding the next unrenewed cert globally | Find it **per company** |

## Required Libraries

```
requests
python-dotenv
cryptography
```

`ssl`, `socket`, `re`, `json`, `time`, `datetime`, `argparse`, `concurrent.futures` are standard library.
