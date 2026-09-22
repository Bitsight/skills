---
name: bitsight-generate-spm-insights
description: Answer "what specific security issues should I address first in my organization?" Use when an SPM analyst or IT/security manager asks for prioritised actions, threat ranking, or a security-posture summary for their own organisation. Produces a structured insight with summary, threats, risk vector highlights, and recommendations.
tags: CM
version: 1.0
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
---

# Skill: Bitsight SPM Insights

## Before Starting

The organisation's Bitsight company GUID is provided in the request. Do not run any company-resolution dialogue.

**API key — confidential**
Do NOT load, display, or echo the `BITSIGHT_API_KEY` value in the conversation. Check for it in this order:

1. Shell environment (`BITSIGHT_API_KEY`)
2. A `.env` or `.envrc` file in the working directory

If not found, ask the user to set it — do not ask them to paste the key directly into the conversation:
_"Please set your Bitsight API key in your shell environment (`export BITSIGHT_API_KEY=...`) or a `.env` / `.envrc` file, then try again. You can find your token under **Account → User API Token** in the Bitsight portal."_

## Authentication

All API calls use HTTP Basic Auth: API key as username, empty string as password. Set `User-Agent: bitsight-spm-insights/1.0` on all requests.

## Steps

### Step 1: Fetch Organisation Data

Issue all six HTTP requests **in parallel** for the supplied company GUID. Each call's result is treated as a source of truth — do not invent values, do not interpolate between sources. Compute `today` and `twelve_months_ago = today - 365 days` once before fetching.

All calls below are `GET` unless explicitly marked `POST`.

---

#### 1. Current Rating

Headline security rating, 90-day average, and analysis caveats. **Answers: What is the organisation's current security posture at a glance? Is the analysis subject to any caveats (low confidence, delegated controls, non-primary entity)?**

```
GET https://api.bitsighttech.com/ratings/v1/companies/<guid>
  ?fields=current_rating,rating_avg_90_days,confidence,has_delegated_security_controls,is_primary,name,industry,sub_industry
```

Extract: `current_rating` (numeric), `rating_avg_90_days.rating`, `confidence`, `has_delegated_security_controls`, `is_primary`, `name`, `industry`, `sub_industry`.

#### 2. Peer Comparison

Peer percentile rank against Bitsight's curated industry peer group. **Answers: How does this organisation rank vs comparable companies in the same industry?**

```
GET https://api.bitsighttech.com/ratings/v1/companies/<guid>/peer-analytics/ratings-distribution/
  ?recommended_peers_only=true
```

Extract: `headline_peer_percentile` (0–100), `peer_count`, `risk_peer_percentiles[]` — each carrying `risk_type`, `peer_percentile`, and `priority`. Used to enrich risk vector highlights (see Step 2 per-RV peer lookup).

#### 3. 12-Month Rating Trend

Rating-change events over the past 12 months. **Answers: Is this organisation's posture improving, declining, fluctuating, or stable?**

```
GET https://api.bitsighttech.com/v1/insights
  ?company=<guid>
  &start=<twelve_months_ago>
  &end=<today>
  &ignore_score_delta=true
```

**This endpoint returns a bare JSON list, not an object.** Extract from each event: `date`, `start_score`, `end_score`, `reasons[]`(risk vector changes and percentile shifts).

#### 4. Current Risk Vector Grades

Current security grades across all production risk vectors. **Answers: Which security categories are weakest, and which matter most**

```
GET https://api.bitsighttech.com/portfolio/risk-vectors/grades
  ?company.guid=<guid>
  &period=latest
  &limit=100
  &exclude_alpha=true
  &exclude_beta=true
```

Extract from `results[0].grades[].risk_vectors[]`, each with: `risk_vector.name`, `risk_vector.slug`, `grade` (A–F or N/A), `percentile`.

#### 5. Critical Vulnerabilities Findings

Confirmed Severe/Material, currently-exposed vulnerabilities ranked by exploit priority. **Answers: What active CVEs require immediate attention?**

```
POST https://api.bitsighttech.com/v2/companies/<guid>/threats/query
Content-Type: application/json

{
  "severity_level": ["Severe", "Material"],
  "evidence_certainty": ["CONFIRMED"],
  "exposure_detection": "EXPOSED",
  "sort": "-dve_highest_score",
  "limit": 50,
  "offset": 0,
  "expand": ["remediation_tip", "description"],
  "fields": [
    "guid", "name", "severity",
    "evidence_record_count", "first_seen_date", "last_seen_date",
    "dve", "epss", "remediation_tip", "description"
  ]
}
```

**`severity_level`, `evidence_certainty`, `expand` and `fields` are JSON arrays** — send `["Severe", "Material"]`, never the comma-separated string `"Severe,Material"`. This endpoint validates each as a list and returns HTTP 422 (`value is not a valid list`) for a string.

Extract from each threat: `guid`, `name` (CVE ID), `severity.level` (`"Severe"` or `"Material"`, matching the query filter), `severity.details` (CVSS score), `evidence_record_count`, `first_seen_date`, `last_seen_date`, `remediation_tip`, `description`, `dve.cti_attributes[].name` (exploit signals — "Exploited in the Wild", "Known Exploited Vulnerability", ransomware, Metasploit, etc.), `dve.dve_score`, `epss.percentile`.

#### 6. Bitsight Defaults

Reference metadata for rating bands and risk-vector ranking. **Answers: What do the numeric ratings and risk vectors mean, per Bitsight's own definitions?** Static reference call — no GUID — issue in parallel with the rest.

```
GET https://api.bitsighttech.com/defaults
```

Extract:
- `rating_ranges` — each band carries `min`, `max`, `name` (e.g. `"Advanced"`), and `description`. Source of truth for rating bands; **do not hardcode band thresholds**.
- `risk_vectors.details_by_name` — each entry carries `id` (short slug, e.g. `ssl`), `slug` (long slug, e.g. `ssl_configurations`), and `impact` (`high`/`medium`/`low`). Source of truth for RV impact and the #2↔#3 slug join.


#### Unavailability handling

Any of the endpoint calls may return a non-2xx. Treat any such response as "unavailable" — do not invent values for that source.

**Record each failed call.** Distinguish an _empty_ success from a _failed_ call, and carry every failure forward — failures are reported in `errors` (Step 3), keyed by output section. A call **succeeded** when it returns a 2xx response, _even if the payload is empty_ (`[]`, `count: 0`, `null`, `results: []`) — that means the organisation genuinely has no such data, so do **not** record it as an error. A call **failed** when it returns a non-2xx (403/404/422/5xx), an error body (`{"detail": ...}`, `{"error": ...}`), or otherwise does not complete — capture its message. #6 (`/defaults`) is not a section of its own — it feeds the rating band and the risk-vector ranking, so its failure is handled inside those (see Step 2): the band drops to `null`, and the risk-vector section is reported under `risk_vector_grades`.

---

### Step 2: Reason Over the Data

Apply these rules to the fetched data to produce the structured output. Ground every claim ONLY in the data — no speculation, no inferred root causes.

---

#### Derivations

These computations turn raw values into the categorical outputs the schema requires. Compute them deterministically — do not estimate.

**Rating band** (from #1 `current_rating` and #6 `rating_ranges`):
Find the band in `rating_ranges` whose `min ≤ current_rating ≤ max`. Use its `name` for `rating_summary.category` and its `description` as background context for `summary` prose (do not emit the description as its own field). Do not hardcode thresholds — they come from #6.

**If #1 is unavailable**: set both `rating_summary.current_rating` and `rating_summary.category` to `null` — do not derive a band, and do not match tone to a band. Fall back to a neutral tone and note in `summary` that the rating could not be determined this run.

**If #6 is unavailable** (even when #1 succeeded): keep `rating_summary.current_rating` from #1, but set `rating_summary.category` to `null` — **do not guess band thresholds** to place the rating. Fall back to a neutral tone (no band to match) and note in `summary` that the rating category could not be determined this run. No separate error entry is needed: `current_rating` present with `category` null already means the band could not be placed.

**90-day trend** (from #1 `current_rating` and `rating_avg_90_days.rating`):
Compute `delta = current_rating − rating_avg_90_days.rating`. Mention in `summary` only when `|delta| ≥ 10`. Positive = improving, negative = declining. If #1 is unavailable, omit any 90-day movement from `summary`.

**Peer position bucket** (from any raw percentile, 0–100):

**Apply this rule deterministically — the bucket depends ONLY on the numeric percentile value:**

- percentile < 25 → `"below_peers"` (e.g., 0, 5, 10, 24, 24.9)
- 25 ≤ percentile ≤ 75 → `"in_line_with_peers"` (e.g., 25, 50, 75)
- percentile > 75 → `"above_peers"` (e.g., 75.1, 80, 100)
- negative percentile (e.g., −1) or missing/null → `null`

Apply to #2 `headline_peer_percentile` for `rating_summary.peer_position`. If #2 is unavailable, set `peer_position = null` — do not substitute a default bucket.

**12-month trend classification** (from #3 events):
Sort events by `date`. Compute per-event `delta = end_score − start_score`; `net_delta = last event's end_score − first event's start_score`; `direction_flips` = the number of times the sign of `delta` reverses between consecutive events.

- `direction_flips ≥ 4` → `"fluctuating"`
- `net_delta > 20` → `"improving"`
- `net_delta < −20` → `"declining"`
- otherwise → `"stable"`

Keep `event_count` (total events) and `direction_flips` for `trend_narrative`. If #3 is unavailable or empty, set `trend_12m = null` — do not substitute a default classification.

**Risk vector ranking (composite, worst-first)** (from #4, #6, #2):

Build `risk_vector_highlights` from #4's risk vectors using #6 impact and #2 peer signals. Do **not** rank by letter grade alone.

1. **Drop** any risk vector with `grade == "N/A"`.
2. **Impact**: look up `impact` from #6 `details_by_name`, keyed by #4 `risk_vector.slug` == #6 `id`. Default to `medium` if absent.
3. **Per-RV peer comparison lookup**: map the RV's `slug` (#4 / #6 `id`) to its peer `risk_type` via #6 `details_by_name[].slug`, then find that `risk_type` in #2 `risk_peer_percentiles[]`. If found and its `peer_percentile ≥ 0`, bucket the percentile (rule above) for `peer_comparison` and capture its `priority` for tie-breaking. If no match, or #2 unavailable, set `peer_comparison = null` and treat `peer_priority` as `"low"`.
4. **Composite sort key** — sort ascending by, in order:
   - `−(grade_severity × impact_severity)` where `grade_severity = {F:4, D:3, C:2, B:1, A:0}` and `impact_severity = {high:3, medium:2, low:1}` (worst composite first). A high-impact C can outrank a low-impact F.
   - `peer_priority` ordered `{critical:0, high:1, medium:2, low:3}`.
   - `peer_comparison` ordered `{below_peers:0, in_line_with_peers:1, above_peers:2, null:3}`.
   - `percentile` (#4) ascending — lower percentile (relatively worse standing) sorts first.
   - RV `name` alphabetically, as a final deterministic fallback if every prior key still ties.
5. Take the **top 5**. The list always communicates the _most-actionable_ state: weaknesses (F/D/C) surface first; if none, strengths (B/A) take the slots.

**If #6 is unavailable**, the composite ranking cannot be built to standard: there is no impact table and no slug join for per-RV peer standing. Do not emit a partial list — set `risk_vector_highlights` to `[]`, record `risk_vector_grades` in `errors` (Step 3), and note in `summary` that risk-vector prioritisation was unavailable this run. `risk_vector_highlights` is backed by **both** #4 and #6; report `risk_vector_grades` in `errors` if either fails.

**Vulnerability prioritisation** (from #5):

For each threat, derive: `exploited_in_wild` = `"Exploited in the Wild"` ∈ `dve.cti_attributes[].name`; `high_epss` = `epss.percentile ≥ 95`; `critical_cvss` = CVSS (`severity.details`) `≥ 9.0`. Sort ascending by, in order: not-`exploited_in_wild`, not-`high_epss`, not-`critical_cvss`, then `−CVSS`. This puts actively-exploited CVEs first regardless of CVSS, then high-EPSS, then Critical-CVSS, then highest CVSS.

**Stale vulnerability filter:** Do NOT surface vulnerabilities where `exploited_in_wild` is false AND `high_epss` is false AND CVSS < 7.0 AND `first_seen_date` is more than 180 days ago. Old, low-exploitation-likelihood vulnerabilities add noise.

---

#### Security Concepts

**Risk Vector Grades (surface the letter directly)**
The schema's `grade` field accepts `"A" | "B" | "C" | "D" | "F" | "N/A"` — use #4's letter grade as-is, no mapping.

Use these grade meanings only for **`key_issue` prose framing**, not for the `grade` field value:

- A: Excellent — highlight as a strength.
- B: Good — do NOT describe as a weakness, gap, or vulnerability. At most "room for improvement."
- C: Fair — neutral language ("opportunity to improve"). Do NOT call this a vulnerability, weakness, gap, or risk.
- D: Poor — frame as a weakness using business-impact language.
- F: Failing — frame as a weakness prominently.
- N/A: excluded from `risk_vector_highlights`; do not mention in prose.

**Vulnerabilities (CVE) Prioritisation**
Within the prioritised threats, surface in this order:

1. `"Exploited in the Wild"` present in `dve.cti_attributes[].name` — actively exploited; takes precedence regardless of CVSS.
2. `epss.percentile ≥ 95` — high likelihood of exploitation.
3. `severity.details` indicates CVSS ≥ 9.0 — Critical.

When narrating CVEs in `top_threats[].description`:

- Use `name` as the identifier (the CVE ID, e.g. `CVE-2021-44228`).
- Reference exploit signals from `dve.cti_attributes[].name` (e.g. "actively exploited in the wild", "linked to ransomware", "Metasploit module exists").
- You may reference `remediation_tip` (HTML-light, with product names and links) to ground `recommendations[].action` — **paraphrase it into plain prose; never copy its raw HTML tags/markup verbatim into any output field.** Downstream HTML stripping is not reliable enough to depend on for correctness — treat every output string as plain text you produce yourself, not as a container that may carry markup.
- `evidence_record_count` gives scope ("affects N assets") — use it when meaningful.

**Conditional summary mentions** (only surface when notable):

These three fields all come from #1. If #1 is unavailable, none of them can be surfaced — omit all three.

- `confidence` — mention only when NOT `"HIGH"`.
- `has_delegated_security_controls` — mention only when `true`.
- `is_primary` — mention only when `false` (must surface this caveat).

**Peer Comparison Unavailable:** If #2 failed, set `peer_position = null`, omit all peer-relative language from `summary`, and set every `risk_vector_highlights[].peer_comparison = null`.

---

#### Tone Rules

Match tone strictly to the derived rating band.

**Advanced** — Lead with what is working; establish strong overall posture first. Introduce areas to watch with softened language ("the primary area to watch," "one opportunity to strengthen"). Conclude that routine monitoring is appropriate.

**Intermediate** — Acknowledge genuine strengths and proportional risks in equal measure. Apply risk language only to D/F grades on rating-impacting RVs and to `below_peers` standings on material vectors.

**Basic** — Risk-forward. Lead with the most material concerns. Briefly acknowledge genuine strengths if present.

#### Writing Rules

- Risk vector names in Title Case, unabbreviated: "SSL Configurations," not "ssl_configurations." Acronyms stay capitalised (DKIM, SPF, DMARC, DNSSEC).
- Use numerals for all numbers (8, not eight).
- Reference timeframes as "the last 12 months" (historical context) or "currently" (rating, RVs, CVEs).
- Frame risk in terms of business impact (operational disruption, data exposure, regulatory or financial consequences) — not purely technical findings.
- This is the organisation's own security posture. Address findings as the reader's own responsibility, not a third party's.
- **No raw HTML or markup in any output field** — no `<...>` tags, entities, or attributes, even when paraphrasing HTML-bearing source fields like `remediation_tip`. Every string in the output is plain prose you write; do not pass through or lightly edit markup from a source field.

#### Constraints

- **NO speculation**: do not infer exploitation, lateral movement, or root causes the data does not explicitly support.
- **NO client prescriptions**: do not instruct the reader's organisation; do not assume internal policies or reference frameworks.
- **NO stale noise**: do not surface old, low-risk findings or vulnerabilities with minimal exploitation likelihood. Quality over quantity.
- **NO absence claims for unfetched data**: never assert that something is absent (e.g. "no breaches") unless a source in #1–#6 actually checked for it. A clean risk vector grade or an empty `top_threats` supports "no active security incidents" or "no exposed critical vulnerabilities" — it does not support "no breaches," since SPM never queries breach intelligence. Scope every absence claim to the specific source that grounds it.

---

### Step 3: Emit Structured Output

Return a single JSON object matching the `SpmInsightOutput` schema. Cap each list at the schema's `max_length` of 5.

```json
{
  "question_type": "spm",
  "summary": "...",
  "rating_summary": { ... },
  "top_threats": [ ... ],
  "risk_vector_highlights": [ ... ],
  "recommendations": [ ... ],
  "errors": [ ... ]
}
```

#### `summary`

One continuous paragraph, 4–6 sentences, written for an **SPM analyst or security/IT manager** (a technical security audience). The summary should communicate **what the most material risks are and why they matter to the business** — not the underlying metrics or technical naming.


**Lead with the most material risk exposure** surfaced from the data — actively-exploited vulnerabilities, or the specific weaknesses driving the worst risk vectors — translated into the business consequence (data exposure, service disruption, regulatory or financial impact, ransomware risk).

**Hard constraints — do not violate:**

1. **No Bitsight terminology in the prose.** Do NOT write:
   - The numeric rating ("a rating of 660")
   - Bitsight-specific framing ("Basic / Intermediate / Advanced band")
   - Point movements or event counts ("declined 100 points", "35 rating events")
   - Percentile numbers ("at the 15th percentile")
   - Risk-vector slugs or internal grade letters ("D-grade", "graded F")
   - Risk-vector names that are jargon to a non-technical reader (`DKIM`, `DMARC`, `DNSSEC`, `SPF`, `SSL Configurations`, `Web Application Headers`, `Patching Cadence`, etc.) — translate to plain English consequences. _"weaknesses in how encrypted connections are configured on public services"_ not _"failing SSL Configurations"_.

2. **Emphasise business impact, not technical findings.** Every concern raised in the prose should answer _"why does this matter?"_ in business terms — likelihood of unauthorised access, data exposure, service disruption, regulatory consequences, reputational damage. Avoid pure-technical sentences like _"the organisation has weak TLS configurations on public endpoints"_ in favour of _"weaknesses in how encrypted traffic is protected on public services could expose sensitive data in transit."_

3. **Write for a technical security audience.** Plain-English phrasing. Where technical concepts are unavoidable, briefly translate them. The audience understands security but should not need to decode Bitsight internals. Prefer "vulnerabilities being actively exploited by attackers" over "actively-exploited CVEs." Prefer "weaknesses in basic security controls" over "failures across multiple Diligence vectors."

**Peer language** is allowed as qualitative colour only — _"weaker than comparable organisations in the technology sector"_, _"performs strongly relative to its peer group"_ — never with numbers or percentile language.

**12-month trend** should be characterised qualitatively when relevant: _"a deteriorating security posture over the past year"_, _"persistent instability"_, _"steady improvement"_. Never reference event counts, direction reversals, or net-point movement. Match language strength to how often direction reverses: when most events reverse the previous direction (more reversals than not), use strong instability language ("persistent instability," "highly erratic performance") — reserve milder language ("fluctuated") for cases where direction changes only occasionally.

**90-day movement** may be referenced as direction-only when material to the risk story (_"the situation has worsened over the past quarter"_), never with point deltas or averages.

Apply the conditional mentions for `confidence`, `has_delegated_security_controls`, and `is_primary` per the rules above — phrased in plain English (_"this analysis covers a non-primary entity and may not reflect the wider organisation"_). The non-primary caveat in particular **must** surface when `is_primary: false`.

If peer comparison is unavailable, omit peer-relative phrases entirely.

**The numeric rating and other technical fields are still exposed in the structured output** (`rating_summary.current_rating`, `risk_vector_highlights[].grade`, etc.) — a UI consumer renders those separately. The summary prose is where the business narrative lives.

#### `rating_summary`

- `current_rating`: from #1 `current_rating`.
- `category`: the derived rating band `name`.
- `peer_position`: bucketed #2 `headline_peer_percentile`; `null` if #2 unavailable.
- `trend_12m`: the derived trend classification; `null` if #3 unavailable.
- `trend_narrative`: 1–2 sentences. **When `trend_12m == "fluctuating"`, surface `direction_flips` and `event_count`.**

#### `top_threats` (≤5)

Highest-priority vulnerabilities ranked by exploit likelihood.

**If #5 is unavailable**: set `top_threats` to `[]` and record it in `errors` (see `errors` below). An empty `top_threats` reads as "genuinely none" only when `top_threats` is **absent** from `errors`. The list is trustworthy **only when #5 (Critical Vulnerabilities) returned 2xx**.

**Do not confuse "the query found zero vulnerabilities" with "the call failed."** If #5 returned HTTP `200` with `count: 0` (or an empty list), that is a genuine success — the organisation has no matching vulnerabilities. Do **not** report this as `404`, `"Not Found"`, or any other failure in `errors`. Before writing anything to `errors`, check the call's actual HTTP status: only a real non-2xx response goes there.

Each item:

- `type`: `"vulnerability"`.
- `severity`: `"critical"` when `severity.level == "Severe"`, `"high"` when `severity.level == "Material"`.
- `title`: CVE ID.
- `description`: 1–2 sentences. Include exploit signals from `dve.cti_attributes[].name` (e.g., "Exploited in the Wild", "Known Exploited Vulnerability").
- `guid`: the **`guid` field of that specific entry** in the threats query response (#5) — not the CVE ID, not a shared placeholder. Each vulnerability surfaced gets its own `guid`.

Every `top_threats[]` entry MUST have a distinct, per-item `guid`. Reusing the same `guid` across multiple entries — or falling back to a generic placeholder — defeats the purpose of the field.

#### `risk_vector_highlights` (≤5)

Use the composite-ranked top 5 risk vectors derived in Step 2 (N/A excluded, worst-first).
Each item:

- `name`: RV display name from #4 `risk_vector.name`, Title Case, unabbreviated.
- `grade`: letter grade from #4.
- `peer_comparison`: bucketed per-RV peer comparison (may be `null`).
- `key_issue`: one sentence on the primary point for this risk vector. **Frame as a weakness for C/D/F grades** (business-impact language — operational disruption, data exposure, etc.) and **frame as a strength for A/B grades** (e.g. _"strong DNS protections in place, consistent with industry best practice"_). You may reference `percentile` to anchor magnitude when useful.

#### `recommendations` (≤5)

Prioritised actions, high → low. Each ties back to a specific finding (CVE or RV) from this run.

- `priority`: `"high"` / `"medium"` / `"low"`.
- `action`: imperative sentence. Ground in CVE `remediation_tip` (specific product upgrades) where available.
- `impact`: what's at stake (business framing — operational disruption, data exposure, regulatory or financial consequences).
- `findings_affected`: list of identifiers — CVE IDs or RV names referenced by the action.

**Priority rules:**
- `"high"`: actively-exploited or KEV-listed CVE; RV at F grade.
- `"medium"`: RV at D grade; CVE with EPSS ≥ 95; pattern of repeated events.
- `"low"`: routine monitoring; low-impact maintenance.

**No recommendations derived from a source in errors.** Every recommendation must tie back to a finding from a source that loaded successfully (absent from errors). If a source is in errors, surface no recommendation derived from it — the data is incomplete, and citing it would re-expose withheld data and imply a completeness the run doesn't have.

#### `errors`

Surface the detail behind every failed call so partial errors are understandable. A 2xx with an empty payload is a success: do not add an error for it. In particular, a `count: 0` or empty-list result means "genuinely no data," never "not found" — do not translate that into a `404` or any other fabricated status; only a call's *actual* HTTP status justifies an entry here. Each entry:

- `source`: the affected output section — one of `top_threats`, `current_rating`, `peer_comparison`, `rating_trend`, `risk_vector_grades`. Keyed to the output section.
- `status_code`: the HTTP status of the failed response (e.g. `403`, `404`, `500`). Use `null` only when the call failed without an HTTP status (timeout, transport error).
- `message`: the error detail the call returned, copied **verbatim** (the response body or status line, e.g. `"403 Forbidden: company not in portfolio"`).

**Source ↔ call mapping.** Four sources map 1:1 to a single call: `current_rating` (#1), `peer_comparison` (#2), `rating_trend` (#3), `top_threats` ← Critical Vulnerabilities (#5) alone — SPM has no breach-intel call, so unlike Vendor Insights, `top_threats` never depends on a second call. For a 1:1 source, `message` is that one call's own error detail, copied verbatim (e.g. `"403 Forbidden: company not in portfolio"`) — never a compound `"call: status; call: status"` string.

Only `risk_vector_grades` covers more than one call, because its ranking needs both #4 and #6 — report it once if **either** call fails: `risk_vector_grades` ← Risk Vector Grades (#4) + Bitsight Defaults (#6). Only for this source, name each underlying call in `message` — e.g. `"defaults: 500; risk_vector_grades: 200"` — and set `status_code` to the failing call's status. Do **not** emit separate per-call entries, and do **not** use this compound format for any other source.

When every call succeeded, `errors` is an empty list `[]`. A source's presence in `errors` is the only signal that the empty list or `null` in the section it backs is due to a failure rather than genuinely-absent data.

---

## Implementation Notes

- **All six calls run in parallel.** Issue #1–#6 concurrently; none depends on another's result. #6 (`/defaults`) is a static reference call with no GUID but is fetched alongside the rest so derivations have rating ranges and RV impact available immediately.

- **Rating bands and RV impact come from `/defaults`, never hardcoded.** The band thresholds and per-RV impact weights are owned by Bitsight and can change; read them from #6 each run rather than baking numbers into this prompt.

- **The #4↔#2 slug join goes through `/defaults`.** #4 returns short slugs (`ssl`), #2 returns long ones (`ssl_configurations`); `details_by_name[].id` and `[].slug` are the canonical pair. Match on those, not on string similarity.

- **Peer comparison 403 is expected for out-of-portfolio entities.** On any non-2xx from #2, omit peer language from `summary` and treat all `peer_comparison` values as `null`.

- **The trend endpoint (#3) returns a bare list, not a dict.** Parse it as a list; if the call failed, set `trend_12m = null`.

- **`guid` is a plain string field on `ThreatHighlight`**.

- **HTML in `remediation_tip` is fine.** The field contains light HTML for vendor-supplied fix instructions. Reference it in prose-level `recommendations[].action` content — the orchestrator strips HTML before display.
