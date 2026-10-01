---
name: bitsight-subscribe-vendors
description: Search for one or more vendors in Bitsight by domain, company name, or GUID, and subscribe (add) them to the portfolio. Use when the user wants to subscribe, add, or onboard vendors to their Bitsight portfolio — whether single, bulk, or from a file. Do NOT trigger for read-only lookups (checking ratings, viewing portfolio contents).
version: 1.0
tags: CM, Onboarding
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
scope: company
---

# Bitsight Vendor Search and Subscribe

## Approach

This skill runs `scripts/subscribe.py` — a self-contained Python CLI that handles the full search-and-subscribe workflow. Do not make API calls directly in the conversation; invoke the script and relay its output.

> **Note:** Run `scripts/subscribe.py` as-is. Do not modify it. If the user needs something it doesn't support (custom subscription logic, different confirmation behaviour), tell them and stop. For a non-standard input format, first convert the file to one of the supported formats (see `references/file-input.md`); the conversion must not call the Bitsight API or read `BITSIGHT_API_TOKEN`. If Python 3 isn't available, stop and ask the user to install it; do not rewrite the script in another language.

## Before Starting

Collect two required inputs before invoking the script. If either is missing, ask before proceeding.

**1. Company identifiers** — Accept a single value, a pasted list, or a file path. Supported types:
- **GUID** (`b9f06faa-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- **Domain** (`example.com`) — preferred
- **Display name** (`Example Corp`) — warn upfront that matches may be inaccurate; never infer a domain from a name

**2. API token — confidential**
Do NOT load, display, or echo the `BITSIGHT_API_TOKEN` value in the conversation. Check for it in this order:
1. Shell environment (`BITSIGHT_API_TOKEN`)
2. A `.env` or `.envrc` file in the working directory (or uploaded)

If not found, ask the user to set it — do not ask them to paste the token directly into the conversation:
*"Please set your Bitsight API token in your shell environment (`export BITSIGHT_API_TOKEN=...`) or a `.env` / `.envrc` file, then try again. You can find your token under **Account → User API Token** in the Bitsight portal."* Only do this if you can read the content of the working directory to check for `.env` files.

Authentication uses HTTP Basic Auth: API token as username, empty string as password. Set `User-Agent: <bitsight-user-agent>` on all Bitsight API requests.

## Running the Script

Resolve the absolute path to `scripts/subscribe.py` relative to this skill's directory, then run it.

**Inline identifiers** (single value or short pasted list):
```
python3 <skill-dir>/scripts/subscribe.py <identifier> [<identifier> ...]
```

**File input:**
```
python3 <skill-dir>/scripts/subscribe.py --file <path>
```

The script is interactive — it will prompt the user for confirmation of ambiguous matches and for subscription type selection. Relay those prompts and responses naturally in the conversation.

The script supports a `--resolve-only` option that just resolves identifiers and returns the GUID(s) that would be subscribed, without making any changes to the Bitsight service. If there are multiple matches for a domain or company name, then this provides the GUIDs. If the user wants to proceed then run the script again without `--resolve-only` to do the actual subscription and provide the list of GUIDs instead of the domain or company name to avoid ambiguity. 

## What the Script Does

1. **Resolve** — GUIDs are checked against the portfolio directly; domains and display names are searched via the Bitsight companies search API.
2. **Confirm** — Ambiguous or display-name matches are shown in a numbered table; the user selects which to proceed with.
3. **Select subscription type** — Available types and remaining quota are fetched live; the user picks one.
4. **Subscribe** — Calls the bulk subscribe API and checks both HTTP errors and per-company errors in the response.
5. **Report** — Prints a summary (subscribed, already in portfolio, not found, errors) and the updated quota table.

## After the Script Finishes

Relay the final summary to the user. If the script exits with an error, show the message and diagnose before retrying.
