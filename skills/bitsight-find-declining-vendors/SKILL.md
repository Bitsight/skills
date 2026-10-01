---
name: bitsight-find-declining-vendors
description: Find companies in a Bitsight portfolio whose security ratings have declined over a given period, and export a CSV report. Use when the user wants to identify vendors trending negatively, detect rating drops above a threshold, or monitor portfolio health over time.
tags: CM
version: 1.0
license: Copyright ©2026 BitSight Technologies, Inc. All rights reserved. Use subject to license terms and conditions.
---

# Bitsight Identify Vendors whose ratings are declining

The user wants to find companies in their Bitsight portfolio whose security ratings are declining, and produce a CSV report or other type of output if requested by the user.

## Your job

Work through the steps below in order. Be conversational — gather what you need, run the script, and clearly summarise the results.

## Output rules

Run `scripts/declining.py` as-is. Do not modify it.

- **Different format** (JSON, Markdown, Excel…): run the script unchanged, then convert
  the CSV it wrote. The conversion only reads that CSV. It must not call the Bitsight API
  or read `BITSIGHT_API_TOKEN`.
- **Sending results elsewhere** (another app, service, URL, email): only when the user
  explicitly asks. Tell them exactly what data goes where, and wait for their confirmation
  before sending.


## Step 1 — Ensure the script is installed

The script is `scripts/declining.py` and needs Python 3. If Python 3 isn't available,
stop and ask the user to install it. Do not rewrite the script in another language.

Every request to the Bitsight API must send the `User-agent: <bitsight-user-agent>` header.
The script already does this.

The documentation of the script is:

```
declining.py - Find Bitsight portfolio companies with declining ratings.

Usage:
    python declining.py --output results.csv CONSTRAINT [CONSTRAINT ...]

Examples:
    python declining.py --output out.csv 'portfolio:-30/2w'
    python declining.py --output out.csv 'portfolio:-10%/3w'
    python declining.py --output out.csv 'portfolio:-30/2w' 'Tier 2:-10%/1m' 'My Folder:-20/10d'

Constraint format:  <selector>:<point_change>[%]/<time_period>
  selector      'portfolio' (all companies), a tier name, or a folder name
  point_change  negative integer — absolute points (e.g. -30) or percentage (e.g. -10%)
  time_period   Nd | Nw | Nm | Nq  (days, weeks, months, quarters)

A company FAILS a constraint when:
  Absolute:   max_rating + point_change >= current_rating
  Percentage: max_rating * (1 + point_change / 100) >= current_rating
Examples:
  max=720, drop=-30 (absolute):  720 + (-30) = 690 >= 680 → FAIL
  max=720, drop=-10% (percent):  720 * 0.90 = 648 >= 640 → FAIL

Environment:
    BITSIGHT_API_TOKEN  Required. Your Bitsight API token.

Output CSV columns: name, guid, failed_constraints
```

## Step 2 — Check for the API token

`BITSIGHT_API_TOKEN` is confidential. Do NOT load, display, or echo its value in the conversation.

Check for it in this order:
1. Shell environment (`BITSIGHT_API_TOKEN`)
2. A `.env` or `.envrc` file in the working directory

If not found, ask the user to set it — do not ask them to paste the token directly into the conversation:

> To use this skill you need a Bitsight API token. Set it with:
> ```
> export BITSIGHT_API_TOKEN=your_token_here
> ```
> You can find your token in the Bitsight portal under **Account → API Token**.

Do not proceed until the token is available.


## Step 3 — Gather constraints

If the user has not already provided constraints, explain the format and ask for them:

> **Constraint format:** `<selector>:<point_change>[%]/<time_period>`
>
> | Part | Description | Examples |
> |------|-------------|---------|
> | `selector` | Which companies to check | `portfolio`, `Tier 1`, `Critical Vendors` |
> | `point_change` | Minimum drop — absolute points or percentage of peak | `-30`, `-10%` |
> | `time_period` | Lookback window | `10d`, `2w`, `3m`, `1q` |
>
> A company is flagged when its rating has fallen by at least the specified amount from its peak — either as absolute points or as a percentage of the peak rating.
>
> **Example constraints:**
> - `portfolio:-30/2w` — any company that dropped 30+ points in the last 2 weeks
> - `portfolio:-10%/3w` — any company whose rating fell 10%+ from its peak in the last 3 weeks
> - `Tier 1:-50/1m` — Tier 1 companies that dropped 50+ points in the last month
> - `Tier 1:-10%/1m` — Tier 1 companies that dropped 10%+ from their peak in the last month
> - `Critical Vendors:-20/1q` — companies in the "Critical Vendors" folder that dropped 20+ points this quarter

You can specify multiple constraints; a company is included in the output if it fails **any** of them.

Once you have the constraints, confirm them back to the user before running.


## Step 4 — Choose an output file

If the user has not specified an output path, suggest `declining.csv` in the current directory and confirm.


## Step 5 — Run the script

Run:
```
python scripts/declining.py --output <outfile> <constraint1> [constraint2 ...]
```

Quote each constraint individually to handle spaces in selector names, e.g.:
```
python scripts/declining.py --output declining.csv 'portfolio:-30/2w' 'Tier 1:-10%/1m'
```

There is a `--max-companies <n>` option to limit the number of companies checked (default 250), which will take an early exit if the number of companies to be checked exceeds the limit. If this happens, confirm with the user whether to proceed anyway, and if so, run with a much higher limit. Note that this may take a very long time (e.g. 1 hour) so you must run this in the background.

This is a read-only script that only fetches data from the Bitsight API; it does not modify any data or state in the Bitsight service.


## Step 6 — Report results

After the script completes:

- If **no companies** were flagged: tell the user no companies met the threshold(s), and briefly confirm which constraints were checked.
- If companies **were** flagged: summarise clearly, e.g.:

  > Found **3** companies with declining ratings:
  >
  > | Company | GUID | Failed constraints | Max Rating | Max Rating Date | Current Rating |
  > |---------|------|--------------------|------------|-----------------|----------------|
  > | Acme Corp | `abc-123` | `portfolio:-30/2w` | 720 | 2026-05-01 | 680 |
  > | ...

  Then confirm the CSV has been written and give the full path.

- If the script **errored**: show the relevant error output and help the user diagnose it (missing API token, unrecognised selector name, network issue, etc.).
