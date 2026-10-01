# CLI Reference

## Environment

Create a `.env` file in the repo root or run with environment variables:

```env
BITSIGHT_API_TOKEN=replace-with-api-token
PORTAL_API_BASE_URL=https://service.bitsighttech.com/customer-api/v1
PORTAL_AUTH_SCHEME=Basic
```

For Basic auth, the CLI encodes `BITSIGHT_API_TOKEN` as `Basic base64(api_token:)`. Use `PORTAL_AUTH_HEADER` when the API expects a fully custom authorization header.

## Cross-Platform Invocation

Use `python3` (macOS/Linux) or `py -3` on Windows:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp"
```

```powershell
py -3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp"
```

## Global Flags

`--output csv|json` and `--base-url` are **global flags** — they must appear BEFORE the subcommand:

```bash
# correct
python3 skills/bitsight-access-company-data/scripts/portal_api.py --output csv assets --company "Example Corp"

# wrong — exit 2, empty output
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp" --output csv
```

JSON is the default output format. `--output json` is never required.

## Company Disambiguation

If a name matches multiple companies, the CLI prints numbered choices with details such as `in_portfolio`, `self_published`, `has_company_tree`, `is_primary`, `primary_company`, and `confidence`, then exits with code `2`.

Re-run with one of:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp" --company-index 2
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py assets --company "Example Corp" --select-guid 00000000-0000-0000-0000-000000000000
```

Before selecting, inspect candidates and the company tree:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py companies --company "Example Corp"
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid 00000000-0000-0000-0000-000000000000 --expand confidence,is_shell
```

For tree-only matching, return visible GUIDs filtered by name, domain, IP, or broad `q` terms:

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py company-tree --company-guid 00000000-0000-0000-0000-000000000000 --guids-only --tree-name "Example"
```

Ask for clarification instead of guessing when multiple parent, subsidiary, primary, or self-published companies plausibly match the user's business scope.
