# Portal URL Generation

Use this only when the user needs browser-ready links into the Bitsight UI, such as report artifacts, remediation handoffs, or evidence that should be easy to inspect in the portal.

## Command

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py portal-urls --company-guid GUID --portal-product both --risk-vector open_ports --asset login.example.com --affects-rating
```

The command is shared CLI. If `--company-guid` is provided, it does not need API credentials. If `--company` is provided, it resolves the company through the API before building links.

## CM vs SPM

Bitsight has two portal URL families:

- CM / Continuous Monitoring: `/app/tprm/...`
- SPM / Security Posture Management: `/app/spm/...`

Use `--portal-product cm`, `--portal-product spm`, or `--portal-product both`. Generated reports should use `both`, ask the user to choose CM or SPM on the first Bitsight-link click after a page refresh, and reuse that page-session choice for subsequent Bitsight links.

## Generated Links

`portal-urls` emits:

- Company overview: `/app/{product}/company/{guid}/overview/`
- Rating details: `/app/{product}/company/{guid}/rating-details/`
- Ratings tree: `/app/{product}/ratings-tree/?guid={guid}`
- Findings: `/app/{product}/company/{guid}/findings/`
- Infrastructure assets: `/app/{product}/company/{guid}/infrastructure/assets/table/`
- Optional per-risk-vector findings links.
- Optional asset inventory searches and asset-scoped findings links.
- Optional CVE/vulnerability findings links.

Findings filter URLs preserve `risk_vector`, `impacts_risk_vector_details`, `affects_rating`, `assets.asset`, `vulnerabilities`, and `sort`. List search URLs use `search=...`.

## Asset Links

Use exact asset filters for findings links. Do **not** use generic `search=...` for asset-scoped findings because it searches finding identifiers/evidence text and can return broader results than the selected asset.

- Asset inventory table links may use `search=<asset>&sort=-importance`.
- Asset-scoped findings links must use `assets.asset=<asset>&sort=-last_seen`.
- Asset-scoped rating-impacting findings links must use `affects_rating=true&assets.asset=<asset>&sort=-last_seen`.

Example:

```text
https://service.bitsighttech.com/app/tprm/company/GUID/findings/?affects_rating=true&assets.asset=www.example.com&sort=-last_seen
```

## Useful Options

- `--portal-product`: `cm`, `spm`, or `both`. Default: `cm`.
- `--risk-vector`: risk-vector slug or common label. Repeat or pass comma-separated values.
- `--asset`: exact hostname, domain, or IP for findings filters. Repeat or pass comma-separated values.
- `--vulnerability` / `--cve`: CVE ID, vulnerability name, or alias.
- `--affects-rating`: add `impacts_risk_vector_details=AFFECTS_RATING` to generated risk-vector links.
- `--report-minimum`: include the risk-vector links needed by the sample posture report. Add asset links with `--asset`.

## Report Minimum

The sample report minimum includes:

- Risk vectors: SSL configurations, DNSSEC, DMARC, DKIM, SSL certificates, application security, web appsec, SPF, mobile software, open ports.
- Assets: none by default. Pass the company's own domains or hosts with `--asset` (e.g. `--asset www.example.com`).

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py portal-urls --company-guid {guid} --portal-product both --report-minimum --affects-rating
```
