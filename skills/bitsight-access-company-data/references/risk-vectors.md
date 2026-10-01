# Risk Vectors Reference

Use `risk_vector` to select one or more finding families. Risk vectors can be combined with asset filters such as `assets__asset`, `assets__combined_importance`, and `assets__is_monitored`.

For verified API behavior, gotchas, and per-vector CVE playbooks, see [findings-api-knowledge.md](findings-api-knowledge.md) and `../assets/findings-api-knowledge.json`.

## Compromised Systems

- `botnet_infections`: infected systems participating in botnet activity. Useful filters: `severity_category`, `infection__family`, `infection__id`, `assets__asset`, `observed_ips_contains`.
- `spam_propagation`: systems observed sending spam. Useful filters: `severity_category`, `assets__asset`, `observed_ips_contains`.
- `malware_servers`: systems hosting or distributing malware. Useful filters: `severity_category`, `assets__asset`, `observed_ips_contains`.
- `unsolicited_comm`: unsolicited communications findings. Useful filters: `severity_category`, `assets__asset`.
- `potentially_exploited`: signals that assets may be exploited. Useful filters: `severity_category`, `assets__asset`, `first_seen_gte`.

## Diligence

- `spf`: sender policy framework findings. Useful filters: `grade`, `check_pass`, `evidence_key`.
- `dkim`: DKIM findings. Useful filters: `grade`, `check_pass`, `evidence_key`.
- `dmarc`: DMARC findings. Useful filters: `grade`, `check_pass`, `evidence_key`.
- `ssl_certificates`: certificate findings. Useful filters: `grade`, `assets__asset`, `first_seen_gte`, `last_seen_gte`. **`assets__asset=<hostname>` is the only server-side filter for hostname scope** — use it to limit results to certificates observed on a specific host (e.g. `assets__asset=www.example.com`). Without it, queries return all SSL cert findings for the company (tens of thousands for large companies). Note: `evidence_key` for this vector is the certificate **serial number**, not a hostname — do not use it for hostname filtering. Certificate expiry dates live at `details.diligence_annotations.certchain[].endDate` and must be filtered client-side after fetching the narrowed result set.
- `ssl_configurations`: SSL/TLS configuration findings. Useful filters: `grade`, `assets__asset`, `check_pass`.
- `open_ports`: exposed service and port findings. Useful filters: `vulnerabilities`, `details.vulnerabilities.severity`, `cvss__base`, `assets__asset`, `assets__combined_importance`, `impacts_risk_vector_details`. See `vector_playbooks.open_ports` in `findings-api-knowledge.json`.
- `dnssec`: DNSSEC findings. Useful filters: `grade`, `evidence_key`.
- `application_security`: web application security findings. Useful filters: `assets__asset`, `severity_category`, `check_pass`.
- `patching_cadence`: patching cadence findings. Useful filters: `grade`, `duration_gte`, `assets__combined_importance`.
- `insecure_systems`: insecure system findings. Useful filters: `assets__asset`, `severity_category`.
- `server_software`: vulnerable or unsupported server software. Useful filters: `vulnerabilities`, `details.vulnerabilities.severity`, `cvss__base`, `assets__asset`. See `vector_playbooks.server_software`.
- `desktop_software`: vulnerable or unsupported desktop software. Useful filters: `vulnerabilities`, `details.vulnerabilities.severity`, `cvss__base`. See `vector_playbooks.desktop_software`.
- `mobile_software`: vulnerable or unsupported mobile software. Useful filters: `vulnerabilities`, `details.vulnerabilities.severity`, `cvss__base`. See `vector_playbooks.mobile_software`.
- `mobile_application_security`: mobile application security findings. Useful filters: `assets__identifier`, `severity_category`.
- `web_appsec`: web application security findings. Useful filters: `assets__asset`, `severity_category`.

## User Behavior

- `file_sharing`: file sharing activity findings. Useful filters: `file_sharing_category`, `assets__asset`, `severity_category`.
- `mobile_app_publications`: mobile application publication findings. Useful filters: `assets__identifier`, `assets__asset`.

## Security Incidents

- `data_breaches`: security incident and breach-related findings. Useful filters: `first_seen_gte`, `last_seen_gte`, `severity_category`.

## Examples

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company "Example Corp" --risk-vector botnet_infections,malware_servers --filter affects_rating=true
```

```bash
python3 skills/bitsight-access-company-data/scripts/portal_api.py findings --company "Example Corp" --risk-vector open_ports --vulnerability CVE-2023-27522 --asset-importance critical
```
