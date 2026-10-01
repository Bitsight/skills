#!/usr/bin/env python3
"""Validate the attribution of one or more IP addresses to a named company.

For each IP this builds an evidence-first attribution report with two columns
side by side:

  * WHAT BITSIGHT CLAIMS -- the attribution reasons Bitsight holds for the IP
    against the company's footprint (GET /v1/companies/{guid}/infrastructure/
    reasons), including the source, the matched CIDR, and every reason with its
    category, whether it is expired, and when it was last seen.
  * WHAT IS TRUE RIGHT NOW -- independent live probes (RDAP, reverse DNS, TLS
    certificate, port-43 whois) that either SUPPORT, CONTRADICT, or were NEVER
    CHECKED. A verdict that only repeats Bitsight's cached reasoning is not a
    validation, so the live column is where an attribution is confirmed or
    overturned.

Each IP gets a transparent verdict (confirmed / disputed / uncorroborated /
unsubstantiated / live-only / mixed) plus the exact factors that support it,
contradict it, or could not be checked. Read-only: it never mutates the tenant.

Usage:
    python3 validate_ip_attribution.py 203.0.113.10 --company example.com
    python3 validate_ip_attribution.py 203.0.113.10 198.51.100.4 --company-guid <guid>
    python3 validate_ip_attribution.py 203.0.113.10 --company-guid <guid> --skip-live

Auth: set BITSIGHT_API_TOKEN (or BITSIGHT_API_JWT) in the environment or a .env
/ .envrc file; the token is confidential and is never printed. See --help.

Required libraries: none (Python standard library only)."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "<bitsight-user-agent>"
SKILL_VERSION = "2026.257"
DEFAULT_HOST = "https://api.bitsighttech.com"
RDAP_BASE = "https://rdap.org"
DEFAULT_LIVE_TIMEOUT = 6.0

# Hosting / cloud / CDN providers legitimately used by many companies. RDAP,
# whois, or PTR that resolves to one of these is NOT a contradiction of the
# company's use of the IP -- it is inconclusive (the company may host there).
CLOUD_HOSTING_TOKENS = {
    "amazon", "aws", "amazonaws", "google", "googleusercontent", "gcp",
    "microsoft", "azure", "cloudflare", "akamai", "fastly", "digitalocean",
    "linode", "ovh", "hetzner", "godaddy", "rackspace", "oracle cloud",
    "cloudfront", "vultr", "leaseweb", "incapsula", "sucuri", "level3",
    "lumen", "cogent", "hostinger", "namecheap", "squarespace", "wix",
    "gandi", "fastly", "stackpath", "netlify", "vercel", "heroku",
}

# Factor status vocabulary.
SUPPORT = "support"
CONTRADICT = "contradict"
INCONCLUSIVE = "inconclusive"
NOT_CHECKED = "not_checked"
ERROR = "error"


class CliError(Exception):
    def __init__(self, message: str, code: str = "ERROR", exit_code: int = 1):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


# ---------------------------------------------------------------------------
# Auth / base URL / .env (contract shared with the other Bitsight skills)
# ---------------------------------------------------------------------------

def resolve_base_url(api_jwt: str | None) -> str:
    """JWT portal_host claim -> base URL, applying the /customer-api rule exactly once."""
    default = (os.getenv("BITSIGHT_API_BASE") or DEFAULT_HOST).rstrip("/")
    if not api_jwt:
        return default
    try:
        payload = api_jwt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, KeyError, json.JSONDecodeError, IndexError):
        return default
    host = (claims.get("portal_host") or "").strip().rstrip("/")
    if not host:
        return default
    if host == "https://service.bitsighttech.com":
        return "https://api.bitsighttech.com"
    return host if host.endswith("/customer-api") else f"{host}/customer-api"


def auth_headers(api_jwt: str | None, api_token: str | None) -> dict:
    h = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if api_jwt:
        h["Authorization"] = f"bearer {api_jwt}"
    elif api_token:
        h["Authorization"] = "Basic " + base64.b64encode(f"{api_token}:".encode()).decode()
    return h


def load_dotenv_simple() -> None:
    """Populate os.environ from the nearest .env / .envrc, without clobbering."""
    seen: set[Path] = set()
    starts = [Path(__file__).resolve().parent, Path.cwd(), *Path.cwd().parents]
    for start in starts:
        for name in (".env", ".envrc"):
            path = (start / name).resolve()
            if path in seen or not path.exists():
                continue
            seen.add(path)
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value


# ---------------------------------------------------------------------------
# Bitsight HTTP
# ---------------------------------------------------------------------------

def http_get_json(url: str, headers: dict, timeout: float, retries: int) -> Any:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8")
            return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                last_error = exc
                continue
            if exc.code == 401:
                raise CliError("Authentication failed - check your API token/JWT.",
                               "AUTH_FAILED", 2) from exc
            if exc.code == 403:
                raise CliError(f"Permission denied: {detail}", "PERMISSION_DENIED", 2) from exc
            if exc.code == 404:
                raise CliError(f"Not found: {detail}", "NOT_FOUND", 2) from exc
            raise CliError(f"HTTP {exc.code}: {detail}", "HTTP_ERROR", 2) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
                last_error = exc
                continue
            raise CliError(f"Request failed: {exc}", "NETWORK_ERROR", 2) from exc
    raise CliError(f"Request failed after retries: {last_error}", "NETWORK_ERROR", 2)


def build_url(base: str, path: str, params: dict[str, Any]) -> str:
    clean = {k: v for k, v in params.items() if v is not None and v != ""}
    query = urllib.parse.urlencode(clean, doseq=True)
    url = f"{base}{path}"
    return f"{url}?{query}" if query else url


# ---------------------------------------------------------------------------
# Company resolution + footprint
# ---------------------------------------------------------------------------

def _looks_like_domain(value: str) -> bool:
    return bool(value) and " " not in value and "." in value and "/" not in value


def resolve_company(base: str, headers: dict, company: str, timeout: float, retries: int) -> dict:
    """Resolve a name or domain to {guid, name, primary_domain} via companies/search."""
    param = "domain" if _looks_like_domain(company) else "name"
    payload = http_get_json(
        build_url(base, "/v1/companies/search", {param: company, "limit": 25}),
        headers, timeout, retries)
    results = (payload or {}).get("results") if isinstance(payload, dict) else None
    if not results:
        raise CliError(
            f"No company matched {param}={company!r} via /v1/companies/search; "
            "pass --company-guid explicitly.",
            "NO_COMPANY", 2)
    chosen = results[0]
    if param == "domain":
        for r in results:
            if str(r.get("primary_domain", "")).lower() == company.lower():
                chosen = r
                break
    return {
        "guid": chosen.get("guid") or "",
        "name": chosen.get("name") or "",
        "primary_domain": chosen.get("primary_domain") or "",
    }


def fetch_company_footprint(base: str, headers: dict, guid: str, timeout: float, retries: int) -> dict:
    """Best-effort name + primary_domain for a bare GUID (for live-evidence matching)."""
    try:
        payload = http_get_json(
            build_url(base, f"/v1/companies/{guid}", {"fields": "guid,name,primary_domain"}),
            headers, timeout, retries)
    except CliError:
        return {"guid": guid, "name": "", "primary_domain": ""}
    if not isinstance(payload, dict):
        return {"guid": guid, "name": "", "primary_domain": ""}
    return {
        "guid": guid,
        "name": payload.get("name") or "",
        "primary_domain": payload.get("primary_domain") or "",
    }


def _registrable(domain: str) -> str:
    """Best-effort registrable domain (last two labels). Not a full PSL, but enough
    to compare a PTR/SAN host against a company primary_domain."""
    domain = (domain or "").strip().strip(".").lower()
    parts = [p for p in domain.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _brand_tokens(name: str, primary_domain: str, extra_domains: list[str]) -> dict:
    """Build the footprint token set the live probes match against."""
    domains = set()
    brands = set()
    for d in [primary_domain, *extra_domains]:
        reg = _registrable(d)
        if reg:
            domains.add(reg)
            brands.add(reg.split(".")[0])
    # Derive a brand token from the company name too (first alnum word >= 3 chars).
    for word in re.split(r"[^a-z0-9]+", (name or "").lower()):
        if len(word) >= 3 and word not in {"inc", "llc", "ltd", "corp", "the", "com", "co"}:
            brands.add(word)
            break
    return {"domains": {d for d in domains if d}, "brands": {b for b in brands if b}}


# ---------------------------------------------------------------------------
# Bitsight attribution (what Bitsight claims)
# ---------------------------------------------------------------------------

def _flatten_reasons(raw_reasons: Any) -> list[dict]:
    out: list[dict] = []
    if not isinstance(raw_reasons, list):
        return out
    for r in raw_reasons:
        if not isinstance(r, dict):
            continue
        record = None
        last_seen = None
        evidence = r.get("evidence")
        if isinstance(evidence, dict):
            steps = evidence.get("steps")
            if isinstance(steps, list) and steps and isinstance(steps[0], dict):
                record = steps[0].get("record")
                last_seen = steps[0].get("last_seen")
        out.append({
            "category": r.get("category"),
            "value": r.get("value"),
            "is_expired": bool(r.get("is_expired")) if r.get("is_expired") is not None else None,
            "record": record,
            "last_seen": last_seen,
        })
    return out


def get_bitsight_attribution(base: str, headers: dict, guid: str, target: str,
                             all_matching: bool, include_subsidiaries: bool,
                             timeout: float, retries: int) -> dict:
    """GET /v1/companies/{guid}/infrastructure/reasons?net_cidr=<ip|cidr>.

    A null / empty body means Bitsight does NOT attribute the target to this
    company. A non-empty array is Bitsight's attribution, one entry per matching
    CIDR, each with its source and reasons."""
    params: dict[str, Any] = {"net_cidr": target}
    if all_matching:
        params["all_matching_cidrs"] = "true"
    if include_subsidiaries:
        params["include_subsidiaries"] = "true"
    body = http_get_json(
        build_url(base, f"/v1/companies/{guid}/infrastructure/reasons", params),
        headers, timeout, retries)

    matches: list[dict] = []
    if isinstance(body, list):
        for entry in body:
            if not isinstance(entry, dict):
                continue
            matches.append({
                "cidr": entry.get("cidr"),
                "source": entry.get("source"),
                "as_number": entry.get("as_number"),
                "whois_url": entry.get("whois_url"),
                "reasons": _flatten_reasons(entry.get("reasons")),
            })
    attributed = bool(matches)
    all_reasons = [r for m in matches for r in m["reasons"]]
    any_reason = bool(all_reasons)
    all_expired = any_reason and all(r.get("is_expired") for r in all_reasons)
    return {
        "attributed": attributed,
        "match_count": len(matches),
        "sources": sorted({str(m["source"]) for m in matches if m.get("source")}),
        "has_reasons": any_reason,
        "all_reasons_expired": all_expired if any_reason else None,
        "matches": matches,
    }


# ---------------------------------------------------------------------------
# Live evidence (what is true right now) -- all best-effort, stdlib only
# ---------------------------------------------------------------------------

def _match_tokens(text: str, footprint: dict) -> tuple[bool, bool, bool]:
    """Return (matches_footprint, is_cloud_hosting, has_other_org).
    matches_footprint: a company domain/brand token is present.
    is_cloud_hosting: a known cloud/hosting token is present.
    has_other_org: some org-looking text is present that is not the footprint."""
    t = (text or "").lower()
    if not t:
        return False, False, False
    matches = any(d in t for d in footprint["domains"]) or any(
        re.search(rf"\b{re.escape(b)}\b", t) for b in footprint["brands"])
    is_cloud = any(c in t for c in CLOUD_HOSTING_TOKENS)
    return matches, is_cloud, bool(t.strip())


def _classify(text: str, footprint: dict, evidence: str) -> dict:
    matches, is_cloud, has_text = _match_tokens(text, footprint)
    if matches:
        return {"status": SUPPORT, "evidence": evidence}
    if is_cloud:
        return {"status": INCONCLUSIVE, "evidence": evidence,
                "note": "resolves to a shared cloud/hosting provider - companies host here legitimately"}
    if has_text:
        return {"status": CONTRADICT, "evidence": evidence,
                "note": "identifies an organization that is not the named company"}
    return {"status": INCONCLUSIVE, "evidence": evidence}


def check_rdap(ip: str, footprint: dict, timeout: float) -> dict:
    url = f"{RDAP_BASE}/ip/{urllib.parse.quote(ip)}"
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json",
                                               "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": NOT_CHECKED, "note": "no RDAP record for this IP"}
        return {"status": ERROR, "note": f"RDAP HTTP {exc.code}"}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"status": ERROR, "note": f"RDAP lookup failed: {exc}"}
    names: list[str] = []
    if isinstance(data, dict):
        if data.get("name"):
            names.append(str(data["name"]))
        for ent in data.get("entities", []) or []:
            if not isinstance(ent, dict):
                continue
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        names.append(str(item[3]))
            if ent.get("handle"):
                names.append(str(ent["handle"]))
        for rem in data.get("remarks", []) or []:
            if isinstance(rem, dict):
                for line in rem.get("description", []) or []:
                    names.append(str(line))
    text = " | ".join(n for n in names if n)
    result = _classify(text, footprint, text[:400] or "(no org name in RDAP)")
    result["registrant"] = names[0] if names else None
    result["country"] = data.get("country") if isinstance(data, dict) else None
    return result


def check_reverse_dns(ip: str, footprint: dict, timeout: float) -> dict:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return {"status": NOT_CHECKED, "note": "no PTR record"}
    except (OSError, TimeoutError) as exc:
        return {"status": ERROR, "note": f"reverse DNS failed: {exc}"}
    finally:
        socket.setdefaulttimeout(old)
    result = _classify(hostname, footprint, hostname)
    result["ptr"] = hostname
    return result


def check_tls(ip: str, footprint: dict, timeout: float) -> dict:
    try:
        pem = ssl.get_server_certificate((ip, 443), timeout=timeout)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return {"status": NOT_CHECKED, "note": f"no TLS on :443 ({exc.__class__.__name__})"}
    except TypeError:
        # Python < 3.10 has no timeout kwarg; treat as unavailable rather than blocking.
        return {"status": NOT_CHECKED, "note": "TLS probe unavailable on this Python"}
    names: list[str] = []
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    except (AttributeError, ssl.SSLError, OSError):
        return {"status": INCONCLUSIVE, "note": "TLS certificate present but could not be parsed"}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    for rdn in decoded.get("subject", ()):  # subject is a tuple of 1-tuples of pairs
        for key, val in rdn:
            if key == "commonName":
                names.append(val)
    for typ, val in decoded.get("subjectAltName", ()):
        if typ == "DNS":
            names.append(val)
    text = " | ".join(names)
    result = _classify(text, footprint, text[:400] or "(certificate had no CN/SAN)")
    result["cert_names"] = names[:20]
    return result


def _whois_query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def check_whois(ip: str, footprint: dict, timeout: float) -> dict:
    try:
        iana = _whois_query("whois.iana.org", ip, timeout)
        refer = None
        for line in iana.splitlines():
            if line.lower().startswith(("refer:", "whois:")):
                refer = line.split(":", 1)[1].strip()
                break
        body = _whois_query(refer, ip, timeout) if refer else iana
    except (OSError, TimeoutError) as exc:
        return {"status": ERROR, "note": f"whois failed: {exc}"}
    org_lines: list[str] = []
    for line in body.splitlines():
        low = line.lower()
        if any(low.startswith(k) for k in (
                "orgname:", "org-name:", "organization:", "owner:", "netname:",
                "descr:", "responsible:", "customer:")):
            val = line.split(":", 1)[1].strip()
            if val:
                org_lines.append(val)
    text = " | ".join(org_lines)
    result = _classify(text, footprint, text[:400] or "(no org fields in whois)")
    result["registrant"] = org_lines[0] if org_lines else None
    return result


def run_live_probes(target: str, footprint: dict, timeout: float) -> dict:
    """Run the four live probes for a single host IP. Returns a factor dict."""
    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        # A CIDR / network: RDAP + whois can still speak to the block; host
        # probes (DNS/TLS) cannot target a range.
        return {
            "rdap": check_rdap(target.split("/")[0], footprint, timeout),
            "whois": check_whois(target.split("/")[0], footprint, timeout),
            "reverse_dns": {"status": NOT_CHECKED, "note": "target is a CIDR, not a single host"},
            "tls": {"status": NOT_CHECKED, "note": "target is a CIDR, not a single host"},
        }
    if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_link_local:
        reason = "private / reserved IP - not routable, live attribution checks do not apply"
        return {k: {"status": NOT_CHECKED, "note": reason}
                for k in ("rdap", "whois", "reverse_dns", "tls")}
    return {
        "rdap": check_rdap(target, footprint, timeout),
        "whois": check_whois(target, footprint, timeout),
        "reverse_dns": check_reverse_dns(target, footprint, timeout),
        "tls": check_tls(target, footprint, timeout),
    }


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def decide_verdict(attributed: bool, factors: dict | None) -> dict:
    supporting = [k for k, v in (factors or {}).items() if v.get("status") == SUPPORT]
    contradicting = [k for k, v in (factors or {}).items() if v.get("status") == CONTRADICT]
    unchecked = [k for k, v in (factors or {}).items()
                 if v.get("status") in (NOT_CHECKED, ERROR)]

    if supporting and contradicting:
        verdict, reason = "mixed", ("live evidence both supports and contradicts - "
                                    "needs human review")
    elif contradicting and not supporting:
        verdict = "disputed"
        reason = ("live evidence contradicts the attribution"
                  if attributed else "live evidence ties this IP to a different organization")
    elif attributed and supporting:
        verdict, reason = "confirmed", "Bitsight attributes the IP and live evidence corroborates it"
    elif attributed and not supporting:
        verdict, reason = "uncorroborated", ("Bitsight attributes the IP but no live factor could "
                                             "confirm it - cached reasoning only")
    elif not attributed and supporting:
        verdict, reason = "live_only", ("Bitsight does not attribute the IP, but live evidence ties "
                                        "it to the company - a possible attribution gap")
    else:
        verdict, reason = "unsubstantiated", ("neither Bitsight nor any live factor ties this IP to "
                                              "the company")
    return {
        "verdict": verdict,
        "verdict_reason": reason,
        "factors_supporting": supporting,
        "factors_contradicting": contradicting,
        "factors_unchecked": unchecked,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _validate_targets(raw: list[str]) -> list[str]:
    out = []
    for item in raw:
        item = item.strip()
        try:
            if "/" in item:
                ipaddress.ip_network(item, strict=False)
            else:
                ipaddress.ip_address(item)
        except ValueError as exc:
            raise CliError(f"{item!r} is not a valid IP address or CIDR: {exc}", exit_code=2)
        out.append(item)
    return out


def run(args: argparse.Namespace) -> dict:
    api_jwt = args.api_jwt or os.getenv("BITSIGHT_API_JWT")
    api_token = args.api_token or os.getenv("BITSIGHT_API_TOKEN")
    if not api_jwt and not api_token:
        raise CliError("Set BITSIGHT_API_JWT or BITSIGHT_API_TOKEN (env, .env, or flag).",
                       "MISSING_CREDENTIALS", 2)

    targets = _validate_targets(args.ip)
    base = resolve_base_url(api_jwt)
    headers = auth_headers(api_jwt, api_token)
    timeout = float(args.timeout)
    retries = int(args.retries)

    # Resolve the company + its footprint tokens.
    if args.company_guid:
        company = {"guid": args.company_guid, "name": args.company_name or "",
                   "primary_domain": ""}
        if not args.skip_live and not args.company_name and not args.company_domain:
            company = fetch_company_footprint(base, headers, args.company_guid, timeout, retries)
    elif args.company:
        company = resolve_company(base, headers, args.company, timeout, retries)
    else:
        raise CliError("Provide --company <name-or-domain> or --company-guid <guid>.",
                       "NO_COMPANY", 2)
    if not company["guid"]:
        raise CliError("Could not determine a company GUID to validate against.", "NO_COMPANY", 2)

    footprint = _brand_tokens(company.get("name", ""), company.get("primary_domain", ""),
                              list(args.company_domain or []))

    live_timeout = float(args.live_timeout)
    results = []
    for target in targets:
        claim = get_bitsight_attribution(
            base, headers, company["guid"], target,
            all_matching=not args.no_all_matching,
            include_subsidiaries=args.include_subsidiaries,
            timeout=timeout, retries=retries)
        factors = None if args.skip_live else run_live_probes(target, footprint, live_timeout)
        verdict = decide_verdict(claim["attributed"], factors)
        results.append({
            "ip": target,
            "bitsight_claim": claim,
            "live_evidence": factors,
            **verdict,
        })

    verdict_counts: dict[str, int] = {}
    for r in results:
        verdict_counts[r["verdict"]] = verdict_counts.get(r["verdict"], 0) + 1

    return {
        "success": True,
        "company": {
            "guid": company["guid"],
            "name": company.get("name") or None,
            "primary_domain": company.get("primary_domain") or None,
        },
        "footprint_tokens": {
            "domains": sorted(footprint["domains"]),
            "brands": sorted(footprint["brands"]),
        },
        "live_checks_run": not args.skip_live,
        "ip_count": len(results),
        "verdict_counts": verdict_counts,
        "results": results,
        "skill_version": SKILL_VERSION,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt_factor(name: str, factor: dict) -> str:
    status = factor.get("status", "?")
    bits = [f"    - {name}: {status.upper()}"]
    for key in ("registrant", "ptr", "cert_names", "country", "note", "evidence"):
        if factor.get(key):
            val = factor[key]
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            bits.append(f"        {key}: {val}")
    return "\n".join(bits)


def render_text(result: dict) -> str:
    company = result["company"]
    lines = [
        f"# IP attribution validation vs {company.get('name') or company['guid']}"
        + (f" ({company['primary_domain']})" if company.get("primary_domain") else ""),
        f"IPs: {result['ip_count']} | live checks: "
        f"{'on' if result['live_checks_run'] else 'off (--skip-live)'} | "
        f"verdicts: {', '.join(f'{k}={v}' for k, v in result['verdict_counts'].items())}",
        "",
    ]
    for r in result["results"]:
        claim = r["bitsight_claim"]
        lines.append(f"## {r['ip']} -> {r['verdict'].upper()}")
        lines.append(f"  {r['verdict_reason']}")
        if claim["attributed"]:
            src = ", ".join(claim["sources"]) or "unknown source"
            exp = ""
            if claim["all_reasons_expired"]:
                exp = " (ALL reasons expired)"
            elif claim["has_reasons"] is False:
                exp = " (asserted, no derivation reasons)"
            lines.append(f"  BITSIGHT CLAIMS: attributed via {src}{exp}")
            for m in claim["matches"]:
                for reason in m["reasons"]:
                    flag = " [expired]" if reason.get("is_expired") else ""
                    lines.append(
                        f"    - {reason.get('category')}: {reason.get('value')}"
                        f" ({reason.get('record')} last seen {reason.get('last_seen')}){flag}")
        else:
            lines.append("  BITSIGHT CLAIMS: NOT attributed to this company")
        if r["live_evidence"]:
            lines.append("  LIVE EVIDENCE:")
            for name in ("rdap", "whois", "reverse_dns", "tls"):
                if name in r["live_evidence"]:
                    lines.append(_fmt_factor(name, r["live_evidence"][name]))
        lines.append("")
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ip", nargs="+", help="One or more IP addresses (or CIDRs) to validate.")
    parser.add_argument("--company", help="Company name or domain to validate against "
                                          "(resolved via /v1/companies/search).")
    parser.add_argument("--company-guid", help="Company GUID; skips name/domain resolution.")
    parser.add_argument("--company-name", help="Company name (used only for live-evidence "
                                               "matching when --company-guid is given).")
    parser.add_argument("--company-domain", action="append",
                        help="Known company domain(s) to match live evidence against. Repeatable.")
    parser.add_argument("--include-subsidiaries", action="store_true",
                        help="Also consider CIDRs attributed to the company's subsidiaries.")
    parser.add_argument("--no-all-matching", action="store_true",
                        help="Only the single best-matching CIDR (default: all matching CIDRs).")
    parser.add_argument("--skip-live", action="store_true",
                        help="Report only Bitsight's attribution claim; no live RDAP/DNS/TLS/whois "
                             "probes.")
    parser.add_argument("--live-timeout", type=float, default=DEFAULT_LIVE_TIMEOUT,
                        help=f"Per-probe timeout for live checks, seconds. Default: {DEFAULT_LIVE_TIMEOUT}")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="HTTP timeout for Bitsight API calls, seconds. Default: 30")
    parser.add_argument("--retries", type=int, default=3,
                        help="HTTP retry attempts on 429/5xx/network errors. Default: 3")
    parser.add_argument("--format", choices=["json", "text"], default="json",
                        help="Output format. Default: json")
    parser.add_argument("--api-token", help="Override BITSIGHT_API_TOKEN.")
    parser.add_argument("--api-jwt", help="Override BITSIGHT_API_JWT (bearer; outranks the token).")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    load_dotenv_simple()
    args = parse_args(argv)
    try:
        result = run(args)
    except CliError as exc:
        print(json.dumps({"success": False, "error_code": exc.code, "error": str(exc)}, indent=2)
              if args.format == "json" else f"Error: {exc}", file=sys.stderr)
        return exc.exit_code
    print(json.dumps(result, indent=2) if args.format == "json" else render_text(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
