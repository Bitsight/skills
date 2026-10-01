#!/usr/bin/env python3
"""
check_certificate.py - Check Bitsight SPM companies for SSL certificates that
are about to expire and have not yet been renewed.

This script does ALL the data gathering and live TLS probing described in the
skill, then prints a single JSON object to **stdout**. It does NOT format a
human-readable report itself — the calling LLM reads the JSON and renders it in
whatever form the user wants (Markdown report, Jira ticket, email, CSV, ...).

All human-readable progress is written to **stderr** so it never pollutes the
JSON on stdout.

Usage:
    python check_certificate.py [--threshold DAYS] [--lookahead DAYS]
                                [--timeout SECS] [--api-token TOKEN] [--api-jwt JWT]
                                [--probe-method {auto,socket,ct,api}]
                                [--verbose]

Configuration (CLI flag overrides env var overrides default):

    --api-token     BITSIGHT_API_TOKEN          (required if --api-jwt not set)
    --api-jwt       BITSIGHT_API_JWT            (uses bearer auth, overrides --api-token)
    --threshold     EXPIRY_THRESHOLD_DAYS        default 5
    --lookahead     NEXT_EXPIRY_LOOKAHEAD_DAYS   default 30
    --timeout       CONNECT_TIMEOUT              default 10
    --probe-method  CERT_PROBE_METHOD            default auto

Probe methods (how a cert's live expiry is determined):
    socket - open a direct TLS connection and read the served cert. Most
             accurate, but USELESS behind a TLS-intercepting proxy (you get the
             proxy's re-signed cert, not the origin's).
    ct     - query Certificate Transparency logs (crt.sh) for the domain and
             use the latest logged cert's not_after. Proxy-immune (it's an HTTPS
             API returning JSON), but reflects *issued* certs, not necessarily
             what is deployed, and cannot check bare IPs or specific ports.
    api    - ask the Bitsight live-certificates API to probe each finding's
             endpoint server-side (outside your network) and return the leaf
             cert in PEM. Proxy-immune AND reflects the actually-deployed cert,
             so it is the best choice behind a TLS-intercepting proxy. Findings
             are batched per company (up to 20 observation IDs per call, made
             sequentially).
    auto   - probe google.com first; if its cert is not from Google Trust
             Services a TLS-intercepting proxy is assumed and the script falls
             back to ct. Otherwise socket. (default)

The token is never printed or echoed.

Exit codes:
    0 - no action needed
    1 - action needed (a cert is expiring/unreachable within threshold, or a
        company has an unrenewed cert within the lookahead window)
    2 - configuration error (missing token / no companies)

Required third-party libraries: requests, python-dotenv, cryptography
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import NoReturn

import requests

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional at runtime
    def load_dotenv(*_a, **_k) -> bool:
        return False

from cryptography import x509
from cryptography.x509.oid import NameOID
import base64


class APISession(requests.Session):
    """HTTP session with attached API base URL."""
    def __init__(self, api_base: str | None = None):
        super().__init__()
        self._api_base = api_base or API_BASE


class AuthInfo:
    """Holds API authentication credentials (token or JWT)."""
    def __init__(self, api_token: str | None = None, api_jwt: str | None = None):
        self.api_token = api_token
        self.api_jwt = api_jwt

    def get_api_base(self) -> str | None:
        """Extract API base URL from JWT's portal_host claim, or None if not available."""
        if not self.api_jwt:
            return None
        try:
            parts = self.api_jwt.split('.')
            if len(parts) != 3:
                return None
            payload = parts[1]
            padding = '=' * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload + padding)
            claims = json.loads(decoded)
            portal_host = claims.get("portal_host", "").strip()
            if not portal_host:
                return None
            portal_host = portal_host.rstrip('/')
            if portal_host == "https://service.bitsighttech.com":
                return "https://api.bitsighttech.com"
            # The claim may already carry the prefix; appending a second one
            # would 404 every request.
            if portal_host.endswith("/customer-api"):
                return portal_host
            return f"{portal_host}/customer-api"
        except (ValueError, KeyError, json.JSONDecodeError):
            return None


API_BASE = os.getenv("BITSIGHT_API_BASE") or "https://api.bitsighttech.com"
USER_AGENT = "<bitsight-user-agent>"
PAGE_DELAY = 0.2          # seconds between paginated findings requests
ENDPOINT_REGEX = re.compile(r'^([^\[]+?)(?:\[.*?\])?:(\d+)$')

CT_BASE = "https://crt.sh/"
CT_HTTP_TIMEOUT = 60      # crt.sh is slow for domains with large CT history
CT_QUERY_DELAY = 0.3      # politeness delay between crt.sh queries

API_PROBE_BATCH = 20      # max rolledup_observation_ids per live-certificates call

# How live expiry is determined: "socket" (direct TLS), "ct" (crt.sh logs), or
# "api" (Bitsight live-certificates, server-side). Set in main() from
# --probe-method; defaults to socket so unit imports work.
PROBE_METHOD = "socket"

# When True, dump raw API response JSON to stderr. Set in main() from --verbose.
VERBOSE = False

# A single, consistent "now" for the whole run (UTC-aware).
_NOW = datetime.now(timezone.utc)

# Probe cache: (hostname, port) -> raw live-cert dict (threshold-independent).
_probe_cache: dict[tuple[str, int], dict] = {}

# CT lookups are domain-keyed, so memoize by hostname to avoid duplicate calls.
_ct_cache: dict[str, dict] = {}
_ct_session: requests.Session | None = None


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _clean_env(value: str | None) -> str | None:
    """Support direnv-style 'set KEY=value' by stripping up to the first '='."""
    if value is None:
        return None
    if "=" in value:
        return value.split("=", 1)[1].strip()
    return value.strip()


# ---------------------------------------------------------------------------
# TLS probing
# ---------------------------------------------------------------------------

def _is_bare_ip(host: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            continue
    return False


def _make_ctx(is_bare_ip: bool, verify: bool, legacy: bool) -> ssl.SSLContext:
    """Build an SSL context that relaxes verification one axis at a time.

    We only care about expiry dates, not chain trust or hostname match.
    """
    ctx = ssl.create_default_context()
    # Allow legacy TLS 1.0/1.1: the default context refuses anything below TLS
    # 1.2, but plenty of older endpoints still serve a valid cert over 1.0/1.1
    # and we only need to read its expiry, not vouch for the connection.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        # Falls back gracefully if the build's OpenSSL has TLS 1.0/1.1 disabled.
        pass
    # Modern OpenSSL also blocks the weaker ciphers/keys those old protocols use
    # at its default security level; drop SECLEVEL so the handshake can complete.
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    except ssl.SSLError:
        pass
    if not verify:
        # Truly skip verification. getpeercert() returns {} here, so callers
        # must read the cert with binary_form=True.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif is_bare_ip:
        # Bare IP: can't match hostname, but still want verification when a
        # cert is presented (which it always is).
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
    if legacy:
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    return ctx


def _connect_and_get_cert(hostname: str, port: int, connect_timeout: float):
    """Connect over TLS and return (x509_cert, error_string, peer_address).

    Retries, relaxing verification/legacy-renegotiation one axis at a time.
    Reads the cert via getpeercert(binary_form=True) so it works regardless of
    verify mode, then parses it with cryptography. peer_address is the IP we
    actually connected to (from getpeername); note that behind a TLS-intercepting
    proxy this is the proxy's address, not the origin's.
    """
    is_bare_ip = _is_bare_ip(hostname)
    needs_legacy = False
    needs_noverify = False
    last_err: str | None = None

    for verify, legacy in [(True, False), (True, True), (False, False), (False, True)]:
        if legacy and not needs_legacy:
            continue
        if not verify and not needs_noverify:
            continue
        ctx = _make_ctx(is_bare_ip, verify, legacy)
        server_hostname = None if is_bare_ip else hostname
        try:
            with socket.create_connection((hostname, port), timeout=connect_timeout) as sock:
                peer_address = sock.getpeername()[0]
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            if not der:
                last_err = "no_certificate_presented"
                continue
            return x509.load_der_x509_certificate(der), None, peer_address
        except ssl.SSLCertVerificationError:
            # Detect cert errors by the exception class, not exc.reason.
            needs_noverify = True
            last_err = "certificate_verify_failed"
        except ssl.SSLError as exc:
            if getattr(exc, "reason", None) == "UNSAFE_LEGACY_RENEGOTIATION_DISABLED":
                needs_legacy = True
                last_err = "legacy_renegotiation_required"
            else:
                return None, f"ssl_error: {getattr(exc, 'reason', None) or exc}", None
        except (socket.timeout, TimeoutError):
            return None, "connection_timeout", None
        except (ConnectionRefusedError, OSError) as exc:
            return None, f"connection_error: {exc}", None

    return None, last_err or "unreachable", None


def _cert_not_after_utc(cert: x509.Certificate) -> datetime:
    """UTC-aware certificate expiry, compatible across cryptography versions.

    cryptography >= 42 exposes the tz-aware `not_valid_after_utc`; older
    releases only have the naive-UTC `not_valid_after`.
    """
    dt = getattr(cert, "not_valid_after_utc", None)
    if dt is not None:
        return dt
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _raw_from_expiry(expiry_dt: datetime | None, err: str | None,
                     address: str | None = None) -> dict:
    if expiry_dt is None:
        return {"live_expiry_dt": None, "live_expiry": None,
                "days_until_expiry": None, "error": err, "address": address}
    return {
        "live_expiry_dt": expiry_dt,
        "live_expiry": expiry_dt.date().isoformat(),
        "days_until_expiry": (expiry_dt - _NOW).days,
        "error": None,
        "address": address,
    }


def _fetch_live_cert_socket(hostname: str, port: int, connect_timeout: float) -> dict:
    """Direct-TLS probe. Threshold-independent raw result for the probe cache."""
    cert, err, address = _connect_and_get_cert(hostname, port, connect_timeout)
    return _raw_from_expiry(_cert_not_after_utc(cert) if cert else None, err, address)


def _fetch_live_cert(hostname: str, port: int, connect_timeout: float) -> dict:
    """Network call. Dispatches to the configured probe method."""
    if PROBE_METHOD == "ct":
        return _fetch_live_cert_ct(hostname, port, connect_timeout)
    if PROBE_METHOD == "api":
        # In api mode the cache is pre-populated per company (see
        # prepopulate_api_cache) before any walk runs. A miss here means this
        # endpoint was not among the API's results; we never probe directly.
        return _raw_from_expiry(None, "api_not_probed")
    return _fetch_live_cert_socket(hostname, port, connect_timeout)


def classify(raw: dict, threshold: datetime) -> str:
    """Pure function, no network. Classify a raw cert against a threshold dt."""
    if raw["error"]:
        return raw["error"]
    if raw["live_expiry_dt"] is not None and raw["live_expiry_dt"] > threshold:
        return "renewed"
    return "expiring"


def probe(hostname: str, port: int, threshold: datetime, connect_timeout: float) -> dict:
    """Public entry point. Contacts each endpoint at most once (via cache)."""
    key = (hostname, port)
    raw = _probe_cache.get(key)
    if raw is None:
        raw = _fetch_live_cert(hostname, port, connect_timeout)
        _probe_cache[key] = raw
        shown = raw["live_expiry"] or raw["error"]
        print(f"  probed {hostname}:{port} -> {shown}", file=sys.stderr)
    return {
        "hostname": hostname,
        "port": port,
        "address": raw.get("address"),
        "live_expiry": raw["live_expiry"],
        "days_until_expiry": raw["days_until_expiry"],
        "status": classify(raw, threshold),
    }


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh) probe — proxy-immune fallback
# ---------------------------------------------------------------------------

def _ct_get_session() -> requests.Session:
    global _ct_session
    if _ct_session is None:
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        _ct_session = s
    return _ct_session


def _hostname_matches(hostname: str, names: list[str]) -> bool:
    """True if hostname equals one of `names` or is covered by a wildcard."""
    hl = hostname.lower().rstrip(".")
    for raw in names:
        n = raw.strip().lower().rstrip(".")
        if not n:
            continue
        if n == hl:
            return True
        if n.startswith("*."):
            suffix = n[1:]  # ".example.com"
            # Wildcard covers exactly one extra label.
            if hl.endswith(suffix) and "." not in hl[: -len(suffix)] and hl != suffix[1:]:
                return True
    return False


def _fetch_live_cert_ct(hostname: str, port: int, _connect_timeout: float) -> dict:
    """Look up the latest CT-logged cert for `hostname` and use its not_after.

    Proxy-immune: crt.sh returns JSON over HTTPS, so a TLS-intercepting proxy
    re-signs only the transport while the cert facts pass through unchanged.
    Memoized per hostname (port is irrelevant to a CT lookup).
    """
    if _is_bare_ip(hostname):
        return _raw_from_expiry(None, "ct_no_ip_lookup")
    cached = _ct_cache.get(hostname)
    if cached is not None:
        return cached

    session = _ct_get_session()
    backoff = 2.0
    err = "ct_lookup_failed"
    entries = None
    for _attempt in range(4):
        try:
            # exclude=expired drops already-expired certs: they can never be the
            # latest not_after, and excluding them greatly reduces payload/latency.
            resp = session.get(CT_BASE,
                               params={"q": hostname, "output": "json",
                                       "exclude": "expired"},
                               timeout=CT_HTTP_TIMEOUT)
        except requests.RequestException as exc:
            err = f"ct_request_error: {exc}"
            time.sleep(backoff)
            backoff = min(backoff * 2, 20)
            continue
        if resp.status_code in (429, 502, 503, 504):
            err = f"ct_http_{resp.status_code}"
            time.sleep(backoff)
            backoff = min(backoff * 2, 20)
            continue
        if resp.status_code != 200:
            err = f"ct_http_{resp.status_code}"
            break
        try:
            entries = resp.json()
        except ValueError:
            err = "ct_bad_json"
        break

    if entries is None:
        raw = _raw_from_expiry(None, err)
        _ct_cache[hostname] = raw
        return raw

    latest = None
    for e in entries:
        na = e.get("not_after")
        if not na:
            continue
        try:
            dt = datetime.fromisoformat(na).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
        name_value = e.get("name_value")
        names: list[str] = str(name_value).splitlines() if name_value else []
        cn = e.get("common_name")
        if cn:
            names.append(str(cn))
        if not _hostname_matches(hostname, names):
            continue
        if latest is None or dt > latest:
            latest = dt

    raw = _raw_from_expiry(latest, None if latest else "ct_no_match")
    _ct_cache[hostname] = raw
    time.sleep(CT_QUERY_DELAY)
    return raw


# ---------------------------------------------------------------------------
# Bitsight live-certificates API probe — proxy-immune, deployment-accurate
# ---------------------------------------------------------------------------

def _pem_not_after(pem: str) -> datetime:
    """UTC-aware expiry of a PEM-encoded leaf certificate."""
    return _cert_not_after_utc(x509.load_pem_x509_certificate(pem.encode()))


def _api_result_endpoint_key(result: dict) -> tuple[str, int] | None:
    """Derive a (host, port) key from an API result the way the walks key it.

    Parses the echoed raw `endpoint` with the SAME regex `_extract_endpoints`
    uses, so the key aligns with the record's endpoints even when the API's
    parsed `hostname` is null (e.g. a bare-IP endpoint). Falls back to the
    explicit hostname/port fields.
    """
    endpoint = result.get("endpoint")
    if endpoint:
        m = ENDPOINT_REGEX.match(str(endpoint))
        if m:
            try:
                return (m.group(1).strip(), int(m.group(2)))
            except ValueError:
                pass
    hostname = result.get("hostname")
    port = result.get("port")
    if hostname and port is not None:
        try:
            return (str(hostname), int(port))
        except (TypeError, ValueError):
            pass
    return None


def _store_api_result(result: dict, obs_endpoints: dict[str, set[tuple[str, int]]]) -> None:
    """Translate one live-certificates API result into _probe_cache entries.

    The walks look up by the (host, port) key parsed from the finding's observed
    endpoints, which often does NOT match what the API reports: a finding may
    record a bare IP (e.g. `203.0.113.58:443`) while the API echoes the
    enriched form (`gateway.example.net[203.0.113.58]:443`, hostname set). So we
    store the cert under every key form the walk might use — the IP (`address`),
    the hostname, the parsed echoed `endpoint`, and the observation's own
    endpoint key (joined via the rolledup_observation_id we sent). Storing one
    cert under several aliases is harmless: they all name the same endpoint.
    """
    # The IP the service actually connected to, server-side — the real origin
    # address, never an in-network proxy.
    address = result.get("address")
    pem = result.get("pem")
    if pem:
        try:
            raw = _raw_from_expiry(_pem_not_after(pem), None, address)
        except Exception as exc:  # malformed PEM shouldn't abort the whole run
            raw = _raw_from_expiry(None, f"api_bad_pem: {exc}", address)
    else:
        raw = _raw_from_expiry(None, result.get("error") or "api_no_certificate", address)

    hostname = result.get("hostname")
    port = result.get("port")
    keys: set[tuple[str, int]] = set()
    if port is not None:
        try:
            p = int(port)
            if hostname:
                keys.add((str(hostname), p))   # walk keyed by hostname
            if address:
                keys.add((str(address), p))    # walk keyed by the bare IP
        except (TypeError, ValueError):
            pass
    parsed = _api_result_endpoint_key(result)
    if parsed:
        keys.add(parsed)

    # Ground-truth join: the finding's own endpoint key(s) for this observation.
    # A rolled-up observation is a single Bitsight finding keyed to one cert; its
    # endpoints are just the places that cert was observed. The API returns one
    # representative result per observation, so that result's cert applies to ALL
    # of the observation's endpoints. Store it under every one of them — otherwise
    # the sibling endpoints (the ones whose host doesn't match this result's
    # hostname/IP) miss the cache and surface as "api_not_probed", which the walks
    # then treat as not-renewed (a false positive) even though the cert is fine.
    obs_id = result.get("rolledup_observation_id")
    known = obs_endpoints.get(str(obs_id)) if obs_id is not None else None
    if known:
        keys |= known

    for key in keys:
        _probe_cache[key] = raw


def _post_live_certificates(
    session: APISession, guid: str, obs_ids: list[str], connect_timeout: float
) -> list[dict]:
    """POST one batch of observation IDs and return the API's results list."""
    url = f"{session._api_base}/v1/companies/{guid}/findings/live-certificates"
    body = {
        "rolledup_observation_ids": obs_ids,
        "timeout": max(1, min(30, int(connect_timeout))),
    }
    backoff = 2.0
    resp = None
    for _attempt in range(5):
        resp = session.post(url, json=body)
        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", backoff))
            time.sleep(retry_after)
            backoff = min(backoff * 2, 30)
            continue
        resp.raise_for_status()
        if VERBOSE:
            print(f"    live-certificates returned", json.dumps(resp.json(), indent=2), file=sys.stderr)
        return resp.json().get("results", [])
    if resp is not None:
        resp.raise_for_status()
    return []


def prepopulate_api_cache(
    session: APISession,
    companies: list[dict],
    records: list[dict],
    window_days: int,
    connect_timeout: float,
) -> list[str]:
    """Batch-probe each company's findings server-side and fill _probe_cache.

    Scoped to certs expiring within `window_days` (the superset of what the
    walks probe) so far-future certs aren't probed needlessly. Proxy-immune and
    reflects the actually-deployed leaf cert. After this runs, the lazy probe()
    calls in the walks are pure cache reads.

    Returns a list of human-readable failure messages for batches that errored
    out (e.g. HTTP 405/403). A failed batch leaves its endpoints unprobed, so
    they surface as 'api_not_probed' and get flagged as not-renewed downstream;
    the caller surfaces these messages so a wholesale probe failure can't
    masquerade as a portfolio full of expiring certs.
    """
    failures: list[str] = []
    cutoff = _NOW + timedelta(days=window_days)
    obs_by_guid: dict[str, set[str]] = {}
    obs_endpoints: dict[str, set[tuple[str, int]]] = {}
    for rec in records:
        # No lower bound: certs Bitsight already records as expired must still be
        # probed live — they may have been quietly renewed, or may genuinely still
        # be down (the most urgent case). Only the upper (lookahead) bound applies.
        if rec["expiry_dt"] > cutoff:
            continue
        for oid in rec["observation_ids"]:
            obs_by_guid.setdefault(rec["company_guid"], set()).add(oid)
        for oid, eps in rec["obs_endpoints"].items():
            obs_endpoints.setdefault(oid, set()).update(eps)

    for company in companies:
        obs_ids = sorted(obs_by_guid.get(company["guid"], set()))
        if not obs_ids:
            continue
        print(f"  API-probing {len(obs_ids)} finding(s) for {company['name']}...",
              file=sys.stderr)
        for i in range(0, len(obs_ids), API_PROBE_BATCH):
            batch = obs_ids[i:i + API_PROBE_BATCH]
            try:
                results = _post_live_certificates(session, company["guid"], batch,
                                                  connect_timeout)
            except requests.HTTPError as exc:
                msg = (f"{company['name']}: live-certificates probe failed "
                       f"({len(batch)} finding(s) left unprobed): {exc}")
                print(f"    {msg}", file=sys.stderr)
                failures.append(msg)
                continue
            for result in results:
                _store_api_result(result, obs_endpoints)
    print(f"  API probe filled {len(_probe_cache)} endpoint(s).", file=sys.stderr)
    return failures


# ---------------------------------------------------------------------------
# Preliminary proxy check
# ---------------------------------------------------------------------------

def detect_intercepting_proxy(connect_timeout: float) -> str | None:
    """Fetch google.com's cert; warn if not issued by Google Trust Services."""
    cert, err, _addr = _connect_and_get_cert("google.com", 443, connect_timeout)
    if cert is None:
        return (f"Could not verify TLS to google.com ({err}); unable to confirm "
                "whether a TLS-intercepting proxy is present.")
    issuer_orgs = [str(a.value) for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    issuer = ", ".join(issuer_orgs) if issuer_orgs else cert.issuer.rfc4514_string()
    if not any("Google Trust Services" in o for o in issuer_orgs):
        return (f"google.com certificate was issued by '{issuer}', not 'Google "
                "Trust Services'. You are likely behind a TLS-intercepting "
                "proxy that will corrupt the certificate expiry checks.")
    return None


# ---------------------------------------------------------------------------
# Bitsight API
# ---------------------------------------------------------------------------

def _new_session(auth: AuthInfo, api_base: str | None = None) -> APISession:
    session = APISession(api_base)
    if auth.api_jwt:
        session.headers.update({"Authorization": f"bearer {auth.api_jwt}"})
    elif auth.api_token:
        session.auth = (auth.api_token, "")  # HTTP Basic: token as username, empty pw
    session.headers.update({"Accept": "application/json", "User-Agent": USER_AGENT})
    return session


def discover_companies(session: APISession) -> list[dict]:
    """Discover 'my company' and 'mysub' entities from the portfolio.

    Returns a list of {guid, name, my_company} dicts. Read-only.
    """
    print("Discovering target companies from portfolio...", file=sys.stderr)
    resp = session.get(
        f"{session._api_base}/v2/portfolio",
        params={
            "fields": "guid,name,my_company,subscription_type,subscription_type_key",
            "scope": "spm-and-tree",
        },
    )
    resp.raise_for_status()
    results = resp.json().get("results", [])

    targets = []
    for r in results:
        # The distinguishing value lives in subscription_type.slug; the
        # top-level my_company / subscription_type_key fields requested above
        # are often absent, so rely on the slug and treat the others as
        # fallbacks only.
        slug = ((r.get("subscription_type") or {}).get("slug") or "").lower()
        is_my = slug == "my_company" or bool(r.get("my_company"))
        is_sub = slug == "my_subsidiary" or r.get("subscription_type_key") == "my_subsidiary"
        if is_my or is_sub:
            targets.append({
                "guid": r.get("guid"),
                "name": r.get("name"),
                "my_company": is_my,
            })
    print(f"  Found {len(targets)} target company/companies.", file=sys.stderr)
    return targets


def fetch_findings(auth: AuthInfo, guid: str, api_base: str | None = None) -> list[dict]:
    """Fetch all SSL-configuration findings for a company. Read-only.

    Handles pagination via 'next', treats 404 as no findings, and backs off
    on HTTP 429.
    """
    session = _new_session(auth, api_base)
    url = f"{session._api_base}/ratings/v1/companies/{guid}/findings"
    params: dict | None = {
        "format": "json",
        "affects_rating": "true",
        "risk_vector": "ssl_certificates",
        "limit": 100,
    }
    findings: list[dict] = []
    while url:
        backoff = 2.0
        for _attempt in range(5):
            resp = session.get(url, params=params)
            if resp.status_code == 404:
                return findings
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", backoff))
                time.sleep(retry_after)
                backoff = min(backoff * 2, 30)
                continue
            resp.raise_for_status()
            break
        else:
            print(f"  Giving up on {guid} after repeated 429s.", file=sys.stderr)
            return findings

        data = resp.json()
        findings.extend(data.get("results", []))
        url = data.get("next") or (data.get("links") or {}).get("next")
        params = None  # subsequent page URLs are absolute
        if url:
            time.sleep(PAGE_DELAY)
    return findings


# ---------------------------------------------------------------------------
# Infrastructure attribution — why an endpoint is attributed to the company
# ---------------------------------------------------------------------------

# Each SPM company (my_company + each subsidiary) is discovered and queried on its
# OWN guid, so subsidiary infrastructure is already covered by its own query;
# leaving this "false" avoids a parent double-attributing its subs. Flip to "true"
# to also explain infra attributed via subsidiaries in a single parent query.
ATTR_INCLUDE_SUBSIDIARIES = "false"

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def _is_domain(host: str) -> bool:
    """A dotted hostname (not a bare IP) — used to pick the domain query form."""
    h = (host or "").strip()
    return bool(_DOMAIN_RE.match(h)) and not _is_bare_ip(h)


def fetch_attribution(session: APISession, guid: str, asset: str) -> list[dict] | None:
    """Ask Bitsight WHY `asset` (a hostname or IP) is attributed to the company.

    IPs use `net_cidr` / `all_matching_cidrs`; domains use `domain` /
    `all_matching_domains`. Read-only. Returns the raw list, or None on error.
    """
    url = f"{session._api_base}/v1/companies/{guid}/infrastructure/reasons/"
    if _is_bare_ip(asset):
        params = {"all_matching_cidrs": "true", "net_cidr": asset}
    else:
        params = {"all_matching_domains": "true", "domain": asset}
    params["include_subsidiaries"] = ATTR_INCLUDE_SUBSIDIARIES
    params["source.slug"] = ""
    try:
        resp = session.get(url, params=params)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    data = resp.json()
    return data if isinstance(data, list) else None


def _summarize_reason(reason: dict) -> str:
    """One-line summary of a single attribution reason (a cert, DNS or WHOIS link)."""
    category = reason.get("category")
    evidence = reason.get("evidence") or {}
    summary = evidence.get("summary") or {}
    steps = evidence.get("steps") or []
    frm, to = summary.get("from"), summary.get("to")
    relation = record = last_seen = None
    if steps:
        first = steps[0] or {}
        relation = first.get("relation")
        record = first.get("record")
        last_seen = first.get("last_seen")
    head = f"{frm} {relation or '->'} {to}" if (frm and to) else None
    meta = []
    if category:
        meta.append(str(category))
    if record and record.lower() != str(category or "").lower():
        meta.append(str(record))
    if last_seen:
        meta.append(f"last seen {last_seen}")
    if reason.get("is_expired"):
        meta.append("expired")
    tail = f" ({', '.join(meta)})" if meta else ""
    return (head or category or "attributed") + tail


def summarize_attribution(raw: list[dict] | None) -> dict:
    """Collapse the raw reasons response into {sources, reasons} for the JSON output."""
    sources: list[str] = []
    reasons: list[str] = []
    for item in raw or []:
        src = item.get("source")
        if src and src not in sources:
            sources.append(str(src))
        for reason in item.get("reasons") or []:
            summ = _summarize_reason(reason)
            if summ and summ not in reasons:
                reasons.append(summ)
    return {"sources": sources, "reasons": reasons}


def annotate_attribution(
    auth: AuthInfo,
    companies: list[dict],
    next_expiry_by_company: list[dict],
    attention_records: list[dict],
    api_base: str | None = None,
) -> None:
    """For every flagged (non-renewed) endpoint, attach an `attribution` field
    explaining why its host is attributed to the company. Mutates the endpoint
    dicts in place. Endpoints are resolved concurrently, deduplicated by
    (guid, host); a per-thread session keeps the shared one thread-safe.
    """
    name_to_guid = {c["name"]: c["guid"] for c in companies}
    targets: dict[tuple[str, str], list[dict]] = {}

    def add(guid: str | None, ep: dict) -> None:
        host = ep.get("hostname")
        if guid and host:
            targets.setdefault((guid, host), []).append(ep)

    for rec in attention_records:
        guid = name_to_guid.get(rec["company_name"])
        for ep in rec.get("endpoints", []):
            if ep.get("status") != "renewed":
                add(guid, ep)
    for row in next_expiry_by_company:
        cert = row.get("cert")
        if not cert:
            continue
        guid = name_to_guid.get(row["company_name"])
        for ep in cert.get("probe_results", []):
            if ep.get("status") != "renewed":
                add(guid, ep)

    if not targets:
        return

    pairs = list(targets.keys())

    def work(pair: tuple[str, str]) -> tuple[tuple[str, str], dict]:
        guid, host = pair
        sess = _new_session(auth, api_base)  # per-thread session
        return pair, summarize_attribution(fetch_attribution(sess, guid, host))

    with ThreadPoolExecutor(max_workers=min(8, len(pairs))) as pool:
        for pair, summ in pool.map(work, pairs):
            for ep in targets[pair]:
                ep["attribution"] = summ
    print(f"  attribution: resolved {len(pairs)} endpoint(s).", file=sys.stderr)


# ---------------------------------------------------------------------------
# Findings parsing
# ---------------------------------------------------------------------------

def _parse_end_date(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _extract_endpoints(finding: dict) -> set[tuple[str, int]]:
    """Return {(hostname, port)} for a finding."""
    endpoints: set[tuple[str, int]] = set()
    annotations = (finding.get("details") or {}).get("diligence_annotations") or {}
    for entry in annotations.get("attributed_observed_ips") or []:
        m = ENDPOINT_REGEX.match(str(entry))
        if m:
            host = m.group(1).strip()
            try:
                endpoints.add((host, int(m.group(2))))
            except ValueError:
                continue
    if not endpoints:
        for asset in finding.get("assets") or []:
            host = asset.get("asset")
            if host:
                endpoints.add((host, 443))
    return endpoints


def _parse_cn(subject_name: str) -> str | None:
    """Extract the CN value from a subject DN like 'CN=foo.com,O=Acme'."""
    m = re.search(r'CN\s*=\s*([^,/]+)', subject_name)
    return m.group(1).strip() if m else None


def _cert_display_name(record: dict) -> str:
    """Friendly label for a cert finding.

    Prefer an observed endpoint hostname that appears in the cert's SAN list
    (most relevant to what is actually being checked); otherwise the CN;
    otherwise the first SAN; otherwise the raw subject DN.
    """
    sans = [s.strip() for s in record["san_list"] if s and s.strip()]
    san_by_lower = {s.lower(): s for s in sans}
    for host in sorted(h for (h, _p) in record["endpoints"] if not _is_bare_ip(h)):
        match = san_by_lower.get(host.lower())
        if match:
            return match
    if record.get("cn"):
        return record["cn"]
    if sans:
        return sorted(sans)[0]
    return record["subject"]


def parse_company_findings(company: dict, findings: list[dict]) -> list[dict]:
    """Parse + deduplicate findings into cert records for one company.

    Dedup key is (subjectName, endDate); endpoint sets and SAN lists are unioned
    across findings so no endpoint is missed and no cert is double-counted.
    """
    by_cert: dict[tuple[str, str], dict] = {}
    for finding in findings:
        annotations = (finding.get("details") or {}).get("diligence_annotations") or {}
        certchain = annotations.get("certchain") or []
        if not certchain:
            continue
        leaf = certchain[0]
        end_dt = _parse_end_date(leaf.get("endDate"))
        if end_dt is None:
            continue
        subject = leaf.get("subjectName") or "(unknown subject)"
        key = (subject, leaf.get("endDate"))
        record = by_cert.get(key)
        if record is None:
            record = {
                "company_name": company["name"],
                "company_guid": company["guid"],
                "subject": subject,
                "cn": _parse_cn(subject),
                "san_list": set(),
                "expiry_dt": end_dt,
                "expiry_date": end_dt.date().isoformat(),
                "endpoints": set(),
                "observation_ids": set(),
                "obs_endpoints": {},
            }
            by_cert[key] = record
        finding_endpoints = _extract_endpoints(finding)
        record["endpoints"] |= finding_endpoints
        obs_id = finding.get("rolledup_observation_id")
        if obs_id:
            obs_id = str(obs_id)
            record["observation_ids"].add(obs_id)
            # Keep each observation's OWN endpoints so an API result can be
            # mapped back to the exact key the walks use (see _store_api_result).
            record["obs_endpoints"].setdefault(obs_id, set()).update(finding_endpoints)
        dns = leaf.get("dnsName")
        if isinstance(dns, str):
            dns = [dns]
        for san in dns or []:
            if san:
                record["san_list"].add(san)

    # Resolve a friendly display name now that endpoints + SANs are fully unioned.
    for record in by_cert.values():
        record["display_name"] = _cert_display_name(record)
    return list(by_cert.values())


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _cached_probe_summary(rec: dict) -> tuple[str | None, datetime | None]:
    """Summarize a record's live status from ALREADY-probed endpoints only.

    Makes no new network calls — reads `_probe_cache`. Returns
    (status, live_expiry_dt), or (None, None) if none of the record's endpoints
    have been probed yet (e.g. a cert beyond the lookahead window). `status` is
    "renewed" only if every probed endpoint is renewed; otherwise "expiring" or
    a propagated error string.
    """
    statuses: list[str] = []
    live_dts: list[datetime] = []
    for (h, p) in sorted(rec["endpoints"]):
        raw = _probe_cache.get((h, p))
        if raw is None:
            continue
        statuses.append(classify(raw, rec["expiry_dt"]))
        if raw["live_expiry_dt"] is not None:
            live_dts.append(raw["live_expiry_dt"])
    if not statuses:
        return None, None
    if all(s == "renewed" for s in statuses):
        status = "renewed"
    elif any(s == "expiring" for s in statuses):
        status = "expiring"
    else:
        status = statuses[0]  # propagate an error string
    return status, (max(live_dts) if live_dts else None)


def next_unrenewed_per_company(
    records: list[dict],
    companies: list[dict],
    lookahead_days: int,
    connect_timeout: float,
) -> list[dict]:
    """For each company, find the first upcoming cert not yet renewed."""
    lookahead_cutoff = _NOW + timedelta(days=lookahead_days)

    # Include already-expired certs too: sorted ascending they come first, so an
    # expired-and-unrenewed cert surfaces as the company's most-urgent result
    # (negative days_away). The lookahead_cutoff break below bounds the far end.
    by_company: dict[str, list[dict]] = {}
    for rec in records:
        by_company.setdefault(rec["company_name"], []).append(rec)

    out = []
    for company in companies:
        name = company["name"]
        certs = sorted(by_company.get(name, []), key=lambda r: r["expiry_dt"])

        result_cert = None
        checked_within_window = False
        for rec in certs:
            if rec["expiry_dt"] > lookahead_cutoff:
                break
            checked_within_window = True
            probe_results = [
                probe(h, p, rec["expiry_dt"], connect_timeout)
                for (h, p) in sorted(rec["endpoints"])
            ]
            if probe_results and all(r["status"] == "renewed" for r in probe_results):
                continue
            result_cert = {
                "subject": rec["display_name"],
                "subject_dn": rec["subject"],
                "expiry_date": rec["expiry_date"],
                "days_away": (rec["expiry_dt"] - _NOW).days,
                "already_renewed": False,
                "probe_results": probe_results,
            }
            break

        # Disambiguate why cert is None so the consumer isn't left guessing.
        if result_cert is not None:
            reason = "unrenewed_within_lookahead"
        elif not certs:
            reason = "no_upcoming_findings"
        elif not checked_within_window:
            reason = "none_within_lookahead"
        else:
            reason = "all_renewed"

        # Always surface the nearest upcoming cert (even beyond the lookahead),
        # so "cert: null" companies still show when their next expiry is. Report
        # the LIVE status/expiry (from the probe cache) alongside Bitsight's
        # recorded date, so a cert that was renewed since Bitsight's scan shows
        # its new date rather than the stale one. live_status is "not_checked"
        # for certs beyond the lookahead (never probed).
        nearest = certs[0] if certs else None
        nearest_expiry = None
        if nearest is not None:
            n_status, n_live_dt = _cached_probe_summary(nearest)
            nearest_expiry = {
                "subject": nearest["display_name"],
                "bitsight_expiry": nearest["expiry_date"],
                "bitsight_days_away": (nearest["expiry_dt"] - _NOW).days,
                "live_status": n_status or "not_checked",
                "live_expiry": n_live_dt.date().isoformat() if n_live_dt else None,
            }

        out.append({
            "company_name": name,
            "cert": result_cert,
            "reason": reason,
            "nearest_expiry": nearest_expiry,
        })
    return out


def check_threshold(
    records: list[dict],
    threshold_days: int,
    connect_timeout: float,
) -> tuple[list[dict], int, int, int]:
    """Check all certs expiring within the threshold window.

    Returns (attention_records, findings_checked, renewed_count,
    still_expiring_count).
    """
    threshold_dt = _NOW + timedelta(days=threshold_days)

    # No lower bound: include certs already past their Bitsight-recorded expiry so
    # an expired-but-unrenewed cert is probed live and flagged (days_away negative).
    in_window = [
        rec for rec in records
        if rec["expiry_dt"] <= threshold_dt
    ]
    findings_checked = len(in_window)

    # Probe every unique endpoint in the window, then classify per endpoint.
    window_endpoints: set[tuple[str, int]] = set()
    for rec in in_window:
        window_endpoints |= rec["endpoints"]

    endpoint_status: dict[tuple[str, int], dict] = {}
    for (h, p) in sorted(window_endpoints):
        endpoint_status[(h, p)] = probe(h, p, threshold_dt, connect_timeout)

    renewed = sum(1 for r in endpoint_status.values() if r["status"] == "renewed")
    still_expiring = len(endpoint_status) - renewed

    attention = []
    for rec in sorted(in_window, key=lambda r: r["expiry_dt"]):
        endpoints = [endpoint_status[(h, p)] for (h, p) in sorted(rec["endpoints"])]
        if any(e["status"] != "renewed" for e in endpoints):
            attention.append({
                "company_name": rec["company_name"],
                "subject": rec["display_name"],
                "subject_dn": rec["subject"],
                "bitsight_expiry": rec["expiry_date"],
                "days_away": (rec["expiry_dt"] - _NOW).days,
                "endpoints": endpoints,
            })
    return attention, findings_checked, renewed, still_expiring


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _emit(obj: dict, code: int) -> NoReturn:
    """Print the JSON result to stdout and exit."""
    json.dump(obj, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    sys.exit(code)


def main() -> None:
    global PROBE_METHOD, VERBOSE
    load_dotenv()

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api-token", default=None,
                        help="Bitsight API token (HTTP Basic auth)")
    parser.add_argument("--api-jwt", default=None,
                        help="Bitsight API JWT (bearer auth, overrides --api-token)")
    parser.add_argument("--threshold", type=int, default=None,
                        help="Days ahead to flag in the attention report")
    parser.add_argument("--lookahead", type=int, default=None,
                        help="How far to walk for the next unrenewed cert")
    parser.add_argument("--timeout", type=int, default=None,
                        help="TCP connect timeout when probing")
    parser.add_argument("--probe-method", choices=["auto", "socket", "ct", "api"],
                        default=None,
                        help="How to read live cert expiry: socket (direct TLS), "
                             "ct (Certificate Transparency / crt.sh, proxy-immune), "
                             "api (Bitsight live-certificates, server-side, "
                             "proxy-immune and deployment-accurate), or auto "
                             "(socket unless a TLS proxy is detected). Default auto.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Dump raw API response JSON to stderr for debugging.")
    args = parser.parse_args()
    VERBOSE = args.verbose

    # Precedence: CLI arg -> env var -> hardcoded default.
    api_token = args.api_token or _clean_env(os.environ.get("BITSIGHT_API_TOKEN"))
    api_jwt = args.api_jwt or _clean_env(os.environ.get("BITSIGHT_API_JWT"))
    threshold_days = args.threshold if args.threshold is not None else int(
        _clean_env(os.environ.get("EXPIRY_THRESHOLD_DAYS")) or 5)
    lookahead_days = args.lookahead if args.lookahead is not None else int(
        _clean_env(os.environ.get("NEXT_EXPIRY_LOOKAHEAD_DAYS")) or 30)
    connect_timeout = args.timeout if args.timeout is not None else int(
        _clean_env(os.environ.get("CONNECT_TIMEOUT")) or 10)
    probe_method_arg = (args.probe_method
                        or _clean_env(os.environ.get("CERT_PROBE_METHOD"))
                        or "auto")

    if not api_token and not api_jwt:
        _emit({
            "status": "config_error",
            "error": ("Either BITSIGHT_API_TOKEN or BITSIGHT_API_JWT must be set. "
                      "Set it in your shell environment or a .env / .envrc file. "
                      "For API Token, find it under Account -> User API Token in the Bitsight portal."),
        }, 2)

    auth = AuthInfo(api_token=api_token, api_jwt=api_jwt)

    # Compute API base from JWT if available, otherwise use env var or default
    api_base = auth.get_api_base()
    if api_base:
        print(f"Using API_BASE from JWT portal_host: {api_base}", file=sys.stderr)
    else:
        api_base = API_BASE
        print(f"Using API_BASE: {api_base}", file=sys.stderr)

    # Decide how to read live cert expiry. Behind a TLS-intercepting proxy a
    # direct socket probe returns the proxy's re-signed cert, so we fall back to
    # Certificate Transparency logs (crt.sh), which are proxy-immune.
    proxy_warning = None
    if probe_method_arg == "ct":
        PROBE_METHOD = "ct"
        print("Probe method: ct (Certificate Transparency / crt.sh).", file=sys.stderr)
    elif probe_method_arg == "api":
        PROBE_METHOD = "api"
        print("Probe method: api (Bitsight live-certificates, server-side).",
              file=sys.stderr)
    elif probe_method_arg == "socket":
        PROBE_METHOD = "socket"
        print("Probe method: socket (direct TLS).", file=sys.stderr)
        proxy_warning = detect_intercepting_proxy(connect_timeout)
        if proxy_warning:
            print(f"  WARNING: {proxy_warning} Results will be unreliable; "
                  "consider --probe-method ct.", file=sys.stderr)
    else:  # auto
        print("Checking for TLS-intercepting proxy via google.com...", file=sys.stderr)
        proxy_warning = detect_intercepting_proxy(connect_timeout)
        if proxy_warning:
            PROBE_METHOD = "api"
            print("  Proxy detected -> falling back to Bitsight API checking "
                  " for live expiry.", file=sys.stderr)
        else:
            PROBE_METHOD = "socket"
            print("  No proxy detected -> using direct TLS socket probes.", file=sys.stderr)

    session = _new_session(auth, api_base)
    try:
        companies = discover_companies(session)
    except requests.HTTPError as exc:
        _emit({"status": "config_error",
               "error": f"Failed to fetch portfolio: {exc}"}, 2)

    if not companies:
        _emit({"status": "config_error",
               "error": "No 'my company' or subsidiary companies found in the portfolio."}, 2)

    # Fetch findings concurrently (mindful of rate limits).
    print(f"Fetching SSL findings for {len(companies)} company/companies...", file=sys.stderr)
    all_records: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(3, len(companies))) as pool:
        futures = {
            pool.submit(fetch_findings, auth, c["guid"], api_base): c
            for c in companies
        }
        for fut in as_completed(futures):
            company = futures[fut]
            try:
                findings = fut.result()
            except requests.HTTPError as exc:
                print(f"  Error fetching findings for {company['name']}: {exc}",
                      file=sys.stderr)
                continue
            records = parse_company_findings(company, findings)
            print(f"  {company['name']}: {len(findings)} findings -> "
                  f"{len(records)} unique cert(s).", file=sys.stderr)
            all_records.extend(records)

    # In api mode, batch-probe every relevant finding server-side up front so
    # the per-endpoint walks below become pure cache reads. The window is the
    # superset of what the walks probe (threshold + lookahead).
    probe_failures: list[str] = []
    if PROBE_METHOD == "api":
        print("Probing live certificates server-side via Bitsight API...",
              file=sys.stderr)
        probe_failures = prepopulate_api_cache(
            session, companies, all_records,
            max(threshold_days, lookahead_days), connect_timeout)

    # Step 5: per-company next-unrenewed walk.
    print("Walking upcoming expirations per company...", file=sys.stderr)
    next_expiry_by_company = next_unrenewed_per_company(
        all_records, companies, lookahead_days, connect_timeout)

    # Step 6: threshold check.
    print("Checking threshold window...", file=sys.stderr)
    attention_records, findings_checked, renewed, still_expiring = check_threshold(
        all_records, threshold_days, connect_timeout)

    # Step 6b: explain WHY each flagged endpoint is attributed to its company, so
    # the report can say whether it came in via a cert, DNS record, WHOIS
    # registration or was customer-provided.
    print("Resolving infrastructure attribution for flagged endpoints...", file=sys.stderr)
    annotate_attribution(auth, companies, next_expiry_by_company, attention_records, api_base)

    has_unrenewed = any(
        row["cert"] and not row["cert"]["already_renewed"]
        for row in next_expiry_by_company
    )
    action_required = bool(attention_records) or has_unrenewed

    # If the server-side probe failed for some companies, the affected certs
    # show 'api_not_probed' and get conservatively counted as not-renewed. Flag
    # that explicitly so a wholesale probe failure (e.g. HTTP 405/403) isn't
    # mistaken for a portfolio genuinely full of expiring certs.
    probe_warning = None
    if probe_failures:
        probe_warning = (
            "The Bitsight live-certificates API did not return results for "
            f"{len(probe_failures)} probe batch(es); those certificates could "
            "not be verified live and appear as 'api_not_probed' (counted as "
            "not-renewed). Results may be incomplete. Details: "
            + "; ".join(probe_failures))

    probe_method_note = None
    if PROBE_METHOD == "ct":
        probe_method_note = (
            "Live expiry was read from Certificate Transparency logs (crt.sh), "
            "not a direct TLS probe (a TLS-intercepting proxy was detected or ct "
            "was requested). 'renewed' means a newer cert has been ISSUED for the "
            "domain; it does not confirm the cert is deployed, and bare IPs / "
            "non-standard ports cannot be checked this way (status 'ct_no_ip_lookup' "
            "or 'ct_no_match').")
    elif PROBE_METHOD == "api":
        probe_method_note = (
            "Live expiry was read via the Bitsight live-certificates API, which "
            "probes each finding's endpoint server-side (outside your network) and "
            "returns the actually-served leaf certificate — proxy-immune and "
            "deployment-accurate. Endpoints the API could not reach carry its error "
            "string (or 'api_no_certificate'); endpoints not returned by the API "
            "show 'api_not_probed'. The API refuses non-public addresses.")

    result = {
        "status": "ok",
        "generated": _NOW.isoformat(),
        "threshold_days": threshold_days,
        "lookahead_days": lookahead_days,
        "probe_method": PROBE_METHOD,
        "probe_method_note": probe_method_note,
        "probe_warning": probe_warning,
        "proxy_warning": proxy_warning,
        "companies_checked": [
            {"name": c["name"], "guid": c["guid"], "my_company": c["my_company"]}
            for c in companies
        ],
        "next_expiry_by_company": next_expiry_by_company,
        "attention_records": attention_records,
        "summary": {
            "findings_checked": findings_checked,
            "unique_endpoints_probed": len(_probe_cache),
            "renewed": renewed,
            "still_expiring_or_unreachable": still_expiring,
        },
        "action_required": action_required,
    }

    print(f"Done. Cache size: {len(_probe_cache)}. Action required: {action_required}.",
          file=sys.stderr)
    _emit(result, 1 if action_required else 0)


if __name__ == "__main__":
    main()
