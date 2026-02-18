from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from pathlib import Path
from cachetools import TTLCache
import os
import re
import ipaddress
import requests
from typing import List, Dict, Any, Optional


# -----------------------------
# LOAD ENV FIRST (from project root)
# -----------------------------
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")  # optional


# -----------------------------
# OPENAPI TAG GROUPS (Removes "default")
# -----------------------------
openapi_tags = [
    {
        "name": "System",
        "description": "Service health and operational metadata."
    },
    {
        "name": "IOC Enrichment",
        "description": "Threat intelligence lookups for IP addresses, domains, and file hashes."
    },
    {
        "name": "Vulnerabilities",
        "description": "CVE lookup and vulnerability intelligence."
    },
    {
        "name": "Correlation",
        "description": "Combine and summarize multiple IOC results into a unified threat view."
    }
]


# -----------------------------
# CREATE FASTAPI APP
# -----------------------------
app = FastAPI(
    title="Threat Intelligence MCP Server",
    description="""
    Modular Cybersecurity Platform (MCP) for IOC enrichment, 
    threat scoring, vulnerability intelligence, and correlation.

    This service integrates with external threat intelligence providers 
    (AbuseIPDB, VirusTotal, Shodan, NVD) to enrich and evaluate indicators.
    """,
    version="1.0.0",
    openapi_tags=openapi_tags
)


# -----------------------------
# CACHE CONFIG (2000 entries, 10 min TTL)
# -----------------------------
cache = TTLCache(maxsize=2000, ttl=600)


# -----------------------------
# VALIDATORS
# -----------------------------
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid IP address format.")


def validate_domain(value: str) -> str:
    v = value.strip().lower()
    if not DOMAIN_RE.match(v):
        raise HTTPException(status_code=422, detail="Invalid domain format.")
    return v


def validate_hash(value: str) -> str:
    v = value.strip()
    if not (MD5_RE.match(v) or SHA1_RE.match(v) or SHA256_RE.match(v)):
        raise HTTPException(
            status_code=422,
            detail="Invalid hash format. Expected MD5(32), SHA1(40), or SHA256(64) hex.",
        )
    return v


def validate_cve(value: str) -> str:
    v = value.strip().upper()
    if not CVE_RE.match(v):
        raise HTTPException(status_code=422, detail="Invalid CVE format. Example: CVE-2021-44228")
    return v


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    return cache.get(key)


def cache_set(key: str, data: Dict[str, Any]) -> Dict[str, Any]:
    cache[key] = data
    return data


# -----------------------------
# REQUEST MODELS
# -----------------------------
class CheckIPRequest(BaseModel):
    ip: str = Field(..., examples=["8.8.8.8"])


class ScanHashRequest(BaseModel):
    hash: str = Field(..., examples=["44d88612fea8a8f36de82e1278abb02f"])


class LookupDomainRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"])


class CveDetailsRequest(BaseModel):
    cve_id: str = Field(..., examples=["CVE-2021-44228"])


class CorrelateIOCsRequest(BaseModel):
    iocs: List[str] = Field(
        ...,
        examples=[["8.8.8.8", "example.com", "CVE-2021-44228", "44d88612fea8a8f36de82e1278abb02f"]],
    )


# -----------------------------
# HEALTH ENDPOINT
# -----------------------------
@app.get(
    "/health",
    tags=["System"],
    summary="Service health check",
    description="Returns service operational status and metadata."
)
def health():
    return {
        "status": "ok",
        "service": "Threat Intelligence MCP Server",
        "owner": "Gus"
    }


# -----------------------------
# IP REPUTATION CHECK (AbuseIPDB)
# -----------------------------
@app.post(
    "/tools/check_ip",
    tags=["IOC Enrichment"],
    summary="IP Reputation Lookup",
    description="""
    Queries AbuseIPDB to retrieve reputation data for a given IP address.

    Returns:
    - Risk classification (low / medium / high)
    - Abuse confidence score
    - Country, ISP, domain
    - Reporting statistics
    """
)
def check_ip(payload: CheckIPRequest):
    ip = validate_ip(payload.ip)
    key = f"ip:{ip}"

    cached = cache_get(key)
    if cached:
        return {"cached": True, **cached}

    if not ABUSEIPDB_API_KEY:
        raise HTTPException(status_code=500, detail="ABUSEIPDB_API_KEY missing. Add it to .env in project root.")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Network error calling AbuseIPDB: {e}")

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    data = r.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)

    if score >= 75:
        risk = "high"
    elif score >= 25:
        risk = "medium"
    else:
        risk = "low"

    result = {
        "ip": ip,
        "risk": risk,
        "abuseConfidenceScore": score,
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
        "source": "abuseipdb",
    }
    return cache_set(key, result)


# -----------------------------
# HASH LOOKUP (VirusTotal)
# -----------------------------
@app.post(
    "/tools/scan_hash",
    tags=["IOC Enrichment"],
    summary="File Hash Lookup",
    description="""
    Queries VirusTotal to retrieve reputation and detection statistics for a file hash.

    Returns:
    - Risk classification (low / medium / high)
    - Analysis stats (malicious/suspicious/harmless/undetected)
    - Basic file metadata (if available)
    """
)
def scan_hash(payload: ScanHashRequest):
    h = validate_hash(payload.hash)
    key = f"hash:{h}"

    cached = cache_get(key)
    if cached:
        return {"cached": True, **cached}

    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(status_code=500, detail="VIRUSTOTAL_API_KEY missing. Add it to .env in project root.")

    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Network error calling VirusTotal: {e}")

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    data = r.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected
    score = malicious + suspicious

    if score >= 10:
        risk = "high"
    elif score >= 3:
        risk = "medium"
    elif score >= 1:
        risk = "low"
    else:
        risk = "low"

    result = {
        "hash": h,
        "risk": risk,
        "analysis": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines_counted": total,
        },
        "meaningful_name": attrs.get("meaningful_name"),
        "type_description": attrs.get("type_description"),
        "size": attrs.get("size"),
        "first_seen_itw_date": attrs.get("first_seen_itw_date"),
        "source": "virustotal",
    }
    return cache_set(key, result)


# -----------------------------
# DOMAIN LOOKUP (Shodan preferred, VT fallback)
# -----------------------------
@app.post(
    "/tools/lookup_domain",
    tags=["IOC Enrichment"],
    summary="Domain Intelligence Lookup",
    description="""
    Attempts Shodan domain intel first (if SHODAN_API_KEY is configured).
    Falls back to VirusTotal domain intel if Shodan is unavailable.

    Returns:
    - Risk classification (VT only)
    - Domain categories / reputation / analysis stats (VT)
    - Subdomains/tags (Shodan)
    """
)
def lookup_domain(payload: LookupDomainRequest):
    domain = validate_domain(payload.domain)
    key = f"domain:{domain}"

    cached = cache_get(key)
    if cached:
        return {"cached": True, **cached}

    if SHODAN_API_KEY:
        url = f"https://api.shodan.io/dns/domain/{domain}"
        params = {"key": SHODAN_API_KEY}
        try:
            r = requests.get(url, params=params, timeout=20)
            if r.status_code == 200:
                data = r.json()
                result = {
                    "domain": domain,
                    "source": "shodan",
                    "subdomains": data.get("subdomains", []),
                    "tags": data.get("tags", []),
                }
                return cache_set(key, result)
        except requests.RequestException:
            pass

    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="No SHODAN_API_KEY and no VIRUSTOTAL_API_KEY. Add at least one to .env.",
        )

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Network error calling VirusTotal: {e}")

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    data = r.json().get("data", {})
    attrs = data.get("attributes", {})

    rep = attrs.get("reputation")
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    if malicious >= 5 or suspicious >= 5:
        risk = "high"
    elif malicious >= 1 or suspicious >= 1:
        risk = "medium"
    else:
        risk = "low"

    result = {
        "domain": domain,
        "risk": risk,
        "reputation": rep,
        "analysis_stats": stats,
        "categories": attrs.get("categories"),
        "last_dns_records": attrs.get("last_dns_records"),
        "source": "virustotal",
    }
    return cache_set(key, result)


# -----------------------------
# CVE DETAILS (NVD/NIST)
# -----------------------------
@app.post(
    "/tools/get_cve_details",
    tags=["Vulnerabilities"],
    summary="CVE Details Lookup",
    description="""
    Queries NVD (NIST) CVE API and returns:
    - Description (English)
    - CVSS score + severity (best effort)
    - Risk classification (low/medium/high/critical)
    - Published/modified timestamps
    - Reference links
    """
)
def get_cve_details(payload: CveDetailsRequest):
    cve_id = validate_cve(payload.cve_id)
    key = f"cve:{cve_id}"

    cached = cache_get(key)
    if cached:
        return {"cached": True, **cached}

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers: Dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"cveId": cve_id}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=20)
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Network error calling NVD: {e}")

    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    j = r.json()
    vulns = j.get("vulnerabilities") or []
    if not vulns:
        return cache_set(key, {"cve_id": cve_id, "found": False, "source": "nvd"})

    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions") or []
    desc_en = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)

    metrics = cve.get("metrics") or {}
    cvss = None
    severity = None

    v31 = metrics.get("cvssMetricV31")
    if v31 and isinstance(v31, list) and v31:
        cvss = v31[0].get("cvssData", {}).get("baseScore")
        severity = v31[0].get("cvssData", {}).get("baseSeverity")

    if cvss is None:
        v30 = metrics.get("cvssMetricV30")
        if v30 and isinstance(v30, list) and v30:
            cvss = v30[0].get("cvssData", {}).get("baseScore")
            severity = v30[0].get("cvssData", {}).get("baseSeverity")

    if cvss is None:
        risk = "medium"
    elif cvss >= 9.0:
        risk = "critical"
    elif cvss >= 7.0:
        risk = "high"
    elif cvss >= 4.0:
        risk = "medium"
    else:
        risk = "low"

    result = {
        "cve_id": cve_id,
        "found": True,
        "risk": risk,
        "cvss": cvss,
        "severity": severity,
        "description": desc_en,
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "references": [ref.get("url") for ref in (cve.get("references") or []) if ref.get("url")],
        "source": "nvd",
    }
    return cache_set(key, result)


# -----------------------------
# CORRELATE IOCs (auto-detect + batch)
# -----------------------------
@app.post(
    "/tools/correlate_iocs",
    tags=["Correlation"],
    summary="Correlate and summarize IOCs",
    description="""
    Accepts a list of mixed indicators (IP / domain / hash / CVE).
    Auto-detects the type for each IOC, enriches it, and returns an overall risk.

    Notes:
    - Uses caching for each IOC type
    - Missing API keys or provider errors are returned in 'errors'
    """
)
def correlate_iocs(payload: CorrelateIOCsRequest):
    if not payload.iocs:
        raise HTTPException(status_code=422, detail="iocs list is empty.")

    findings: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for raw in payload.iocs:
        ioc = (raw or "").strip()
        if not ioc:
            continue

        try:
            try:
                ipaddress.ip_address(ioc)
                findings.append({"ioc": ioc, "type": "ip", "result": check_ip(CheckIPRequest(ip=ioc))})
                continue
            except ValueError:
                pass

            if CVE_RE.match(ioc):
                findings.append({"ioc": ioc, "type": "cve", "result": get_cve_details(CveDetailsRequest(cve_id=ioc))})
                continue

            if MD5_RE.match(ioc) or SHA1_RE.match(ioc) or SHA256_RE.match(ioc):
                findings.append({"ioc": ioc, "type": "hash", "result": scan_hash(ScanHashRequest(hash=ioc))})
                continue

            if DOMAIN_RE.match(ioc.lower()):
                findings.append({"ioc": ioc, "type": "domain", "result": lookup_domain(LookupDomainRequest(domain=ioc))})
                continue

            raise HTTPException(status_code=422, detail="IOC type not recognized (expected ip/domain/hash/cve).")

        except HTTPException as e:
            errors.append({"ioc": ioc, "error": e.detail})
        except Exception as e:
            errors.append({"ioc": ioc, "error": f"Unexpected error: {e}"})

    priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    overall = "low"
    for f in findings:
        r = f.get("result") or {}
        risk = (r.get("risk") or "low").lower()
        if risk in priority and priority[risk] > priority.get(overall, 1):
            overall = risk

    return {
        "overallRisk": overall,
        "findingsCount": len(findings),
        "errorsCount": len(errors),
        "findings": findings,
        "errors": errors,
        "note": "If any provider key is missing or rate-limited, those findings will appear under errors.",
    }
