from __future__ import annotations

import os
import re
import json
import time
import logging
import ipaddress
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import requests
from cachetools import TTLCache
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.responses import HTMLResponse


# -----------------------------
# LOGGING
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
logger = logging.getLogger("mcp")


# -----------------------------
# LOAD ENV (project root)
# -----------------------------
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")  # optional
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


# -----------------------------
# OPENAPI TAG GROUPS
# -----------------------------
openapi_tags = [
    {"name": "System", "description": "Service health and operational metadata."},
    {"name": "Status", "description": "Provider status and operational signals."},
    {"name": "Frontend", "description": "Simple static UI for interview/demo use."},
    {"name": "Agent", "description": "Natural language endpoint that decides which tools to use."},
    {"name": "IOC Enrichment", "description": "Threat intelligence lookups for IP addresses, domains, and file hashes."},
    {"name": "Vulnerabilities", "description": "CVE lookup and vulnerability intelligence."},
    {"name": "Correlation", "description": "Combine and summarize multiple IOC results into a unified threat view."},
]


# -----------------------------
# FASTAPI APP
# -----------------------------
app = FastAPI(
    title="Threat Intelligence MCP Server",
    description="""
Modular Cybersecurity Platform (MCP) for IOC enrichment, threat scoring,
vulnerability intelligence, and correlation.

This service integrates with external threat intelligence providers
(AbuseIPDB, VirusTotal, Shodan, NVD) to enrich and evaluate indicators.
""",
    version="1.0.0",
    openapi_tags=openapi_tags,
)


# -----------------------------
# CACHE (>= 5 minutes TTL)
# -----------------------------
cache = TTLCache(maxsize=2000, ttl=600)


# -----------------------------
# PROVIDER STATUS (in-memory)
# -----------------------------
# state: "ok" | "error" | "rate_limited" | "missing_key"
provider_status: Dict[str, Dict[str, Any]] = {
    "abuseipdb": {"state": "missing_key" if not ABUSEIPDB_API_KEY else "unknown", "last_ok": None, "last_error": None},
    "virustotal": {"state": "missing_key" if not VIRUSTOTAL_API_KEY else "unknown", "last_ok": None, "last_error": None},
    "shodan": {"state": "missing_key" if not SHODAN_API_KEY else "unknown", "last_ok": None, "last_error": None},
    "nvd": {"state": "unknown", "last_ok": None, "last_error": None},  # NVD key optional
    "openai": {"state": "missing_key" if not OPENAI_API_KEY else "unknown", "last_ok": None, "last_error": None},
}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def mark_provider_ok(name: str) -> None:
    if name not in provider_status:
        provider_status[name] = {"state": "unknown", "last_ok": None, "last_error": None}
    provider_status[name]["state"] = "ok"
    provider_status[name]["last_ok"] = _now_iso()
    provider_status[name]["last_error"] = None


def mark_provider_error(name: str, msg: str, rate_limited: bool = False) -> None:
    if name not in provider_status:
        provider_status[name] = {"state": "unknown", "last_ok": None, "last_error": None}
    provider_status[name]["state"] = "rate_limited" if rate_limited else "error"
    provider_status[name]["last_error"] = {"time": _now_iso(), "message": msg[:300]}


# -----------------------------
# RATE LIMITING (in-memory)
# -----------------------------
# Simple sliding window: N requests per window per client IP (agent endpoint only)
RL_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RL_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "12"))
_rate_store: Dict[str, List[float]] = {}


def rate_limit_or_429(client_id: str) -> None:
    now = time.time()
    window_start = now - RL_WINDOW_SECONDS
    times = _rate_store.get(client_id, [])
    times = [t for t in times if t >= window_start]
    if len(times) >= RL_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again later. (limit={RL_MAX_REQUESTS}/{RL_WINDOW_SECONDS}s)",
        )
    times.append(now)
    _rate_store[client_id] = times


# -----------------------------
# VALIDATORS / REGEX
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


def with_cached_flag(cached: bool, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"cached": cached, **payload}


def safe_provider_error(provider: str, status_code: int) -> str:
    """
    Sanitized errors (do not leak provider raw payloads).
    """
    if status_code in (401, 403):
        return f"{provider} authentication failed (check API key)."
    if status_code == 429:
        return f"{provider} rate-limited the request (try later)."
    if 400 <= status_code < 500:
        return f"{provider} request rejected (status={status_code})."
    return f"{provider} service error (status={status_code})."


# -----------------------------
# REQUEST LOGGING MIDDLEWARE
# -----------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"{request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"{request.method} {request.url.path} -> {response.status_code}")
    return response


# -----------------------------
# FRONTEND: Serve web/index.html
# -----------------------------
@app.get("/", include_in_schema=False, tags=["Frontend"])
def serve_index():
    index_path = Path(__file__).resolve().parent.parent / "web" / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=500, detail=f"Frontend not found at: {index_path}")
    html = index_path.read_text(encoding="utf-8")
    return HTMLResponse(content=html, media_type="text/html")


# -----------------------------
# MODELS
# -----------------------------
class CheckIPRequest(BaseModel):
    ip: str = Field(..., json_schema_extra={"examples": ["8.8.8.8"]})


class ScanHashRequest(BaseModel):
    hash: str = Field(..., json_schema_extra={"examples": ["44d88612fea8a8f36de82e1278abb02f"]})


class LookupDomainRequest(BaseModel):
    domain: str = Field(..., json_schema_extra={"examples": ["example.com"]})


class CveDetailsRequest(BaseModel):
    cve_id: str = Field(..., json_schema_extra={"examples": ["CVE-2021-44228"]})


class CorrelateIOCsRequest(BaseModel):
    iocs: List[str] = Field(
        ...,
        json_schema_extra={
            "examples": [["8.8.8.8", "google.com", "CVE-2021-44228", "44d88612fea8a8f36de82e1278abb02f"]]
        },
    )


class LLMTriageRequest(BaseModel):
    iocs: List[str] = Field(..., json_schema_extra={"examples": [["8.8.8.8", "example.com", "CVE-2021-44228"]]})
    audience: str = Field("novice", json_schema_extra={"examples": ["novice", "soc_analyst"]})
    tone: str = Field("calm", json_schema_extra={"examples": ["calm", "urgent"]})
    verbosity: str = Field("medium", json_schema_extra={"examples": ["short", "medium", "long"]})


class AgentQueryRequest(BaseModel):
    query: str = Field(..., json_schema_extra={"examples": ["Analyze 185.220.101.5 and CVE-2021-44228. Is it dangerous?"]})
    audience: str = Field("novice", json_schema_extra={"examples": ["novice", "soc_analyst"]})
    tone: str = Field("calm", json_schema_extra={"examples": ["calm", "urgent"]})
    verbosity: str = Field("medium", json_schema_extra={"examples": ["short", "medium", "long"]})


# -----------------------------
# HEALTH + STATUS
# -----------------------------
@app.get("/health", tags=["System"], summary="Service health check")
def health():
    return {
        "status": "ok",
        "service": "Threat Intelligence MCP Server",
        "owner": "Gus",
        "cache": {"maxsize": cache.maxsize, "ttl_seconds": cache.ttl},
    }


@app.get("/status/providers", tags=["Status"], summary="Provider status indicators")
def status_providers():
    return {"providers": provider_status, "note": "In-memory status; resets on restart."}


# -----------------------------
# TOOL: IP (AbuseIPDB)
# -----------------------------
@app.post("/tools/check_ip", tags=["IOC Enrichment"], summary="IP Reputation Lookup")
def check_ip(payload: CheckIPRequest):
    ip = validate_ip(payload.ip)
    key = f"ip:{ip}"

    cached = cache_get(key)
    if cached:
        logger.info(f"check_ip cache hit: {ip}")
        return with_cached_flag(True, cached)

    if not ABUSEIPDB_API_KEY:
        provider_status["abuseipdb"]["state"] = "missing_key"
        raise HTTPException(status_code=500, detail="ABUSEIPDB_API_KEY missing. Add it to .env in project root.")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
    except requests.RequestException as e:
        mark_provider_error("abuseipdb", f"Network error: {e}")
        raise HTTPException(status_code=502, detail="Upstream network error calling AbuseIPDB.")

    if r.status_code != 200:
        rate_limited = (r.status_code == 429)
        mark_provider_error("abuseipdb", f"HTTP {r.status_code}", rate_limited=rate_limited)
        raise HTTPException(status_code=502, detail=safe_provider_error("AbuseIPDB", r.status_code))

    mark_provider_ok("abuseipdb")
    data = r.json().get("data", {})
    score = int(data.get("abuseConfidenceScore", 0) or 0)

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

    cache_set(key, result)
    return with_cached_flag(False, result)


# -----------------------------
# TOOL: HASH (VirusTotal)
# -----------------------------
@app.post("/tools/scan_hash", tags=["IOC Enrichment"], summary="File Hash Lookup")
def scan_hash(payload: ScanHashRequest):
    h = validate_hash(payload.hash)
    key = f"hash:{h}"

    cached = cache_get(key)
    if cached:
        logger.info(f"scan_hash cache hit: {h}")
        return with_cached_flag(True, cached)

    if not VIRUSTOTAL_API_KEY:
        provider_status["virustotal"]["state"] = "missing_key"
        raise HTTPException(status_code=500, detail="VIRUSTOTAL_API_KEY missing. Add it to .env in project root.")

    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as e:
        mark_provider_error("virustotal", f"Network error: {e}")
        raise HTTPException(status_code=502, detail="Upstream network error calling VirusTotal.")

    if r.status_code != 200:
        rate_limited = (r.status_code == 429)
        mark_provider_error("virustotal", f"HTTP {r.status_code}", rate_limited=rate_limited)
        raise HTTPException(status_code=502, detail=safe_provider_error("VirusTotal", r.status_code))

    mark_provider_ok("virustotal")
    data = r.json().get("data", {})
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    total = malicious + suspicious + harmless + undetected
    score = malicious + suspicious

    if score >= 10:
        risk = "high"
    elif score >= 3:
        risk = "medium"
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

    cache_set(key, result)
    return with_cached_flag(False, result)


# -----------------------------
# TOOL: DOMAIN (Shodan preferred, VT fallback)
# -----------------------------
@app.post("/tools/lookup_domain", tags=["IOC Enrichment"], summary="Domain Intelligence Lookup")
def lookup_domain(payload: LookupDomainRequest):
    domain = validate_domain(payload.domain)
    key = f"domain:{domain}"

    cached = cache_get(key)
    if cached:
        logger.info(f"lookup_domain cache hit: {domain}")
        return with_cached_flag(True, cached)

    # 1) Try Shodan
    if SHODAN_API_KEY:
        url = f"https://api.shodan.io/dns/domain/{domain}"
        params = {"key": SHODAN_API_KEY}
        try:
            r = requests.get(url, params=params, timeout=20)
            if r.status_code == 200:
                mark_provider_ok("shodan")
                data = r.json()
                result = {
                    "domain": domain,
                    "risk": "unknown",
                    "source": "shodan",
                    "subdomains": data.get("subdomains", []),
                    "tags": data.get("tags", []),
                }
                cache_set(key, result)
                return with_cached_flag(False, result)

            # If shodan errors, track it but continue to VT
            if r.status_code in (401, 403, 429) or r.status_code >= 400:
                mark_provider_error("shodan", f"HTTP {r.status_code}", rate_limited=(r.status_code == 429))

        except requests.RequestException as e:
            mark_provider_error("shodan", f"Network error: {e}")

    else:
        provider_status["shodan"]["state"] = "missing_key"

    # 2) Fallback to VirusTotal
    if not VIRUSTOTAL_API_KEY:
        provider_status["virustotal"]["state"] = "missing_key"
        raise HTTPException(status_code=500, detail="No SHODAN_API_KEY and no VIRUSTOTAL_API_KEY. Add at least one.")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=20)
    except requests.RequestException as e:
        mark_provider_error("virustotal", f"Network error: {e}")
        raise HTTPException(status_code=502, detail="Upstream network error calling VirusTotal.")

    if r.status_code != 200:
        rate_limited = (r.status_code == 429)
        mark_provider_error("virustotal", f"HTTP {r.status_code}", rate_limited=rate_limited)
        raise HTTPException(status_code=502, detail=safe_provider_error("VirusTotal", r.status_code))

    mark_provider_ok("virustotal")
    data = r.json().get("data", {})
    attrs = data.get("attributes", {})

    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)

    if malicious >= 5 or suspicious >= 5:
        risk = "high"
    elif malicious >= 1 or suspicious >= 1:
        risk = "medium"
    else:
        risk = "low"

    result = {
        "domain": domain,
        "risk": risk,
        "reputation": attrs.get("reputation"),
        "analysis_stats": stats,
        "categories": attrs.get("categories"),
        "last_dns_records": attrs.get("last_dns_records"),
        "source": "virustotal",
    }

    cache_set(key, result)
    return with_cached_flag(False, result)


# -----------------------------
# TOOL: CVE (NVD)
# -----------------------------
@app.post("/tools/get_cve_details", tags=["Vulnerabilities"], summary="CVE Details Lookup")
def get_cve_details(payload: CveDetailsRequest):
    cve_id = validate_cve(payload.cve_id)
    key = f"cve:{cve_id}"

    cached = cache_get(key)
    if cached:
        logger.info(f"get_cve_details cache hit: {cve_id}")
        return with_cached_flag(True, cached)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers: Dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        headers["X-Api-Key"] = NVD_API_KEY

    params = {"cveId": cve_id}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=20)
    except requests.RequestException as e:
        mark_provider_error("nvd", f"Network error: {e}")
        raise HTTPException(status_code=502, detail="Upstream network error calling NVD.")

    if r.status_code != 200:
        rate_limited = (r.status_code == 429)
        mark_provider_error("nvd", f"HTTP {r.status_code}", rate_limited=rate_limited)
        raise HTTPException(status_code=502, detail=safe_provider_error("NVD", r.status_code))

    mark_provider_ok("nvd")
    j = r.json()
    vulns = j.get("vulnerabilities") or []
    if not vulns:
        result = {"cve_id": cve_id, "found": False, "source": "nvd"}
        cache_set(key, result)
        return with_cached_flag(False, result)

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
    else:
        cvss = float(cvss)
        if cvss >= 9.0:
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

    cache_set(key, result)
    return with_cached_flag(False, result)


# -----------------------------
# CORRELATE IOCs (adds TRACE)
# -----------------------------
def detect_ioc_type(ioc: str) -> str:
    s = (ioc or "").strip()
    if not s:
        return "unknown"
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if CVE_RE.match(s):
        return "cve"
    if MD5_RE.match(s) or SHA1_RE.match(s) or SHA256_RE.match(s):
        return "hash"
    if DOMAIN_RE.match(s.lower()):
        return "domain"
    return "unknown"


@app.post("/tools/correlate_iocs", tags=["Correlation"], summary="Correlate and summarize IOCs")
def correlate_iocs(payload: CorrelateIOCsRequest):
    if not payload.iocs:
        raise HTTPException(status_code=422, detail="iocs list is empty.")

    findings: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    trace: List[Dict[str, Any]] = []

    step = 0
    for raw in payload.iocs:
        ioc = (raw or "").strip()
        if not ioc:
            continue

        step += 1
        ioc_type = detect_ioc_type(ioc)
        trace_item = {"step": step, "ioc": ioc, "type": ioc_type, "tool": None, "status": None, "cached": None}

        try:
            if ioc_type == "ip":
                trace_item["tool"] = "check_ip"
                out = check_ip(CheckIPRequest(ip=ioc))
                trace_item["status"] = "ok"
                trace_item["cached"] = bool(out.get("cached"))
                findings.append({"ioc": ioc, "type": "ip", "result": out})

            elif ioc_type == "cve":
                trace_item["tool"] = "get_cve_details"
                out = get_cve_details(CveDetailsRequest(cve_id=ioc))
                trace_item["status"] = "ok"
                trace_item["cached"] = bool(out.get("cached"))
                findings.append({"ioc": ioc, "type": "cve", "result": out})

            elif ioc_type == "hash":
                trace_item["tool"] = "scan_hash"
                out = scan_hash(ScanHashRequest(hash=ioc))
                trace_item["status"] = "ok"
                trace_item["cached"] = bool(out.get("cached"))
                findings.append({"ioc": ioc, "type": "hash", "result": out})

            elif ioc_type == "domain":
                trace_item["tool"] = "lookup_domain"
                out = lookup_domain(LookupDomainRequest(domain=ioc))
                trace_item["status"] = "ok"
                trace_item["cached"] = bool(out.get("cached"))
                findings.append({"ioc": ioc, "type": "domain", "result": out})

            else:
                trace_item["tool"] = "none"
                trace_item["status"] = "error"
                trace_item["cached"] = False
                errors.append({"ioc": ioc, "error": "IOC type not recognized (expected ip/domain/hash/cve)."})

        except HTTPException as e:
            trace_item["status"] = "error"
            trace_item["cached"] = False
            errors.append({"ioc": ioc, "error": e.detail})
        except Exception as e:
            trace_item["status"] = "error"
            trace_item["cached"] = False
            errors.append({"ioc": ioc, "error": "Unexpected internal error."})
            logger.exception(f"Unexpected error correlating IOC={ioc}: {e}")

        trace.append(trace_item)

    # Overall risk (best-effort): highest risk found in results
    priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
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
        "trace": trace,  # <-- step-by-step tool call trace
        "note": "Provider failures and missing keys appear under errors and provider status.",
    }


# -----------------------------
# LLM TRIAGE (keeps /tools/llm_triage)
# -----------------------------
def extract_response_text(resp: Any) -> str:
    txt = getattr(resp, "output_text", None)
    if isinstance(txt, str) and txt.strip():
        return txt.strip()

    chunks: List[str] = []
    for item in getattr(resp, "output", []) or []:
        for c in getattr(item, "content", []) or []:
            t = getattr(c, "text", None)
            if isinstance(t, str):
                chunks.append(t)

    return "\n".join(chunks).strip()


def build_llm_prompts(audience: str, tone: str, verbosity: str, correlated_data: Dict[str, Any]) -> Tuple[str, str]:
    system_prompt = (
        "You are a cybersecurity analyst producing a helpful incident triage note. "
        "You will receive structured JSON from threat intelligence providers. "
        "Do not invent facts. Do not hallucinate. Only use the provided data. "
        "If data is missing, rate-limited, or a provider failed, state that clearly in 'Limitations'. "
        "Your output must be understandable to the requested audience."
    )

    if audience == "novice":
        audience_style = (
            "Write for a non-technical person. Avoid acronyms and jargon. "
            "Explain what the IOC means in plain language."
        )
    else:
        audience_style = (
            "Write for a SOC analyst. Include technical reasoning, indicators, and suggested investigation steps."
        )

    tone_style = "Keep the tone calm and reassuring." if tone == "calm" else "Be urgent and direct."

    verbosity_style = {
        "short": "Keep it very short (3-6 bullets total).",
        "medium": "Use moderate detail (6-12 bullets total).",
        "long": "Include more detail and context (12-20 bullets total).",
    }.get(verbosity, "Use moderate detail (6-12 bullets total).")

    user_prompt = (
        f"{audience_style}\n{tone_style}\n{verbosity_style}\n\n"
        "You are given a JSON object with IOC enrichment results.\n"
        "Return ONLY the following sections, exactly in this order, with these headings:\n\n"
        "Overall Risk: <low|medium|high|critical>\n"
        "Summary:\n"
        "- ...\n"
        "Recommended Actions:\n"
        "- ...\n"
        "Limitations:\n"
        "- ...\n\n"
        "Rules:\n"
        "- If providers failed or keys are missing, mention it under Limitations.\n"
        "- If overallRisk exists in JSON, use it as the base and adjust ONLY if evidence clearly supports it.\n"
        "- Never output raw JSON.\n\n"
        "Here is the correlated IOC JSON:\n"
        f"{json.dumps(correlated_data, indent=2)}"
    )

    return system_prompt, user_prompt


@app.post("/tools/llm_triage", tags=["Correlation"], summary="LLM-powered threat triage")
def llm_triage(payload: LLMTriageRequest, debug: bool = Query(False)):
    if not openai_client:
        provider_status["openai"]["state"] = "missing_key"
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY missing. Add it to your .env file.")

    correlated_data = correlate_iocs(CorrelateIOCsRequest(iocs=payload.iocs))
    system_prompt, user_prompt = build_llm_prompts(payload.audience, payload.tone, payload.verbosity, correlated_data)

    try:
        response = openai_client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        mark_provider_ok("openai")
        output_text = extract_response_text(response)

        resp: Dict[str, Any] = {
            "iocs": payload.iocs,
            "overallRisk": correlated_data.get("overallRisk"),
            "findingsCount": correlated_data.get("findingsCount"),
            "errorsCount": correlated_data.get("errorsCount"),
            "llm_analysis": output_text,
            # include trace by default (this is part of requirements)
            "trace": correlated_data.get("trace", []),
        }

        if debug:
            resp["correlated_data"] = correlated_data
            resp["providers"] = provider_status

        return resp

    except Exception as e:
        mark_provider_error("openai", f"{e}")
        logger.error(f"OpenAI request failed: {e}")
        raise HTTPException(status_code=502, detail="LLM provider error. Try again later.")


# -----------------------------
# AGENT ENDPOINT (Natural Language) + Rate Limit
# -----------------------------
IOC_EXTRACT_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_EXTRACT_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# hash: 32/40/64 hex
IOC_EXTRACT_HASH = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
# domain: basic extraction; later validated strictly
IOC_EXTRACT_DOMAIN = re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")


def extract_iocs_from_text(text: str) -> List[str]:
    if not text:
        return []
    candidates = set()

    for m in IOC_EXTRACT_IP.findall(text):
        candidates.add(m)

    for m in IOC_EXTRACT_CVE.findall(text):
        candidates.add(m.upper())

    for m in IOC_EXTRACT_HASH.findall(text):
        candidates.add(m)

    for m in IOC_EXTRACT_DOMAIN.findall(text):
        candidates.add(m.lower())

    # Validate and keep only recognized IOCs
    cleaned: List[str] = []
    for c in candidates:
        t = detect_ioc_type(c)
        if t == "ip":
            try:
                cleaned.append(validate_ip(c))
            except Exception:
                pass
        elif t == "cve":
            try:
                cleaned.append(validate_cve(c))
            except Exception:
                pass
        elif t == "hash":
            try:
                cleaned.append(validate_hash(c))
            except Exception:
                pass
        elif t == "domain":
            try:
                cleaned.append(validate_domain(c))
            except Exception:
                pass

    # Stable order (nice for demos)
    cleaned.sort()
    return cleaned


@app.post("/agent/query", tags=["Agent"], summary="Natural language threat triage (rate limited)")
def agent_query(payload: AgentQueryRequest, request: Request, debug: bool = Query(False)):
    # Rate limit by client IP (best-effort)
    client_ip = request.client.host if request.client else "unknown"
    rate_limit_or_429(client_ip)

    iocs = extract_iocs_from_text(payload.query)
    if not iocs:
        raise HTTPException(
            status_code=422,
            detail="No valid IOCs found in query. Include an IP, domain, hash, or CVE in your text.",
        )

    # Reuse existing /tools/llm_triage behavior
    triage = llm_triage(
        LLMTriageRequest(
            iocs=iocs,
            audience=payload.audience,
            tone=payload.tone,
            verbosity=payload.verbosity,
        ),
        debug=debug,
    )

    # Include the user query back (helpful for session history UI)
    triage["query"] = payload.query
    triage["agent"] = {"rate_limit": {"window_seconds": RL_WINDOW_SECONDS, "max_requests": RL_MAX_REQUESTS}}
    return triage