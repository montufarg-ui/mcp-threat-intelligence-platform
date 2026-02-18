from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import requests
from pathlib import Path
from cachetools import TTLCache


# -----------------------------
# LOAD ENV FIRST (from project root)
# -----------------------------
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


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
# CACHE CONFIG (1000 IPs, 10 min TTL)
# -----------------------------
cache = TTLCache(maxsize=1000, ttl=600)


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
# REQUEST MODEL
# -----------------------------
class CheckIPRequest(BaseModel):
    ip: str


# -----------------------------
# IP REPUTATION CHECK
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

    # 1️⃣ Return cached result if exists
    if payload.ip in cache:
        return cache[payload.ip]

    # 2️⃣ Load API key
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="ABUSEIPDB_API_KEY missing. Add it to .env in project root."
        )

    # 3️⃣ Prepare AbuseIPDB request
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": payload.ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    # 4️⃣ Call external API
    try:
        r = requests.get(url, headers=headers, params=params, timeout=15)
    except requests.RequestException as e:
        raise HTTPException(
            status_code=502,
            detail=f"Network error calling AbuseIPDB: {e}"
        )

    if r.status_code != 200:
        raise HTTPException(
            status_code=r.status_code,
            detail=r.text
        )

    # 5️⃣ Process response
    data = r.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)

    if score >= 75:
        risk = "high"
    elif score >= 25:
        risk = "medium"
    else:
        risk = "low"

    # 6️⃣ Build result object
    result = {
        "ip": payload.ip,
        "risk": risk,
        "abuseConfidenceScore": score,
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
        "source": "abuseipdb"
    }

    # 7️⃣ Store in cache
    cache[payload.ip] = result

    # 8️⃣ Return result
    return result
