# Threat Intelligence MCP Server

Enterprise-grade Modular Cybersecurity Platform (MCP) for IOC enrichment, vulnerability intelligence, and threat correlation.

This service aggregates multiple threat intelligence providers and normalizes their output into structured, risk-scored results.

---

## 🚀 Features

* ✅ IP Reputation Lookup (AbuseIPDB)
* ✅ File Hash Intelligence (VirusTotal)
* ✅ Domain Intelligence (Shodan / VirusTotal)
* ✅ CVE Vulnerability Lookup (NVD / NIST)
* ✅ Multi-IOC Correlation Engine
* ✅ Risk Scoring & Normalization
* ✅ 10-Minute TTL Caching Layer
* ✅ OpenAPI 3.1 Interactive Documentation
* ✅ Structured Logging
* ✅ Secure Environment Variable Handling

---

## 🏗 Architecture

```
Client
   ↓
FastAPI MCP Server
   ↓
-----------------------------------------------
| AbuseIPDB | VirusTotal | Shodan | NVD (NIST) |
-----------------------------------------------
   ↓
Normalized Threat Output
   ↓
Unified Risk Assessment
```

The MCP server acts as a threat intelligence aggregation layer:

* Accepts Indicators of Compromise (IOCs)
* Validates and sanitizes inputs
* Queries external threat providers
* Normalizes and risk-scores results
* Correlates multiple indicators
* Returns structured, unified threat intelligence

This design resembles SOC tooling logic and mini-SOAR automation architecture.

---

## 🛠 Technology Stack

* Python 3.10+
* FastAPI
* Pydantic
* cachetools (TTLCache)
* requests
* Uvicorn

---

## ⚙️ Setup

### 1️⃣ Clone Repository

```bash
git clone <your-repo-url>
cd <your-project-folder>
```

---

### 2️⃣ Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

If requirements.txt does not exist yet:

```bash
pip freeze > requirements.txt
```

---

### 4️⃣ Configure Environment Variables

Create a `.env` file in the project root:

```
Hi I am you Api Gus lol
cp .env.example .env
```

⚠️ `.env` is excluded via `.gitignore` for security.

---

## ▶️ Run the Server

```bash
uvicorn mcp_server.app:app --reload --port 8001
```

---

## 📘 API Documentation

Open:

```
http://127.0.0.1:8001/docs
```

Interactive Swagger UI allows testing all endpoints.

---

# 🧪 Example Requests

## 🔎 Check IP Reputation

```bash
curl -X POST http://127.0.0.1:8001/tools/check_ip \
-H "Content-Type: application/json" \
-d '{"ip":"8.8.8.8"}'
```

---

## 🧬 Scan File Hash

```bash
curl -X POST http://127.0.0.1:8001/tools/scan_hash \
-H "Content-Type: application/json" \
-d '{"hash":"44d88612fea8a8f36de82e1278abb02f"}'
```

---

## 🌐 Lookup Domain Intelligence

```bash
curl -X POST http://127.0.0.1:8001/tools/lookup_domain \
-H "Content-Type: application/json" \
-d '{"domain":"google.com"}'
```

---

## 🛡 Get CVE Details

```bash
curl -X POST http://127.0.0.1:8001/tools/get_cve_details \
-H "Content-Type: application/json" \
-d '{"cve_id":"CVE-2021-44228"}'
```

---

## 🔄 Correlate Multiple IOCs

```bash
curl -X POST http://127.0.0.1:8001/tools/correlate_iocs \
-H "Content-Type: application/json" \
-d '{"iocs":["8.8.8.8","google.com","CVE-2021-44228"]}'
```

---

# 🧠 Design Decisions

### Input Validation

* Strict regex validation for IP, domain, hash, and CVE formats.
* Prevents malformed or malicious input.

### Caching Strategy

* TTLCache (10 minutes)
* Reduces external API calls
* Improves performance and rate-limit resilience

### Risk Normalization

Each provider’s response is mapped into standardized risk levels:

* low
* medium
* high
* critical (CVE only)

This allows unified threat scoring across different data sources.

---

# 🔐 Security Considerations

* API keys stored in environment variables
* `.env` excluded from Git tracking
* External requests include timeouts
* Provider errors handled gracefully
* Input validation enforced before processing

---

# 📦 Project Structure

```
project-root/
│
├── mcp_server/
│   └── app.py
│
├── README.md
├── requirements.txt
├── .env.example
└── .gitignore
```

---

# 🎯 What This Project Represents

This is not just an API.

It is a modular threat intelligence aggregation service that:

* Automates IOC enrichment
* Assists SOC analysts
* Performs multi-provider correlation
* Normalizes threat scoring
* Mimics SOAR-style automation logic

This demonstrates applied cybersecurity automation architecture using modern Python frameworks.

---
